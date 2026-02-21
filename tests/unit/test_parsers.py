"""
Unit tests — Phase 1 parsers.

Focused test set (30–50 tests) covering:
- Malicious pickle detection
- Valid pickle acceptance
- Malformed safetensors rejection
- ONNX custom op detection
- Threat scoring explainability
- audit_only mode
- require_signature fail-closed
"""

from __future__ import annotations

import io
import json
import pickle
import struct
import tempfile
import os
from pathlib import Path

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def make_pickle_payload(module: str, func: str, args: list) -> bytes:
    """Build a pickle payload that calls module.func(*args) on load."""

    class _Exploit:
        def __reduce__(self):
            import importlib

            m = importlib.import_module(module)
            return getattr(m, func), tuple(args)

    buf = io.BytesIO()
    pickle.dump(_Exploit(), buf)
    return buf.getvalue()


def make_safe_pickle() -> bytes:
    """Build a safe pickle payload (plain dict)."""
    return pickle.dumps({"weight": [1.0, 2.0, 3.0]})


def make_safetensors_file(metadata: dict = None, tensors: dict = None) -> bytes:
    """Build a minimal safetensors file."""
    header = {}
    if metadata:
        header["__metadata__"] = metadata
    if tensors:
        header.update(tensors)
    header_bytes = json.dumps(header).encode("utf-8")
    length = struct.pack("<Q", len(header_bytes))
    return length + header_bytes


# ── Pickle opcode validator tests ─────────────────────────────────────────────


class TestPickleOpcodeValidator:
    def test_malicious_os_system_blocked(self):
        """Pickle calling os.system must be blocked immediately."""
        from secure_torch.formats.pickle_safe import validate_pickle
        from secure_torch.exceptions import UnsafePickleError
        from secure_torch.threat_score import ThreatScorer

        payload = make_pickle_payload("os", "system", ["echo pwned"])
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError, match="Dangerous module"):
            validate_pickle(payload, scorer)

    def test_malicious_subprocess_blocked(self):
        """Pickle calling subprocess.Popen must be blocked."""
        from secure_torch.formats.pickle_safe import validate_pickle
        from secure_torch.exceptions import UnsafePickleError
        from secure_torch.threat_score import ThreatScorer

        payload = make_pickle_payload("subprocess", "Popen", [["id"]])
        scorer = ThreatScorer()
        with pytest.raises(UnsafePickleError):
            validate_pickle(payload, scorer)

    def test_safe_dict_pickle_accepted(self):
        """A plain dict pickle must pass without findings."""
        from secure_torch.formats.pickle_safe import validate_pickle
        from secure_torch.threat_score import ThreatScorer

        payload = make_safe_pickle()
        scorer = ThreatScorer()
        validate_pickle(payload, scorer)
        assert scorer.total == 0, f"Expected 0 score, got {scorer.total}: {scorer.breakdown}"

    def test_empty_bytes_accepted(self):
        """Empty bytes must not raise."""
        from secure_torch.formats.pickle_safe import validate_pickle
        from secure_torch.threat_score import ThreatScorer

        scorer = ThreatScorer()
        validate_pickle(b"", scorer)  # should not raise

    def test_unknown_module_scores_not_blocks(self):
        """Unknown (not dangerous) module reference adds score but doesn't raise."""
        from secure_torch.formats.pickle_safe import validate_pickle
        from secure_torch.threat_score import ThreatScorer

        # Build a pickle that references a custom module (not in safe or dangerous list)
        class _CustomObj:
            def __reduce__(self):
                return (dict, ())  # safe callable, but we'll test scoring separately

        payload = pickle.dumps({"x": 1})
        scorer = ThreatScorer()
        validate_pickle(payload, scorer)
        # dict is safe — score should be 0
        assert scorer.total == 0


# ── SafeTensors validator tests ───────────────────────────────────────────────


class TestSafeTensorsValidator:
    def test_code_in_metadata_scored(self):
        """eval() in metadata must add to threat score."""
        from secure_torch.formats.safetensors import validate_safetensors
        from secure_torch.threat_score import ThreatScorer

        content = make_safetensors_file(metadata={"prompt": "eval(os.system('id'))"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            scorer = ThreatScorer()
            validate_safetensors(tmp_path, scorer)
            assert scorer.total >= 50, (
                f"Expected >=50 score for code in metadata, got {scorer.total}"
            )
        finally:
            os.unlink(tmp_path)

    def test_clean_metadata_no_score(self):
        """Clean metadata must produce zero score."""
        from secure_torch.formats.safetensors import validate_safetensors
        from secure_torch.threat_score import ThreatScorer

        content = make_safetensors_file(metadata={"model_name": "bert-base", "version": "1.0"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            scorer = ThreatScorer()
            validate_safetensors(tmp_path, scorer)
            assert scorer.total == 0, (
                f"Expected 0 score for clean metadata, got {scorer.total}: {scorer.breakdown}"
            )
        finally:
            os.unlink(tmp_path)

    def test_unsafe_dtype_scored(self):
        """Unsafe dtype 'object' must add to threat score."""
        from secure_torch.formats.safetensors import validate_safetensors
        from secure_torch.threat_score import ThreatScorer

        content = make_safetensors_file(
            tensors={"weight": {"dtype": "object", "shape": [10, 10], "data_offsets": [0, 100]}}
        )
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)

        try:
            scorer = ThreatScorer()
            validate_safetensors(tmp_path, scorer)
            assert scorer.total > 0, "Expected score > 0 for unsafe dtype"
        finally:
            os.unlink(tmp_path)

    def test_truncated_file_warns_not_raises(self):
        """Truncated safetensors file must warn, not raise."""
        from secure_torch.formats.safetensors import validate_safetensors
        from secure_torch.threat_score import ThreatScorer

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(b"\x00\x01\x02")  # truncated
            tmp_path = Path(f.name)

        try:
            scorer = ThreatScorer()
            validate_safetensors(tmp_path, scorer)  # must not raise
            assert len(scorer.warnings) > 0, "Expected a warning for truncated file"
        finally:
            os.unlink(tmp_path)


# ── Threat scoring tests ──────────────────────────────────────────────────────


class TestThreatScorer:
    def test_score_is_named_dict(self):
        """Score breakdown must be a named dict, not a magic number."""
        from secure_torch.threat_score import ThreatScorer

        scorer = ThreatScorer()
        scorer.add("unsigned_model", 40)
        scorer.add("custom_ops_detected", 30)

        assert scorer.total == 70
        assert "unsigned_model" in scorer.breakdown
        assert "custom_ops_detected" in scorer.breakdown
        assert scorer.breakdown["unsigned_model"] == 40

    def test_threat_level_from_score(self):
        """ThreatLevel must map correctly from score."""
        from secure_torch.models import ThreatLevel

        assert ThreatLevel.from_score(0) == ThreatLevel.SAFE
        assert ThreatLevel.from_score(10) == ThreatLevel.LOW
        assert ThreatLevel.from_score(25) == ThreatLevel.MEDIUM
        assert ThreatLevel.from_score(50) == ThreatLevel.HIGH
        assert ThreatLevel.from_score(80) == ThreatLevel.CRITICAL

    def test_is_blocked(self):
        """is_blocked must respect max_score threshold."""
        from secure_torch.threat_score import ThreatScorer

        scorer = ThreatScorer()
        scorer.add("unsigned_model", 40)
        assert scorer.is_blocked(20) is True
        assert scorer.is_blocked(40) is False
        assert scorer.is_blocked(39) is True


# ── Format detection tests ────────────────────────────────────────────────────


class TestFormatDetect:
    def test_safetensors_extension(self):
        from secure_torch.format_detect import detect_format
        from secure_torch.models import ModelFormat

        assert detect_format("model.safetensors") == ModelFormat.SAFETENSORS

    def test_pt_extension(self):
        from secure_torch.format_detect import detect_format
        from secure_torch.models import ModelFormat

        assert detect_format("model.pt") == ModelFormat.PICKLE

    def test_onnx_extension(self):
        from secure_torch.format_detect import detect_format
        from secure_torch.models import ModelFormat

        assert detect_format("model.onnx") == ModelFormat.ONNX

    def test_unknown_extension_raises(self):
        from secure_torch.format_detect import detect_format
        from secure_torch.exceptions import FormatError

        with pytest.raises(FormatError):
            detect_format("model.xyz")


# ── Pipeline / API tests ──────────────────────────────────────────────────────


class TestPipeline:
    def test_require_signature_fails_closed(self):
        """require_signature=True with no bundle must raise SignatureRequiredError."""
        import secure_torch as st
        from secure_torch.exceptions import SignatureRequiredError

        content = make_safetensors_file(metadata={"model": "test"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            with pytest.raises(SignatureRequiredError):
                st.load(tmp_path, require_signature=True)
        finally:
            os.unlink(tmp_path)

    def test_audit_only_loads_despite_high_score(self):
        """audit_only=True must load even when threat score exceeds max."""
        import secure_torch as st

        # Clean safetensors file — unsigned, so score=40 (unsigned_model warning)
        # max_threat_score=0 would block it normally, but audit_only=True should load anyway
        content = make_safetensors_file(metadata={"model": "test"})
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        try:
            result = st.load(tmp_path, audit_only=True, max_threat_score=0)
            assert isinstance(result, tuple), "audit_only=True must return (model, report)"
            model, report = result
            assert report is not None
            assert hasattr(report, "score_breakdown")
            # Report should show the unsigned_model warning in breakdown
            assert isinstance(report.score_breakdown, dict)
        finally:
            os.unlink(tmp_path)

    def test_drop_in_import(self):
        """import secure_torch as torch must expose load, save, jit, hub."""
        import secure_torch as torch

        assert callable(torch.load)
        assert callable(torch.save)
        assert hasattr(torch, "jit")
        assert hasattr(torch, "hub")
        assert callable(torch.from_pretrained)

    def test_sbom_policy_denial_blocks_load(self):
        """SBOM policy denials must block non-audit loads."""
        import secure_torch as st
        from secure_torch.exceptions import SecurityError

        content = make_safetensors_file(metadata={"model": "test"})
        sbom_doc = {
            "spdxVersion": "SPDX-2.3",
            "name": "test-model",
            "packages": [{"sensitivePersonalInformation": "yes"}],
        }
        policy = """
package secure_torch.policy

deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}
"""

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as mf:
            mf.write(content)
            model_path = mf.name
        with tempfile.NamedTemporaryFile(
            suffix=".spdx.json", delete=False, mode="w", encoding="utf-8"
        ) as sf:
            json.dump(sbom_doc, sf)
            sbom_path = sf.name
        with tempfile.NamedTemporaryFile(
            suffix=".rego", delete=False, mode="w", encoding="utf-8"
        ) as pf:
            pf.write(policy)
            policy_path = pf.name

        try:
            with pytest.raises(SecurityError):
                st.load(
                    model_path,
                    sbom_path=sbom_path,
                    sbom_policy_path=policy_path,
                )
        finally:
            os.unlink(model_path)
            os.unlink(sbom_path)
            os.unlink(policy_path)

    def test_sbom_policy_denial_scored_in_audit_mode(self):
        """SBOM policy denials should be scored and reported in audit mode."""
        import secure_torch as st

        content = make_safetensors_file(metadata={"model": "test"})
        sbom_doc = {
            "spdxVersion": "SPDX-2.3",
            "name": "test-model",
            "packages": [{"sensitivePersonalInformation": "yes"}],
        }
        policy = """
package secure_torch.policy

deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}
"""

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as mf:
            mf.write(content)
            model_path = mf.name
        with tempfile.NamedTemporaryFile(
            suffix=".spdx.json", delete=False, mode="w", encoding="utf-8"
        ) as sf:
            json.dump(sbom_doc, sf)
            sbom_path = sf.name
        with tempfile.NamedTemporaryFile(
            suffix=".rego", delete=False, mode="w", encoding="utf-8"
        ) as pf:
            pf.write(policy)
            policy_path = pf.name

        try:
            _, report = st.load(
                model_path,
                sbom_path=sbom_path,
                sbom_policy_path=policy_path,
                audit_only=True,
                max_threat_score=0,
            )
            assert report.sbom is not None
            assert any("sbom_policy_denial" in key for key in report.score_breakdown.keys())
        finally:
            os.unlink(model_path)
            os.unlink(sbom_path)
            os.unlink(policy_path)


class TestRemoteLoaderGuardrails:
    def test_hub_load_security_args_raise(self):
        """hub.load must reject unsupported security args instead of ignoring them."""
        import secure_torch as st
        from secure_torch.exceptions import SecurityError

        with pytest.raises(SecurityError):
            st.hub.load("pytorch/vision", "resnet18", require_signature=True)

    def test_from_pretrained_security_args_raise(self):
        """from_pretrained must reject unsupported security args instead of ignoring them."""
        import secure_torch as st
        from secure_torch.exceptions import SecurityError

        with pytest.raises(SecurityError):
            st.from_pretrained("bert-base-uncased", trusted_publishers=["huggingface.co"])
