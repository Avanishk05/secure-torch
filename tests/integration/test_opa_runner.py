"""
Integration tests — Phase 3: OPA policy runner.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile


from secure_torch.models import SBOMRecord
from secure_torch.sbom.opa_runner import OPAPolicyRunner
from typing import Optional


def make_sbom(
    supplied_by: str = "huggingface.co/meta",
    model_type: str = "transformer",
    sensitive_pii: str = "no",
    training_info: str = "public datasets",
    ai_profile: Optional[dict] = None,
) -> SBOMRecord:
    raw = {
        "spdxVersion": "SPDX-2.3",
        "name": "bert-base-uncased",
        "aiProfile": ai_profile or {},
    }
    record = SBOMRecord(raw=raw)
    record.spdx_version = "SPDX-2.3"
    record.name = "bert-base-uncased"
    record.supplied_by = supplied_by
    record.model_type = model_type
    record.sensitive_pii = sensitive_pii
    record.training_info = training_info
    return record


def write_policy(content: str) -> str:
    """Write a .rego policy to a temp file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


class TestOPAPolicyRunnerFallback:
    """Tests for the pure-Python fallback evaluator (no opa binary required)."""

    def test_pii_model_blocked_by_policy(self):
        """Model with sensitive PII must be denied by policy."""
        policy = """
package secure_torch.policy

deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom(sensitive_pii="yes")

        try:
            runner = OPAPolicyRunner(policy_path)
            runner._opa_binary = None  # force fallback
            denials = runner.evaluate(sbom)
            assert len(denials) > 0, "Expected denial for PII model"
            assert any("personal information" in d for d in denials)
        finally:
            os.unlink(policy_path)

    def test_clean_model_passes_policy(self):
        """Clean model with no PII must pass policy."""
        policy = """
package secure_torch.policy

deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom(sensitive_pii="no")

        try:
            runner = OPAPolicyRunner(policy_path)
            runner._opa_binary = None  # force fallback
            denials = runner.evaluate(sbom)
            assert len(denials) == 0, f"Expected no denials, got: {denials}"
        finally:
            os.unlink(policy_path)

    def test_missing_supplied_by_denied(self):
        """Model with no suppliedBy field must be denied by require policy."""
        policy = """
package secure_torch.policy

deny[msg] {
    not input.suppliedBy
    msg := "Model SBOM missing required suppliedBy field"
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom(supplied_by="")

        try:
            runner = OPAPolicyRunner(policy_path)
            runner._opa_binary = None
            denials = runner.evaluate(sbom)
            assert len(denials) > 0, "Expected denial for missing suppliedBy"
        finally:
            os.unlink(policy_path)

    def test_gpl_dataset_blocked_in_production(self):
        """GPL-licensed training dataset must be blocked in production environment."""
        policy = """
package secure_torch.policy

deny[msg] {
    ds := input.aiProfile.trainingDatasets[_]
    startswith(ds.license, "GPL")
    input.environment == "production"
    msg := sprintf("GPL dataset '%v' blocked in production", [ds.name])
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom(
            ai_profile={
                "trainingDatasets": [
                    {"name": "gpl-corpus", "license": "GPL-3.0"},
                ]
            }
        )

        try:
            runner = OPAPolicyRunner(policy_path)
            runner._opa_binary = None
            denials = runner.evaluate(sbom, context={"environment": "production"})
            assert len(denials) > 0, "Expected denial for GPL dataset in production"
        finally:
            os.unlink(policy_path)

    def test_gpl_dataset_allowed_in_dev(self):
        """GPL dataset must be allowed in non-production environment."""
        policy = """
package secure_torch.policy

deny[msg] {
    ds := input.aiProfile.trainingDatasets[_]
    startswith(ds.license, "GPL")
    input.environment == "production"
    msg := sprintf("GPL dataset '%v' blocked in production", [ds.name])
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom(
            ai_profile={
                "trainingDatasets": [
                    {"name": "gpl-corpus", "license": "GPL-3.0"},
                ]
            }
        )

        try:
            runner = OPAPolicyRunner(policy_path)
            runner._opa_binary = None
            denials = runner.evaluate(sbom, context={"environment": "development"})
            assert len(denials) == 0, f"Expected no denials in dev, got: {denials}"
        finally:
            os.unlink(policy_path)

    def test_missing_policy_file_returns_error(self):
        """Missing policy file must return an error message, not raise."""
        runner = OPAPolicyRunner("/nonexistent/policy.rego")
        runner._opa_binary = None
        sbom = make_sbom()
        denials = runner.evaluate(sbom)
        assert len(denials) > 0
        assert any("Cannot read" in d for d in denials)

    def test_opa_input_not_double_wrapped(self, monkeypatch):
        """OPA --input payload must be the raw input document, not {'input': ...}."""
        policy = """
package secure_torch.policy

deny[msg] {
    false
    msg := "never"
}
"""
        policy_path = write_policy(policy)
        sbom = make_sbom()
        runner = OPAPolicyRunner(policy_path)
        runner._opa_binary = "opa"

        seen_input = {}

        def fake_run(cmd, capture_output, text, timeout):
            input_file = cmd[cmd.index("--input") + 1]
            with open(input_file, "r", encoding="utf-8") as f:
                seen_input["payload"] = json.load(f)

            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='{"result":[{"expressions":[{"value":[]}]}]}',
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        try:
            denials = runner.evaluate(sbom, context={"environment": "production"})
            assert denials == []
            payload = seen_input["payload"]
            assert isinstance(payload, dict)
            assert "input" not in payload
            assert payload["environment"] == "production"
        finally:
            os.unlink(policy_path)
