"""
Unit tests — formats/safetensors.py (extra coverage)

Covers:
- All CODE_PATTERNS (exec, subprocess, ctypes, importlib, etc.)
- Absurd tensor shapes
- Zero-size dimensions
- Unknown dtype warning
- Header-bomb protection
- Non-dict __metadata__
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path


from secure_torch.formats.safetensors import validate_safetensors
from secure_torch.threat_score import ThreatScorer


def make_safetensors(metadata: dict = None, tensors: dict = None) -> bytes:
    """Build a minimal safetensors file."""
    header = {}
    if metadata:
        header["__metadata__"] = metadata
    if tensors:
        header.update(tensors)
    header_bytes = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes


def write_tmp(content: bytes) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


# ── Code patterns in metadata ─────────────────────────────────────────────────

class TestMetadataCodePatterns:

    def _assert_scored(self, metadata_value: str) -> None:
        path = write_tmp(make_safetensors(metadata={"key": metadata_value}))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total >= 50, (
                f"Expected >=50 for '{metadata_value}', got {scorer.total}: {scorer.breakdown}"
            )
        finally:
            os.unlink(path)

    def test_eval_in_metadata_scored(self):
        self._assert_scored("eval(os.system('id'))")

    def test_exec_in_metadata_scored(self):
        self._assert_scored("exec('import os; os.system(\"id\")')")

    def test_os_system_in_metadata_scored(self):
        self._assert_scored("os.system('rm -rf /')")

    def test_subprocess_in_metadata_scored(self):
        self._assert_scored("subprocess.Popen(['id'])")

    def test_import_in_metadata_scored(self):
        self._assert_scored("__import__('os').system('id')")

    def test_importlib_in_metadata_scored(self):
        self._assert_scored("importlib.import_module('os')")

    def test_open_in_metadata_scored(self):
        self._assert_scored("open('/etc/passwd', 'r').read()")

    def test_socket_in_metadata_scored(self):
        self._assert_scored("socket.connect(('evil.com', 80))")

    def test_ctypes_in_metadata_scored(self):
        self._assert_scored("ctypes.cdll.LoadLibrary('evil.so')")

    def test_clean_metadata_no_score(self):
        """Clean metadata must produce zero threat score."""
        path = write_tmp(make_safetensors(metadata={"model": "bert-base", "version": "1.0"}))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total == 0
        finally:
            os.unlink(path)

    def test_no_metadata_key_no_score(self):
        """Files without __metadata__ are fine."""
        path = write_tmp(make_safetensors())
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total == 0
        finally:
            os.unlink(path)

    def test_non_dict_metadata_warns(self):
        """__metadata__ that is not a dict must issue a warning, not crash."""
        # Manually build a header with non-dict __metadata__
        header = {"__metadata__": ["list", "not", "dict"]}
        header_bytes = json.dumps(header).encode("utf-8")
        content = struct.pack("<Q", len(header_bytes)) + header_bytes
        path = write_tmp(content)
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)


# ── Tensor descriptor anomalies ───────────────────────────────────────────────

class TestTensorDescriptors:

    def test_unsafe_dtype_object_scored(self):
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "object", "shape": [10], "data_offsets": [0, 10]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total > 0, "Expected score for unsafe dtype 'object'"
        finally:
            os.unlink(path)

    def test_unsafe_dtype_python_object_scored(self):
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "python_object", "shape": [10], "data_offsets": [0, 10]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total > 0
        finally:
            os.unlink(path)

    def test_safe_dtype_f32_no_score(self):
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "F32", "shape": [10, 10], "data_offsets": [0, 400]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total == 0
        finally:
            os.unlink(path)

    def test_absurd_shape_scored(self):
        """Tensor with a > 1 billion dimension must get a score."""
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "F32", "shape": [1_000_000_001], "data_offsets": [0, 10]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert scorer.total > 0, "Expected score for absurd tensor shape"
        finally:
            os.unlink(path)

    def test_zero_size_dimension_warns(self):
        """Tensor with a zero-size dimension must issue a warning."""
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "F32", "shape": [0, 512], "data_offsets": [0, 0]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)

    def test_unknown_dtype_warns(self):
        """An unknown (but not dangerous) dtype string must produce a warning."""
        path = write_tmp(make_safetensors(tensors={
            "weight": {"dtype": "CUSTOM_DTYPE_99", "shape": [10], "data_offsets": [0, 10]}
        }))
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)

    def test_non_dict_tensor_entry_skipped(self):
        """Non-dict tensor entries must be skipped, not crash."""
        header = {"__metadata__": {}, "bad_entry": "not a dict"}
        header_bytes = json.dumps(header).encode("utf-8")
        content = struct.pack("<Q", len(header_bytes)) + header_bytes
        path = write_tmp(content)
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)  # must not raise
        finally:
            os.unlink(path)


# ── Header edge cases ─────────────────────────────────────────────────────────

class TestHeaderEdgeCases:

    def test_truncated_header_warns_not_raises(self):
        """Only 3 bytes — too small to be valid. Must warn gracefully."""
        path = write_tmp(b"\x00\x01\x02")
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)

    def test_header_bomb_warns(self):
        """A header claiming 200 MB length must be rejected gracefully."""
        # Write a 9-byte file: 8=length, then 1 byte body (much less than claimed)
        enormous_len = 200 * 1024 * 1024  # 200 MB
        content = struct.pack("<Q", enormous_len) + b"{"
        path = write_tmp(content)
        try:
            scorer = ThreatScorer()
            validate_safetensors(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)
