"""
Unit tests — format_detect.py

Covers all extension mappings and magic byte fallbacks.
"""
from __future__ import annotations

import struct
import tempfile
import os
from pathlib import Path

import pytest

from secure_torch.format_detect import detect_format
from secure_torch.models import ModelFormat
from secure_torch.exceptions import FormatError


# ── Extension mapping tests ────────────────────────────────────────────────────

class TestExtensionMapping:

    def test_safetensors_extension(self):
        assert detect_format("model.safetensors") == ModelFormat.SAFETENSORS

    def test_pt_extension(self):
        assert detect_format("model.pt") == ModelFormat.PICKLE

    def test_pth_extension(self):
        assert detect_format("model.pth") == ModelFormat.PICKLE

    def test_bin_extension(self):
        assert detect_format("model.bin") == ModelFormat.PICKLE

    def test_pkl_extension(self):
        assert detect_format("model.pkl") == ModelFormat.PICKLE

    def test_pickle_extension(self):
        assert detect_format("model.pickle") == ModelFormat.PICKLE

    def test_onnx_extension(self):
        assert detect_format("model.onnx") == ModelFormat.ONNX

    def test_unknown_extension_non_existent(self):
        """Unknown extension on a non-existent file raises FormatError."""
        with pytest.raises(FormatError):
            detect_format("model.xyz")

    def test_uppercase_extension_not_matched(self):
        """Extensions are lowercased before matching."""
        # .PT uppercase: since path.suffix.lower() is used, should match
        assert detect_format("model.PT") == ModelFormat.PICKLE

    def test_path_object_accepted(self):
        """Path objects should be accepted as well as strings."""
        result = detect_format(Path("model.safetensors"))
        assert result == ModelFormat.SAFETENSORS


# ── Magic byte fallback tests ─────────────────────────────────────────────────

class TestMagicByteFallback:

    def _write_tmp(self, content: bytes, suffix: str = ".dat") -> Path:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        f.write(content)
        f.close()
        return Path(f.name)

    def test_zip_magic_detected_as_pickle(self):
        """PyTorch .pt files are ZIP archives — magic PK\x03\x04 → PICKLE."""
        path = self._write_tmp(b"PK\x03\x04" + b"\x00" * 64)
        try:
            assert detect_format(path) == ModelFormat.PICKLE
        finally:
            os.unlink(path)

    def test_pickle_proto2_magic(self):
        """Raw pickle protocol 2 magic bytes (\x80\x02) → PICKLE."""
        path = self._write_tmp(b"\x80\x02" + b"\x00" * 16)
        try:
            assert detect_format(path) == ModelFormat.PICKLE
        finally:
            os.unlink(path)

    def test_pickle_proto4_magic(self):
        """Raw pickle protocol 4 magic bytes (\x80\x04) → PICKLE."""
        path = self._write_tmp(b"\x80\x04" + b"\x00" * 16)
        try:
            assert detect_format(path) == ModelFormat.PICKLE
        finally:
            os.unlink(path)

    def test_onnx_protobuf_magic(self):
        """ONNX protobuf header bytes (\x08\x00) → ONNX."""
        path = self._write_tmp(b"\x08\x00" + b"\x00" * 16)
        try:
            assert detect_format(path) == ModelFormat.ONNX
        finally:
            os.unlink(path)

    def test_unknown_magic_raises_format_error(self):
        """Unrecognized magic bytes with unknown extension → FormatError."""
        path = self._write_tmp(b"\xFF\xFF\xFF\xFF" + b"\x00" * 16)
        try:
            with pytest.raises(FormatError):
                detect_format(path)
        finally:
            os.unlink(path)
