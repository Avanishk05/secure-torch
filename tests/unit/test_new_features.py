"""
Unit tests for scan_file(), cache, and Keras format detection.
"""

from __future__ import annotations

from pathlib import Path

from secure_torch.cache import clear_cache, get_cached, put_cached
from secure_torch.format_detect import detect_format
from secure_torch.models import ModelFormat, ValidationReport


class TestFormatDetectKeras:
    """Keras/HDF5 extensions are detected correctly."""

    def test_h5_extension(self, tmp_path: Path):
        f = tmp_path / "model.h5"
        f.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 100)
        assert detect_format(f) == ModelFormat.KERAS

    def test_hdf5_extension(self, tmp_path: Path):
        f = tmp_path / "model.hdf5"
        f.write_bytes(b"\x89HDF\r\n\x1a\n" + b"\x00" * 100)
        assert detect_format(f) == ModelFormat.KERAS

    def test_keras_extension(self, tmp_path: Path):
        f = tmp_path / "model.keras"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)  # keras files are zips
        assert detect_format(f) == ModelFormat.KERAS


class TestCache:
    """In-memory validation result cache."""

    def setup_method(self):
        clear_cache()

    def test_miss_returns_none(self):
        assert get_cached("abc123") is None

    def test_round_trip(self):
        report = ValidationReport(
            path="test.pt",
            format=ModelFormat.PICKLE,
            threat_level="LOW",
            threat_score=5,
            score_breakdown={},
            findings=[],
            warnings=[],
            sha256="abc123",
            size_bytes=100,
            load_allowed=True,
            sandbox_active=False,
        )
        put_cached("abc123", report)
        cached = get_cached("abc123")
        assert cached is not None
        assert cached.sha256 == "abc123"

    def test_eviction_at_capacity(self):
        """Cache evicts oldest entry when full."""
        for i in range(1001):
            report = ValidationReport(
                path=f"model_{i}.pt",
                format=ModelFormat.PICKLE,
                threat_level="LOW",
                threat_score=0,
                score_breakdown={},
                findings=[],
                warnings=[],
                sha256=f"sha_{i}",
                size_bytes=100,
                load_allowed=True,
                sandbox_active=False,
            )
            put_cached(f"sha_{i}", report)

        # First entry should have been evicted
        assert get_cached("sha_0") is None
        # Latest entry should still exist
        assert get_cached("sha_1000") is not None

    def test_clear(self):
        report = ValidationReport(
            path="test.pt",
            format=ModelFormat.PICKLE,
            threat_level="LOW",
            threat_score=0,
            score_breakdown={},
            findings=[],
            warnings=[],
            sha256="xyz",
            size_bytes=100,
            load_allowed=True,
            sandbox_active=False,
        )
        put_cached("xyz", report)
        clear_cache()
        assert get_cached("xyz") is None
