"""
Validation result cache — keyed by SHA256.

Simple in-memory cache that avoids re-validating the same file contents.
"""

from __future__ import annotations

from typing import Optional

from secure_torch.models import ValidationReport

_cache: dict[str, ValidationReport] = {}
_MAX_ENTRIES = 1000


def get_cached(sha256: str) -> Optional[ValidationReport]:
    """Return cached report for the given SHA256, or ``None``."""
    return _cache.get(sha256)


def put_cached(sha256: str, report: ValidationReport) -> None:
    """Store a validation report in the cache."""
    if len(_cache) >= _MAX_ENTRIES:
        # Evict oldest entry (FIFO)
        _cache.pop(next(iter(_cache)))
    _cache[sha256] = report


def clear_cache() -> None:
    """Drop all cached results."""
    _cache.clear()
