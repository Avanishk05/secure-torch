"""
SafeTensors validator — Phase 1.

Wraps safetensors.safe_open with header validation:
- dtype allowlist (reject object, python_object)
- header size bounds (header-bomb protection)
- tensor shape sanity
- metadata code injection detection
"""

from __future__ import annotations

import json
import logging
import struct
from pathlib import Path

from secure_torch.threat_score import (
    CODE_PATTERNS,
    ThreatScorer,
    SCORE_SAFETENSORS_CODE_IN_METADATA,
    SCORE_HEADER_OVERSIZED,
    SCORE_DTYPE_UNSAFE,
)

logger = logging.getLogger(__name__)

# Allowed dtypes — reject anything that could encode executable payloads
SAFE_DTYPES: frozenset[str] = frozenset(
    {
        "F16",
        "F32",
        "F64",
        "BF16",
        "I8",
        "I16",
        "I32",
        "I64",
        "U8",
        "U16",
        "U32",
        "U64",
        "BOOL",
    }
)

UNSAFE_DTYPES: frozenset[str] = frozenset(
    {
        "object",
        "python_object",
        "O",
        "V",
        "void",
    }
)

MAX_HEADER_BYTES = 100 * 1024 * 1024  # 100 MB header is absurd


def validate_safetensors(path: Path, scorer: ThreatScorer) -> None:
    """
    Validate a safetensors file header without loading tensors.

    Args:
        path: Path to .safetensors file.
        scorer: ThreatScorer to accumulate findings.
    """
    try:
        header = _read_header(path)
    except Exception as e:
        scorer.warn(f"SafeTensors header read failed: {e}")
        return

    _check_metadata(header, scorer)
    _check_tensors(header, scorer)


def _read_header(path: Path) -> dict:
    """Read and parse the length-prefixed JSON header."""
    with open(path, "rb") as f:
        # First 8 bytes: little-endian uint64 header length
        raw_len = f.read(8)
        if len(raw_len) < 8:
            raise ValueError("File too small to be a valid safetensors file")

        header_len = struct.unpack("<Q", raw_len)[0]

        if header_len > MAX_HEADER_BYTES:
            raise ValueError(f"Header length {header_len} exceeds maximum {MAX_HEADER_BYTES}")

        header_bytes = f.read(header_len)
        if len(header_bytes) < header_len:
            raise ValueError("Truncated header")

        return json.loads(header_bytes.decode("utf-8"))


def _check_metadata(header: dict, scorer: ThreatScorer) -> None:
    """Check __metadata__ for code injection patterns."""
    metadata = header.get("__metadata__", {})
    if not isinstance(metadata, dict):
        scorer.warn("__metadata__ is not a dict — unusual")
        return

    for key, value in metadata.items():
        value_str = str(value)
        for pattern in CODE_PATTERNS:
            if pattern in value_str:
                scorer.add(
                    f"safetensors_code_in_metadata:{key}",
                    SCORE_SAFETENSORS_CODE_IN_METADATA,
                )
                break


def _check_tensors(header: dict, scorer: ThreatScorer) -> None:
    """Check tensor descriptors for unsafe dtypes and shape anomalies."""
    for tensor_name, descriptor in header.items():
        if tensor_name == "__metadata__":
            continue
        if not isinstance(descriptor, dict):
            continue

        dtype = descriptor.get("dtype", "")
        shape = descriptor.get("shape", [])

        # Dtype check
        if dtype in UNSAFE_DTYPES:
            scorer.add(
                f"safetensors_unsafe_dtype:{tensor_name}:{dtype}",
                SCORE_DTYPE_UNSAFE,
            )
        elif dtype and dtype not in SAFE_DTYPES:
            scorer.warn(f"Unknown dtype '{dtype}' in tensor '{tensor_name}'")

        # Shape sanity
        if isinstance(shape, list):
            if any(d == 0 for d in shape):
                scorer.warn(f"Zero-size dimension in tensor '{tensor_name}': {shape}")
            if any(isinstance(d, int) and d > 1_000_000_000 for d in shape):
                scorer.add(
                    f"safetensors_absurd_shape:{tensor_name}",
                    SCORE_HEADER_OVERSIZED,
                )
