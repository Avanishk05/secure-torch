"""
Format detection — identifies model format by extension then magic bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from secure_torch.models import ModelFormat
from secure_torch.exceptions import FormatError

# Extension → format mapping
_EXT_MAP: dict[str, ModelFormat] = {
    ".safetensors": ModelFormat.SAFETENSORS,
    ".pt": ModelFormat.PICKLE,
    ".pth": ModelFormat.PICKLE,
    ".bin": ModelFormat.PICKLE,
    ".pkl": ModelFormat.PICKLE,
    ".pickle": ModelFormat.PICKLE,
    ".onnx": ModelFormat.ONNX,
}

# Magic bytes for fallback detection
_MAGIC_ONNX = b"\x08"          # protobuf field 1, varint
_MAGIC_ZIP = b"PK\x03\x04"    # PyTorch .pt files are ZIP archives
_MAGIC_PICKLE_PROTO = b"\x80"  # pickle protocol opcode


def detect_format(path: Union[str, Path]) -> ModelFormat:
    """
    Detect model format from file extension, falling back to magic bytes.

    Args:
        path: Path to model file.

    Returns:
        ModelFormat enum value.

    Raises:
        FormatError: If format cannot be determined.
    """
    path = Path(path)
    ext = path.suffix.lower()

    # Extension-first detection
    if ext in _EXT_MAP:
        return _EXT_MAP[ext]

    # Magic byte fallback
    if path.exists():
        with open(path, "rb") as f:
            header = f.read(16)

        if header[:4] == _MAGIC_ZIP:
            return ModelFormat.PICKLE  # PyTorch saves as ZIP
        if header[:1] == _MAGIC_PICKLE_PROTO and header[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
            return ModelFormat.PICKLE
        # ONNX protobuf: starts with field tag for model_version
        if header[:2] in (b"\x08\x00", b"\x08\x01", b"\x08\x02", b"\x0a"):
            return ModelFormat.ONNX

    raise FormatError(
        f"Cannot determine format for '{path}'. "
        f"Supported extensions: {', '.join(_EXT_MAP.keys())}"
    )
