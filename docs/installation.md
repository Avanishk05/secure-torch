# Installation

## Requirements

- Python 3.10, 3.11, or 3.12
- Core runtime dependencies (`safetensors`, `packaging`, `numpy`) are installed automatically

## Install from PyPI

```bash
pip install secure-torch
```

## Optional extras

```bash
# ONNX model support
pip install secure-torch[onnx]

# Online Sigstore / Rekor verification
pip install secure-torch[sigstore]

# Offline key-based verification (Ed25519 / RSA)
pip install secure-torch[crypto]

# Everything
pip install secure-torch[all]
```

```bash
# Optional: rich-rendered CLI audit reports
pip install rich
```

## Development install

```bash
git clone https://github.com/Avanishk05/secure-torch
cd secure-torch
pip install -e .
pip install pytest pytest-cov mypy ruff bandit
```

## Verify installation

```bash
secure-torch --version
```

```python
import secure_torch
print(secure_torch.__version__)  # 0.1.0
```
