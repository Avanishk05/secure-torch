# Installation

## Requirements

- Python 3.10, 3.11, or 3.12
- No mandatory runtime dependencies beyond the standard library

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

## Development install

```bash
git clone https://github.com/Avanishk05/secure-torch
cd secure-torch
pip install -e ".[dev]"
```

## Verify installation

```python
import secure_torch
print(secure_torch.__version__)  # 0.1.0
```
