# Trust Policy

## trusted_publishers

Restrict model loading to models signed by specific publishers.

```python
import secure_torch as torch

model = torch.load(
    "model.pt",
    trusted_publishers=["huggingface.co/meta", "openai.com"],
)
```

If the model's signer identity does not contain any of the trusted publisher strings, `UntrustedPublisherError` is raised.

## require_signature

Fail closed if no signature bundle is found:

```python
model = torch.load("model.pt", require_signature=True)
# Raises SignatureRequiredError if no .sigstore or .sig file found
```

## Combining both

```python
model = torch.load(
    "model.pt",
    require_signature=True,
    trusted_publishers=["huggingface.co/meta"],
    pubkey_path="meta.pub",
)
```

This enforces:
1. A valid signature must exist
2. The signer must be `huggingface.co/meta`

## Audit mode — evaluate without blocking

```python
model, report = torch.load(
    "model.pt",
    audit_only=True,
    trusted_publishers=["huggingface.co/meta"],
)

# Check what would have been blocked
if "untrusted_publisher" in report.score_breakdown:
    print("Publisher not in allowlist — would be blocked in enforcement mode")
```

## Exception reference

| Exception | When raised |
|---|---|
| `SignatureRequiredError` | `require_signature=True` and no bundle found |
| `UntrustedPublisherError` | Signer not in `trusted_publishers` |
| `UnsafeModelError` | Threat score exceeds `max_threat_score` |
| `UnsafePickleError` | Dangerous opcode found in pickle stream |
| `FormatError` | File format cannot be detected |
