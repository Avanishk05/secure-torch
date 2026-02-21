# Quick Start

```{note}
**secure-torch** is a drop-in replacement for `torch.load`. Start with zero config and add trust enforcement incrementally.
```

## Install

```bash
pip install secure-torch
```

## Basic usage — drop-in replacement

```python
import secure_torch as torch

model = torch.load("model.pt")
```

That's it. By default, secure-torch:
- Validates the pickle opcode stream (never executes it)
- Validates safetensors headers and dtype allowlist
- Inspects ONNX custom operator domains
- Computes an explainable threat score

## Audit first, enforce later

The recommended onboarding path — **see what would be blocked before blocking it**:

```python
model, report = torch.load("model.pt", audit_only=True)

print(report.threat_level)       # ThreatLevel.MEDIUM
print(report.threat_score)       # 40
print(report.score_breakdown)    # {'unsigned_model': 40}
print(report.warnings)           # ['No Sigstore bundle found — model is unsigned']
```

Once you're comfortable with the scores, enable enforcement:

```python
model = torch.load("model.pt", max_threat_score=20)  # block if score > 20
```

## Require a valid signature

```python
# Online verification (Rekor transparency log)
model = torch.load(
    "model.pt",
    require_signature=True,
    bundle_path="model.pt.sigstore",
)

# Offline verification (air-gapped / enterprise)
model = torch.load(
    "model.pt",
    require_signature=True,
    pubkey_path="trusted.pub",
    bundle_path="model.pt.sig",
)
```

## Trusted publishers

```python
model = torch.load(
    "model.pt",
    trusted_publishers=["huggingface.co/meta", "openai.com"],
)
```

## Sandbox isolation

```python
model = torch.load("model.pt", sandbox=True)
# Loaded in restricted subprocess — no network, no exec
```

## All drop-in surfaces

```python
import secure_torch as torch

torch.load("model.pt")
torch.save(model, "model.pt")
torch.jit.load("model.pt")
torch.hub.load("pytorch/vision", "resnet50")
torch.from_pretrained("bert-base-uncased")
```
