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

## Compatibility surfaces

```python
import secure_torch as torch

torch.load("model.pt")
torch.save(model, "model.pt")
torch.jit.load("model.pt")  # secure pipeline for local artifacts
torch.hub.load("pytorch/vision", "resnet50")      # remote convenience passthrough
torch.from_pretrained("bert-base-uncased")        # remote convenience passthrough
```

`torch.hub.load` and direct `torch.from_pretrained` calls currently do **not** enforce secure-torch security checks for remote fetches.
If you pass security args (`require_signature`, `trusted_publishers`, `audit_only`, `max_threat_score`, `sandbox`, `sbom_*`, `bundle_path`, `pubkey_path`) they raise `SecurityError`.
Use remote APIs only for convenience, or download model artifacts first and run `torch.load(local_path, ...)` for enforced controls.

## Hugging Face integration (patch mode)

If your stack uses `transformers` / `huggingface_hub`, you can apply a global patch so downloads
are validated before returning to callers:

```python
import secure_torch
from transformers import AutoModel

secure_torch.patch_huggingface(max_threat_score=20)
model = AutoModel.from_pretrained("gpt2")
```

This intercepts `huggingface_hub.file_download.hf_hub_download` and runs the secure-torch
validation pipeline on model files. If a file violates policy, it raises `UnsafeModelError`.
Call `secure_torch.unpatch_huggingface()` to restore original behavior.

## Audit CLI

```bash
# Rich console report when rich is installed; plain summary fallback otherwise
secure-torch audit model.pt

# JSON output for pipelines
secure-torch audit model.pt --json
```
