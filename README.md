# secure-torch

**Model Trust Gateway** — Unified, defense-in-depth Python library for safely loading AI model files.

[![CI](https://github.com/Avanishk05/secure-torch/actions/workflows/ci.yml/badge.svg)](https://github.com/Avanishk05/secure-torch/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secure-torch)](https://pypi.org/project/secure-torch/)
[![Python](https://img.shields.io/pypi/pyversions/secure-torch)](https://pypi.org/project/secure-torch/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## What is secure-torch?

Loading third-party AI models is a supply chain risk. `torch.load`, ONNX Runtime, and safetensors have all been vectors for RCE, data exfiltration, and silent model tampering.

**secure-torch** is a **Model Trust Enforcement Layer** — not just a safe loader wrapper.

It adds what the ML ecosystem is missing:

| Feature | What it does |
|---|---|
| **Signature verification** | Verify model provenance before loading (online + offline) |
| **Trust policy enforcement** | Block models from untrusted publishers |
| **Pickle opcode validation** | Inspect opcodes without executing — blocks RCE payloads |
| **Sandbox isolation** | Load in restricted subprocess (seccomp on Linux) |
| **Explainable threat scoring** | Named breakdown, not a magic number |
| **SBOM parsing** | SPDX AI Profile support (experimental) |

### How it complements safetensors

[safetensors](https://github.com/huggingface/safetensors) solves unsafe deserialization and memory safety. **secure-torch adds the trust layer on top** — signature verification, publisher policy, and provenance validation — for safetensors, PyTorch pickle, and ONNX alike.

---

## Quick Start

```bash
pip install secure-torch
```

### Drop-in usage

```python
import secure_torch as torch          # drop-in replacement

model = torch.load("model.pt")        # safe by default
```

### Require a valid signature

```python
model = torch.load(
    "model.pt",
    require_signature=True,
    bundle_path="model.pt.sigstore",  # online Rekor verification
)
```

### Offline verification (enterprise / air-gapped)

```python
model = torch.load(
    "model.pt",
    require_signature=True,
    pubkey_path="trusted.pub",        # Ed25519 public key
    bundle_path="model.pt.sig",       # raw signature bytes
)
```

### Trusted publishers allowlist

```python
model = torch.load(
    "model.pt",
    trusted_publishers=["huggingface.co/meta", "openai.com"],
)
```

### Audit first, block later (gradual adoption)

```python
model, report = torch.load("model.pt", audit_only=True)

print(report.threat_level)       # ThreatLevel.LOW
print(report.score_breakdown)    # {'unsigned_model': 40}
print(report.warnings)           # ['No signature bundle found']
```

### Sandbox isolation

```python
model = torch.load("model.pt", sandbox=True)
# Model loaded in restricted subprocess (strict exec/network blocking via seccomp on Linux)
```

### Other compatibility surfaces

```python
torch.jit.load("model.pt")  # secure pipeline for local artifacts
torch.hub.load("pytorch/vision", "resnet50")      # remote convenience passthrough
torch.from_pretrained("bert-base-uncased")        # remote convenience passthrough
torch.save(model, "model.pt")
```

`torch.hub.load` and direct `torch.from_pretrained` calls do **not** currently enforce secure-torch security checks for remote fetches.
Passing security arguments (`require_signature`, `trusted_publishers`, `audit_only`, `max_threat_score`, `sandbox`, `sbom_*`, `bundle_path`, `pubkey_path`) raises `SecurityError`.
For enforced security controls, download artifacts first and call `torch.load(local_path, ...)`, or use `secure_torch.patch_huggingface(...)` for Hugging Face download interception.

### Hugging Face integration (automatic download scanning)

```python
import secure_torch
from transformers import AutoModel

# Global monkey-patch: intercept hf_hub_download and validate model files.
secure_torch.patch_huggingface(require_signature=False, max_threat_score=20)

model = AutoModel.from_pretrained("gpt2")

# Optional cleanup when done.
secure_torch.unpatch_huggingface()
```

`patch_huggingface(...)` hooks `huggingface_hub.file_download.hf_hub_download`.
For model-like files (`.pt`, `.pth`, `.bin`, `.safetensors`, `.onnx`),
secure-torch runs format detection, validators, signature/publisher checks, and threat policy
evaluation before returning the downloaded file path. Unsafe artifacts are blocked with
`UnsafeModelError`.

### Interactive CLI audit

```bash
# Styled report (rich-enabled when available)
secure-torch audit model.pt

# Machine-readable output
secure-torch audit model.pt --json
```

---

## Pipeline

Every `secure_load()` call runs this fixed pipeline — steps cannot be skipped:

```
secure_load(file)
  1. format detect        ← .safetensors / .pt / .onnx / magic bytes
  2. signature verify     ← fail fast if require_signature=True
  3. threat score         ← explainable named dict
  4. policy enforce       ← trusted_publishers check
  5. sandbox load         ← subprocess (+ seccomp on Linux)
  6. return tensors
```

---

## Threat Scoring

Scores are **named and explainable** — not a magic number:

```python
model, report = torch.load("model.pt", audit_only=True)
print(report.score_breakdown)
# {
#   'unsigned_model': 40,
#   'custom_ops_detected': 30,
#   'unknown_publisher': 20,
# }
# total: 90 → ThreatLevel.CRITICAL
```

| Score | Threat Level |
|---|---|
| 0 | SAFE |
| 1–19 | LOW |
| 20–49 | MEDIUM |
| 50–79 | HIGH |
| 80+ | CRITICAL |

Default `max_threat_score` is **20** (MEDIUM). Adjust with `max_threat_score=N`.

---

## SBOM Policy (Experimental)

> **Note:** SPDX AI Profile is not yet widely adopted (early 2026). This feature is forward-looking — secure-torch is helping establish the standard.

```python
from secure_torch.sbom.spdx_parser import parse_sbom
from secure_torch.sbom.opa_runner import OPAPolicyRunner

sbom = parse_sbom("model.spdx.json")
runner = OPAPolicyRunner("policy/production.rego")
denials = runner.evaluate(sbom, context={"environment": "production"})

if denials:
    raise RuntimeError(f"Policy violations: {denials}")
```

Example policy (`policy/production.rego`):

```rego
package secure_torch.policy

deny[msg] {
    input.sensitivePersonalInformation == "yes"
    msg := "Model contains sensitive personal information"
}

deny[msg] {
    ds := input.aiProfile.trainingDatasets[_]
    startswith(ds.license, "GPL")
    input.environment == "production"
    msg := sprintf("GPL dataset '%v' blocked in production", [ds.name])
}
```

---

## Supported Formats

| Format | Validator | Notes |
|---|---|---|
| `.safetensors` | Header + dtype allowlist | Complements safetensors library |
| `.pt` / `.pth` / `.bin` | Pickle opcode validator | Never executes pickle |
| `.onnx` | Protobuf inspector | Custom op domain detection |

---

## Signature Verification

### Mode 1 — Online (Sigstore / Rekor)

```python
# Sign your model
cosign sign-blob model.pt --bundle model.pt.sigstore

# Verify on load
torch.load("model.pt", require_signature=True, bundle_path="model.pt.sigstore")
```

### Mode 2 — Offline (Ed25519 pubkey)

```python
# Sign
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
openssl pkeyutl -sign -inkey private.pem -in model.pt -out model.pt.sig

# Verify on load
torch.load("model.pt", require_signature=True, pubkey_path="public.pem", bundle_path="model.pt.sig")
```

---

## CVE Coverage

| CVE | Attack | Status |
|---|---|---|
| CVE-2023-44271 | PyTorch pickle RCE (Salesforce) | ✅ Blocked |
| GHSA-v9fq-2296 | HuggingFace metadata injection | ✅ Scored |
| CVE-2024-5980 | NVIDIA Triton ONNX custom op RCE | ✅ Scored |

---

## Installation

```bash
pip install secure-torch

# With ONNX support
pip install secure-torch[onnx]

# With Sigstore online verification
pip install secure-torch[sigstore]

# With offline public-key verification
pip install secure-torch[crypto]

# Everything
pip install secure-torch[all]
```

---

## Development

```bash
git clone https://github.com/Avanishk05/secure-torch
cd secure-torch
pip install -e .
pip install pytest pytest-cov mypy ruff bandit
pytest tests/
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
