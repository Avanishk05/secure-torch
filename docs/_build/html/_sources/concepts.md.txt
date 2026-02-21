# Core Concepts

## Why secure-torch?

Loading third-party AI models is a supply chain risk. Common attack vectors:

| Attack | Vector | Example CVE |
|---|---|---|
| Pickle RCE | `torch.load` without `weights_only=True` | CVE-2023-44271 |
| Lambda RCE | Keras model pickle | CVE-2023-32686 |
| Metadata injection | safetensors `__metadata__` field | GHSA-v9fq-2296 |
| Custom op RCE | ONNX external operator domains | CVE-2024-5980 |

## The Model Trust Gap

The ML ecosystem handles trust at the distribution layer (HuggingFace, container registries, package managers). **Loader libraries assume trusted input.**

secure-torch creates a new abstraction: the **Model Trust Enforcement Layer** — sitting between the distribution layer and your inference code.

```
[HuggingFace / S3 / Registry]
         ↓
[secure-torch Trust Layer]   ← signature verify, policy enforce, sandbox
         ↓
[Your inference code]
```

## How it complements safetensors

[safetensors](https://github.com/huggingface/safetensors) solves unsafe deserialization and memory safety. **secure-torch adds the trust layer on top:**

| Library | What it solves |
|---|---|
| safetensors | Unsafe deserialization, memory safety |
| **secure-torch** | Signature verification, publisher policy, provenance, sandboxing |

secure-torch wraps safetensors, PyTorch pickle, and ONNX — adding trust enforcement to all three.

## The Pipeline

Every `secure_load()` call runs this fixed pipeline. Steps cannot be skipped or reordered:

```
secure_load(file)
  1. format detect        ← .safetensors / .pt / .onnx / magic bytes
  2. signature verify     ← fail fast if require_signature=True
  3. threat score         ← explainable named dict
  4. policy enforce       ← trusted_publishers check
  5. sandbox load         ← subprocess (+ seccomp on Linux)
  6. return tensors
```

## Threat Score

The threat score is a **named breakdown**, not a magic number:

```python
{
    "unsigned_model": 40,
    "custom_ops_detected": 30,
    "unknown_publisher": 20,
}
# total: 90 → ThreatLevel.CRITICAL
```

| Score | Level | Default action |
|---|---|---|
| 0 | SAFE | Load |
| 1–19 | LOW | Load |
| 20–49 | MEDIUM | **Block** (default threshold) |
| 50–79 | HIGH | Block |
| 80+ | CRITICAL | Block |

Use `audit_only=True` to load regardless and inspect the report.

## Fail-Closed Design

secure-torch is designed to **fail closed**:

- `require_signature=True` → raises `SignatureRequiredError` if no bundle found
- `trusted_publishers=[...]` → raises `UntrustedPublisherError` if signer not in list
- Score > `max_threat_score` → raises `UnsafeModelError`

Use `audit_only=True` to override blocking during evaluation.
