# CVE Coverage

secure-torch includes regression tests for known ML loader CVEs. All tests run on every CI push.

## Covered CVEs

| CVE / Advisory | Affected Library | Attack | secure-torch Response |
|---|---|---|---|
| **CVE-2023-44271** | PyTorch | Pickle RCE via `torch.load` (Salesforce model) | ✅ **Blocked** — `STACK_GLOBAL` opcode with `nt.system` detected and raised |
| **CVE-2023-32686** | Keras | Lambda layer RCE via pickle | ✅ **Blocked** — `subprocess` module reference detected |
| **GHSA-v9fq-2296** | HuggingFace Hub | Pickle injection via safetensors `__metadata__` | ✅ **Scored** — code-like strings in metadata add 50+ to threat score |
| **CVE-2024-5980** | NVIDIA Triton | ONNX custom op RCE | ✅ **Scored** — custom operator domains flagged with 30 score |

## How blocking works

For pickle-based CVEs, the attack payload uses `STACK_GLOBAL` (Python 3.10+ protocol 4) or `GLOBAL` (older protocols) to reference dangerous modules. secure-torch's opcode validator:

1. Tracks the string stack to reconstruct `STACK_GLOBAL` arguments (module, name pushed separately)
2. Checks the module against a `DANGEROUS_MODULES` frozenset
3. Raises `UnsafePickleError` immediately — **never executes the pickle**

Windows-specific: `nt` is the Windows alias for `os`. Both are in the dangerous list.

## Running regression tests

```bash
pytest tests/cve/ -v
```

## Adding a new CVE test

```python
# tests/cve/test_cve_regressions.py

def test_cve_YYYY_NNNNN_description(self):
    """CVE-YYYY-NNNNN — brief description."""
    from secure_torch.formats.pickle_safe import validate_pickle
    from secure_torch.exceptions import UnsafePickleError
    from secure_torch.threat_score import ThreatScorer

    payload = make_pickle_payload("os", "system", ["echo exploit"])
    scorer = ThreatScorer()
    with pytest.raises(UnsafePickleError):
        validate_pickle(payload, scorer)
```
