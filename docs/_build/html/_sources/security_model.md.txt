# Security Model

## Threat model

secure-torch defends against:

1. **Malicious model files** — pickle payloads, ONNX custom ops, safetensors metadata injection
2. **Supply chain attacks** — unsigned models, models from untrusted publishers
3. **Sandbox escapes** — subprocess isolation limits blast radius of any bypass

secure-torch does **not** defend against:
- Compromised Python runtime
- Kernel exploits (seccomp reduces but does not eliminate this)
- Adversarial model weights (biased outputs, backdoors) — this is a separate problem

## Defense in depth

```
Layer 1: Format validation     ← opcode inspection, header checks, dtype allowlist
Layer 2: Signature verification ← provenance before loading
Layer 3: Threat scoring        ← explainable risk quantification
Layer 4: Policy enforcement    ← publisher allowlist, fail-closed
Layer 5: Sandbox isolation     ← subprocess + seccomp (Linux)
```

All 5 layers run on every load. No layer can be bypassed by the model file.

## Fail-closed design

Every security check fails closed:

- Missing signature → `SignatureRequiredError` (if `require_signature=True`)
- Unknown publisher → `UntrustedPublisherError`
- High threat score → `UnsafeModelError`
- Dangerous opcode → `UnsafePickleError`

`audit_only=True` is the **only** way to override blocking.

## Reporting a vulnerability

Please report security vulnerabilities via GitHub Security Advisories:

**[Report a vulnerability](https://github.com/Avanishk05/secure-torch/security/advisories/new)**

Do **not** open a public issue for security vulnerabilities.

We aim to respond within 48 hours and publish a fix within 7 days for critical issues.
