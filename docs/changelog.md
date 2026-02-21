# Changelog

## 0.1.0 (2026-02-18)

### Added

- **Unified 6-step pipeline** — format detect → signature verify → threat score → policy enforce → sandbox → return
- **Pickle opcode validator** — `pickletools.genops()` based, never executes pickle, handles `STACK_GLOBAL` (protocol 4)
- **SafeTensors validator** — header validation, dtype allowlist, metadata injection detection
- **ONNX validator** — custom op domain detection, external data, nested graphs
- **Explainable threat scoring** — named breakdown dict, not a magic number
- **Sigstore verification** — online (Rekor) and offline (Ed25519/RSA pubkey) modes
- **Trust policy enforcement** — `trusted_publishers` allowlist, fail-closed
- **Subprocess sandbox** — cross-platform, strips proxy env vars, 120s timeout
- **seccomp sandbox** — Linux only, applied inside subprocess
- **SBOM parsing** — SPDX 2.3/3.0 AI Profile (experimental)
- **OPA policy runner** — `opa` binary + pure-Python fallback
- **`audit_only=True`** — load regardless of score, return `(model, report)`
- **Drop-in API** — `import secure_torch as torch`
- **CVE regression tests** — CVE-2023-44271, CVE-2023-32686, GHSA-v9fq-2296, CVE-2024-5980
- **GitHub Actions CI** — multi-OS × multi-Python matrix, Trusted Publishing, Sigstore signing
- **Weekly security scan** — Bandit SAST + pip-audit

### Fixed

- `STACK_GLOBAL` opcode handling — Python 3.10+ protocol 4 pushes module and name as separate strings; added string stack tracking
- Added `nt` (Windows) and `posix` (Unix) as `os` aliases to `DANGEROUS_MODULES`
