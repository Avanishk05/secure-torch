# Hardcoded Configuration & Constants

This document lists all hardcoded values, constants, and configuration parameters found in the `secure-torch` codebase.

---

## 1. Threat Scoring (`src/secure_torch/threat_score.py`)

Scores are hardcoded integers representing risk contribution.

| Constant | Value | Description |
|---|---|---|
| `SCORE_UNSIGNED_MODEL` | 40 | No Sigstore/Pubkey signature found |
| `SCORE_CUSTOM_OPS_DETECTED` | 30 | ONNX model contains custom operator domains |
| `SCORE_UNKNOWN_PUBLISHER` | 20 | Signature valid but signer not in `trusted_publishers` |
| `SCORE_PICKLE_REDUCE_OPCODE` | 25 | Pickle `REDUCE` opcode found |
| `SCORE_PICKLE_GLOBAL_DANGEROUS` | 40 | Reference to dangerous module (blocks load) |
| `SCORE_PICKLE_GLOBAL_UNKNOWN` | 10 | Reference to safe but unknown module |
| `SCORE_PICKLE_INST_OPCODE` | 10 | Pickle `INST` opcode (older RCE vector) |
| `SCORE_ONNX_NESTED_GRAPH` | 10 | ONNX graph contains subgraphs |
| `SCORE_SAFETENSORS_CODE_IN_METADATA` | 50 | Code-like strings in metadata (e.g. `eval(`, `os.system`) |
| `SCORE_SBOM_MISSING` | 20 | Provided SBOM path failed to parse or was missing |
| `SCORE_PROVENANCE_UNVERIFIABLE` | 25 | Signature exists but verification failed |
| `SCORE_HEADER_OVERSIZED` | 15 | Safetensors header > 100MB |
| `SCORE_DTYPE_UNSAFE` | 35 | Unsafe dtype detected (e.g. object) |

---

## 2. Threat Levels (`src/secure_torch/models.py`)

Thresholds mapping numeric scores to qualitative levels.

| Level | Score Range |
|---|---|
| `SAFE` | 0 |
| `LOW` | 1 – 19 |
| `MEDIUM` | 20 – 49 |
| `HIGH` | 50 – 79 |
| `CRITICAL` | 80+ |

---

## 3. Loader Defaults (`src/secure_torch/loader.py`)

| Parameter | Default Value | Description |
|---|---|---|
| `max_threat_score` | **20** | Default blocking threshold (allows SAFE, LOW, LOW-MEDIUM) |
| `weights_only` | `True` | Enforced for `torch.load` unless overridden |
| `sandbox` | `False` | Sandbox is OPTIONAL by default |
| `audit_only` | `False` | Blocking enforcement is ACTIVE by default |

---

## 4. Pickle Validation (`src/secure_torch/formats/pickle_safe.py`)

### Dangerous Modules (Fail-Closed Blocklist)
Hardcoded list of modules that trigger `UnsafePickleError`.

- `os`
- `nt` (Windows alias)
- `posix` (Linux alias)
- `subprocess`
- `sys`
- `importlib`
- `importlib.import_module`
- `builtins.eval`, `builtins.exec`, `builtins.compile`, `builtins.__import__`
- `socket`, `shutil`, `pathlib`
- `ctypes`, `cffi`
- `multiprocessing`, `threading`
- `pty`, `signal`, `gc`, `weakref`

### Safe Modules (Allowlist)
Modules allowed without penalty score.

- `torch` (and submodules)
- `collections`, `collections.OrderedDict`
- `_codecs`
- `numpy` (and submodules)
- `__builtin__`, `builtins`

---

## 5. Sandbox (`src/secure_torch/sandbox/subprocess_sandbox.py`)

| Constant | Value | Description |
|---|---|---|
| `timeout` | **120** seconds | Hard limit for subprocess execution |
| `env` filtering | `PROXY`, `HTTP`, `HTTPS`, `FTP`, `SOCKS` | Environment variables stripped from subprocess |

---

## 6. Format Detection (`src/secure_torch/format_detect.py`)

### Magic Bytes coverage
- **Pickle**: `\x80` + protocol version (`\x02`–`\x05`) or ZIP header (`PK\x03\x04`)
- **ONNX**: `\x08` (Varint field 1)
- **Safetensors**: No magic bytes (uses JSON header validation)
