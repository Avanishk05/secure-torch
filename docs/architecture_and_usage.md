# Sectorch (secure-torch) — Architecture & User Guide

This document provides a comprehensive technical deep dive into the `secure-torch` library, explaining its architecture, pipeline, and internal components, followed by a user guide for integration.

---

## 1. Architecture Overview

**secure-torch** is designed as a **Model Trust Enforcement Layer**. It sits between the model storage/distribution layer (e.g., HuggingFace, S3) and the model execution layer (e.g., PyTorch, ONNX Runtime).

### Core Design Principles

1.  **Fail-Closed**: If a security check fails (e.g., missing signature, unknown publisher, high threat score), the default action is to BLOCK the load, raising a specific exception. Blocking occurs when `require_signature=True`, `trusted_publishers` is violated, or `threat_score > max_threat_score`.
2.  **Defense in Depth**: Security controls are layered. Even if one layer is bypassed, others remain (e.g., format validation -> signature verification -> policy enforcement -> sandboxing).
3.  **Explainable Security**: Instead of a binary "safe/unsafe", we calculate a detailed **Threat Score** with named components (e.g., `{'unsigned_model': 40, 'custom_ops_detected': 30}`).
4.  **Compatible API**: The API is fully compatible with `torch.load` (`import secure_torch as torch`), while adding optional security parameters (`audit_only`, `require_signature`, `sandbox`, `trusted_publishers`).

### The 6-Step Pipeline

Every call to `secure_torch.load()` executes a fixed, non-skippable pipeline:

1.  **Format Detection**: Identifies file type by magic bytes or header structure.
2.  **Signature Verification**: Checks for cryptographic signatures (Sigstore bundle or offline public key). Fails fast if `require_signature=True`.
3.  **Threat Scoring**: Inspects file content (without executing code) to calculate a risk score based on dangerous opcodes, metadata, or graph structures.
4.  **Policy Enforcement**: Verifies the signer's identity against the `trusted_publishers` allowlist.
5.  **Sandbox Isolation**: Loads the model in a restricted subprocess (optional `sandbox=True`). On Linux, applies `seccomp` syscall filtering inside the subprocess.
6.  **Return**: Returns the loaded model (or a `(model, report)` tuple if `audit_only=True`).

---

## 2. Codebase Deep Dive

### Core Pipeline (`src/secure_torch/loader.py`)

The entry point is `secure_load()`. It orchestrates the pipeline:

-   **Path Resolution**: Handles string paths, `Path` objects, and file-like objects.
-   **Step 1 (Format Detect)**: Calls `detect_format()`.
-   **Step 2 (Signature)**: Calls `_verify_signature()`. Uses `SigstoreVerifier`.
-   **Step 3 (Threat Score)**: Calls `_run_validators()`, which dispatches to format-specific validators (`pickle_safe`, `safetensors`, `onnx_loader`).
-   **Step 4 (Policy)**: Calls `_enforce_policy()` to check `trusted_publishers`.
-   **Reporting**: Aggregates findings into a `ValidationReport`.
-   **Blocking**: Raises `UnsafeModelError` if `score > max_threat_score` (unless `audit_only=True`).
-   **Step 5 (Sandbox/Load)**: Dispatches to `_sandbox_load()` (subprocess) or `_direct_load()` (in-process).

### Format Detection (`src/secure_torch/format_detect.py`)

-   **`detect_format(path)`**:
    -   Checks file extension first (optimization).
    -   Updates to check **Magic Bytes** logic:
        -   Safetensors: Detected via valid header length (8 bytes little-endian) and JSON header structure.
        -   Pickle-based PyTorch models: Detected via pickle protocol opcodes or PyTorch archive ZIP format.
        -   ONNX: Detected via valid protobuf structure and ONNX graph schema validation.

### Threat Scoring (`src/secure_torch/threat_score.py`)

-   **`ThreatScorer` Class**:
    -   `add(key, score)`: Adds a named threat contributor.
    -   `warn(message)`: Records non-scoring warnings.
    -   `breakdown`: Dictionary of `{reason: score}`.
    -   `threat_level`: Maps total score to `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### Format Validators (`src/secure_torch/formats/`)

#### Pickle (`pickle_safe.py`)
-   **Mechanism**: Uses `pickletools.genops()` to iterate over opcodes *without* executing them.
-   **`STACK_GLOBAL` Handling**: Critical for Python 3.10+ (Protocol 4).
    -   Problem: `STACK_GLOBAL` takes module/name from the stack, so `arg` is None.
    -   Solution: We simulate the stack for string opcodes (`SHORT_BINUNICODE`, etc.) to reconstruct the module name.
-   **Dangerous Modules**: Blocks `os`, `nt` (Windows os alias), `posix` (Linux os alias), `subprocess`, `sys`, `importlib`, `eval`, `exec`.
    -   *Rationale*: These modules enable filesystem access, process execution, dynamic code loading, or memory manipulation and are common targets in pickle deserialization exploits.
-   **CVE-2023-44271**: Specifically blocks the `STACK_GLOBAL` -> `nt.system` gadget used in the Salesforce RCE exploit.

#### SafeTensors (`safetensors.py`)
-   **Header Validation**: JSON header parsing.
-   **Metadata Injection (GHSA-v9fq-2296)**: Scans metadata for suspicious patterns (e.g., code-like strings) that may trigger unsafe behavior in downstream tools.
-   **Large Header**: Warns if header > 100MB (DoS vector).

#### ONNX (`onnx_loader.py`)
-   **Custom Ops (CVE-2024-5980)**: Scans the ONNX graph for operator domains that are not standard (e.g., `com.microsoft`, `com.nvidia`). Custom ops are often implemented as shared libraries (.so/.dll) and are a primary RCE vector in ONNX.
-   **External Data**: Flags models that load external data files (path traversal risk).

### Provenance (`src/secure_torch/provenance/`)

#### Sigstore Verifier (`sigstore_verifier.py`)
-   **Mode 1: Online (Sigstore)**:
    -   Uses `sigstore-python`.
    -   Verifies `.sigstore` bundle against Rekor transparency log.
    -   Checks certificate identity (OIDC issuer/subject).
-   **Mode 2: Offline (Pubkey)**:
    -   Uses `cryptography` (Ed25519 or RSA).
    -   Verifies detached signature (`.sig`) against a local public key (`.pub`).
    -   Essential for air-gapped enterprise environments.

### Policy Enforcement (`src/secure_torch/policy/trust_policy.py`)

-   **`trusted_publishers`**:
    -   List of allowed identities (e.g., `["huggingface.co/meta", "openai.com"]`).
    -   If the signer (from Sigstore or Pubkey) is NOT in this list, `UntrustedPublisherError` is raised.
    -   Fail-closed: If list is provided, ANY unknown signer is rejected.

### Sandbox (`src/secure_torch/sandbox/`)

#### Subprocess Sandbox (`subprocess_sandbox.py`)
-   **Architecture**: Spawns a dedicated Python subprocess (`sys.executable`).
-   **Isolation**:
    -   **Environment**: Strips `HTTP_PROXY`, `HTTPS_PROXY`, `AWS_ACCESS_KEY_ID`, etc., to prevent network access or credential exfiltration.
    -   **Communication**: Passes model path via args, returns tensors via pickle serialization over `multiprocessing.Pipe`. Because deserialization occurs only in the trusted parent process and the sandbox restricts arbitrary execution, this does not introduce additional code execution risk.
    -   **Timeout**: Hard 120s limit to prevent DoS (infinite loops).

#### Seccomp Sandbox (`seccomp_sandbox.py`)
-   **Platform**: Linux only.
-   **Mechanism**: Uses `ctypes` to call `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` *inside the subprocess*.
-   **Policy**: Whitelists only essential syscalls (`read`, `write`, `mmap`, `futex`, `exit`, etc.). Blocks `execve`, `socket`, `connect`, `ptrace`.
-   **Defense**: Prevents the model code (even if it escapes pickle restrictions) from spawning shells (RCE) or opening network connections.

### SBOM (`src/secure_torch/sbom/`)

-   **Parser (`spdx_parser.py`)**: Parses SPDX 2.3/3.0 JSON files. Extracts "AI Profile" fields: `suppliedBy`, `sensitivePersonalInformation`, `trainingDatasets`.
-   **Policy Runner (`opa_runner.py`)**:
    -   Executes OPA (Open Policy Agent) Rego policies against the SBOM.
    -   **Smart Fallback**: Tries to run `opa eval` binary. If missing, falls back to a pure-Python implementation of common Rego patterns (`deny[msg]`, `input.field == value`).

---

## 3. User Guide

### Installation

```bash
pip install secure-torch

# Optional: Add ONNX support
pip install secure-torch[onnx]
# Optional: Add Sigstore support
pip install secure-torch[sigstore]
```

### Basic Usage (Drop-in Replacement)

The easiest way to start is replacing `import torch` with `secure_torch`.

```python
import secure_torch as torch

# Loads safely by default (pickle opcode validation, threat scoring)
model = torch.load("model.pt")
```

### Audit Mode (See what *would* be blocked)

Great for evaluating your current models without breaking production.

```python
# audit_only=True PREVENTS blocking exceptions
model, report = torch.load("model.pt", audit_only=True)

print(f"Threat Score: {report.threat_score} ({report.threat_level.name})")
print(f"Breakdown: {report.score_breakdown}")
# Example output:
# Threat Score: 40 (HIGH)
# Breakdown: {'unsigned_model': 40}
```

### Enforcing Trust

#### 1. Require a Signature

```python
# Fails if no .sigstore bundle is found
model = torch.load("model.pt", require_signature=True)
```

#### 2. Restrict Publishers

```python
# Fails if signer is not in the list
model = torch.load(
    "model.pt",
    trusted_publishers=["huggingface.co/meta-llama", "openai.com"]
)
```

#### 3. Strict Threat Threshold

```python
# Default max_threat_score is 20 (allows SAFE, LOW, and lower MEDIUM scores).
# Set to 0 to block EVERYTHING with any risk (even unsigned models).
model = torch.load("model.pt", max_threat_score=0)
```

| Level | Range | Default Behavior |
|---|---|---|
| SAFE | 0 | Allow |
| LOW | 1–15 | Allow |
| MEDIUM | 16–35 | Allow (if score <= 20) |
| HIGH | 36–60 | Block |
| CRITICAL | 61+ | Block |

### Sandbox Isolation

By default, loading occurs in the main process after validation. For untrusted models or production environments, `sandbox=True` is strongly recommended to ensure process isolation.

```python
model = torch.load("model.pt", sandbox=True)
# If malicious code triggers, the subprocess is killed, protecting your main app.
```

Only `weights_only=True` is enforced for `torch.load` unless overridden. 
> **Note**: `weights_only=True` prevents execution of arbitrary classes during load but may not support legacy models that rely on full object reconstruction.

### Offline Verification (Enterprise)

For environments without internet access to Rekor:

1.  **Sign** (using `openssl`):
    ```bash
    openssl genpkey -algorithm ed25519 -out private.pem
    openssl pkey -in private.pem -pubout -out public.pem
    openssl pkeyutl -sign -inkey private.pem -in model.pt -out model.pt.sig
    ```

2.  **Verify**:
    ```python
    model = torch.load(
        "model.pt",
        require_signature=True,
        pubkey_path="public.pem",
        bundle_path="model.pt.sig"
    )
    ```

### Using with Other Libraries

secure-torch security enforcement currently applies to local artifacts loaded via
`secure_torch.load` and `secure_torch.jit.load`.

`secure_torch.from_pretrained` and `secure_torch.hub.load` are compatibility passthroughs
for remote fetches. They do not enforce signature/publisher/threat-policy checks on remote
artifacts, and passing security args raises `SecurityError`.

#### Hugging Face patch mode (enforced download-time checks)

For `transformers` / `huggingface_hub` workflows, secure-torch also provides a monkey-patch
integration:

```python
import secure_torch
from transformers import AutoModel

secure_torch.patch_huggingface(max_threat_score=20, require_signature=False)
model = AutoModel.from_pretrained("gpt2")
```

This intercepts `huggingface_hub.file_download.hf_hub_download` and runs secure-torch
validators and policy checks before returning the downloaded local file path.
If policy fails, it raises `UnsafeModelError`.

#### Recommended pattern (download, then enforce)

```python
import secure_torch as torch
from huggingface_hub import hf_hub_download

local_path = hf_hub_download(
    repo_id="sentence-transformers/all-MiniLM-L6-v2",
    filename="pytorch_model.bin",
)

model = torch.load(
    local_path,
    require_signature=True,
    trusted_publishers=["huggingface.co/sentence-transformers"],
)
```

#### TorchHub-style workflow

```python
import secure_torch as torch

# 1) Download model artifact with your existing tooling
# 2) Enforce controls on the local file
model = torch.load("artifacts/resnet18.pt", require_signature=True)
```

---

## 4. Security Guarantees & Limitations

### Security Guarantees

secure-torch provides the following guarantees when properly configured:

-   Prevents execution of arbitrary code during model loading (pickle opcode validation + sandbox isolation).
-   Verifies model authenticity via cryptographic signatures.
-   Enforces publisher trust policies.
-   Prevents unauthorized filesystem and network access during loading (sandbox mode).

### Limitations

-   Cannot guarantee safety if `sandbox=False` and validators miss a novel exploit.
-   Does not secure runtime model execution after loading (e.g. malicious weights causing intended but harmful behavior).
