# Secure-Torch: The Ultimate Guide (Novice to Expert)

Welcome to the definitive guide for `secure-torch`. This document is designed to take you from a complete beginner to a threat-modeling expert capable of diagnosing supply-chain vulnerabilities in machine learning models.

---

## Level 1: Novice — The Basics

### What is secure-torch?
Loading third-party AI models is a major supply chain risk. Standard mechanisms like `torch.load()` or even ONNX Runtime can be vectors for Remote Code Execution (RCE), data exfiltration, or silent model tampering.

`secure-torch` is a **Model Trust Enforcement Layer** that acts as a drop-in secure replacement for standard PyTorch model loading. 

### Quick Start
Install the library:
```bash
pip install secure-torch[all]
```

Replace `torch.load` with `secure_torch.load` in your code:
```python
import secure_torch as torch

# Loads safely. If the model is blatantly malicious, this will raise a SecurityError.
model = torch.load("model.pt")
```

### Hugging Face Integration
If you are using the `transformers` library, you don't even need to change your `from_pretrained` calls. Put this at the top of your script:

```python
import secure_torch
secure_torch.patch_huggingface()

from transformers import AutoModel
# The downloaded model is automatically intercepted and scanned by secure-torch!
model = AutoModel.from_pretrained("gpt2")
```

---

## Level 2: Intermediate — Threat Scoring & Provenance

Unlike basic malware scanners that simply say "pass" or "fail", `secure-torch` uses an explainable **Threat Scoring System**.

### The Threat Score
Every model loaded through `secure-torch` goes through an evaluation. Findings accumulate a score.

*   **0-19 (SAFE / LOW):** Standard loading operations.
*   **20-49 (MEDIUM):** Unsigned models or unknown publishers.
*   **50-79 (HIGH):** Risky metadata or unverified opcodes.
*   **80+ (CRITICAL):** Definite malicious intent (e.g., executing system commands).

**Default Behavior:** By default, `max_threat_score=20`. This means if a score hits 21, `secure-torch` blocks it and raises an `UnsafeModelError`.

### Auditing Models
To see what `secure-torch` is thinking without crashing your app, use `audit_only=True`:

```python
import secure_torch as st

model, report = st.load("model.pt", audit_only=True)
print(report.threat_level)     # e.g., ThreatLevel.MEDIUM
print(report.score_breakdown)  # e.g., {'unsigned_model': 40}
```

Or use the interactive CLI dashboard:
```bash
secure-torch audit model.pt
```

### Trust, Signatures, and Publishers
Cryptographic signatures guarantee that a model hasn't been tampered with and comes from a publisher you trust.

```python
model = st.load(
    "model.pt",
    require_signature=True,
    trusted_publishers=["huggingface.co/meta", "openai.com"]
)
```
If the internal signature (`.sigstore` or offline `.sig` pubkey) doesn't match the identities you listed, the load is blocked instantly.

---

## Level 3: Advanced — The Core Pipeline & Sandbox

To use `secure-torch` effectively in enterprise production, you must understand its strict, unskippable pipeline.

### The Immutable Pipeline
Every `secure_load()` call runs the following fixed sequence:
1.  **Format Detect:** Identifies `.safetensors`, `.pt` (pickle), `.onnx`, etc.
2.  **Signature Verify:** Checks Sigstore bundles or offline Ed25519 public keys. Fail fast if `require_signature=True`.
3.  **Threat Score:** Runs format-specific static analysis (e.g., opcodes, metadata) to accumulate the score.
4.  **Policy Enforce:** Validates against `trusted_publishers` and experimental SPDX SBOM OPA policies (`policy.rego`).
5.  **Sandbox Load:** Evaluates whether model extraction needs absolute OS-level isolation.
6.  **Return Tensors:** Hands the model back to the user.

### The Sandbox (`sandbox=True`)
Even with static opcode scanning, zero-day vulnerabilities in C++ serialization libraries can occur. To prevent this, you can turn on the sandbox.

```python
model = st.load("untrusted_model.pt", sandbox=True)
```
**What happens under the hood:**
1.  A restricted child Python subprocess is spawned.
2.  All network-proxy environment variables (`HTTP_PROXY`, etc.) are stripped.
3.  (On Linux): A strict `seccomp` profile is applied, outright denying network and filesystem-write syscalls.
4.  The model is deserialized inside this child process. If it's malicious, it explodes harmlessly inside the prison.
5.  The resulting pure tensors are extracted, saved to a temporary safe format (`safetensors`), and passed back to the parent process.

---

## Level 4: Expert — The Pickle Opcode Validator

The crown jewel of `secure-torch` is `src/secure_torch/formats/pickle_safe.py`. To be an expert, you must understand how we secure the inherently insecure PyTorch pickle format.

### The Misconception
A common misconception is that "we safely unpickle the model". **We never call `pickle.loads()` during validation.** Unpickling malicious data is what triggers the RCE.

### The Opcode Walker
Instead, `secure-torch` acts as a static analyzer for the pickle stack machine using `pickletools.genops()`. It reads the byte stream instruction by instruction, keeping track of what the stack *would* look like without ever actually instantiating the objects in memory.

### Tracking `GLOBAL` and `STACK_GLOBAL`
In a python pickle exploit, the attacker must import a dangerous module to execute code (e.g., `os.system`). They do this via the `GLOBAL` or `STACK_GLOBAL` opcodes.

1.  **`SAFE_MODULES` Allowlist:** Our engine explicitly guarantees that benign module references required by PyTorch (like `torch`, `torch.nn.parameter`, `collections.OrderedDict`, `numpy.core.multiarray`) are tracked and ignored.
2.  **`DANGEROUS_MODULES` Blocklist:** Any reference to `os`, `subprocess`, `sys`, `importlib`, `builtins.eval`, `socket`, `ctypes`, etc., is fatal. The validator tracks strings pushed to the stack via `BINUNICODE`, intercepts the `STACK_GLOBAL` operator, reads the intended module, and if it sees `posix` or `os`, it instantly raises an `UnsafePickleError`.

### The `REDUCE` Opcode Risk
The `REDUCE` opcode pops a callable and a tuple of arguments off the stack and executes them. If the callable was defined by a safe module (like reconstructing a `torch.Tensor`), it's benign. However, if the opcode references an unknown module, it adds `SCORE_PICKLE_REDUCE_OPCODE` (25 points) to the threat score. Because the default max score is 20, an unverified `REDUCE` command naturally blocks the model payload from continuing through the pipeline unless you explicitly allow higher threat scores.

By marrying this deep opcode state-machine tracking with the hardware-level `seccomp` sandbox, `secure-torch` provides mathematically rigorous guarantees against model supply-chain execution attacks.
