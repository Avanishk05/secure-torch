CRITICAL ISSUE 1 — IPC serialization statement is technically unsafe wording

You wrote:

returns tensors via controlled serialization (pickle over multiprocessing.Pipe) — preventing arbitrary code execution during transport.

This statement is technically misleading and potentially dangerous.

Pickle itself is inherently unsafe.

Your security relies on sandbox isolation, not pickle safety.

Correct wording must be:

returns tensors via pickle serialization over multiprocessing.Pipe. Because deserialization occurs only in the trusted parent process and the sandbox restricts arbitrary execution, this does not introduce additional code execution risk.

Do NOT claim pickle transport itself is safe. It isn’t. The sandbox containment makes it safe.

Security reviewers will flag this immediately if not corrected.

CRITICAL ISSUE 2 — Sandbox default behavior still needs clearer security framing

You wrote:

By default, loading happens in the main process (subject to pickle validators).

This is correct, but from a security standpoint, it weakens your model.

You must explicitly state risk and recommendation:

Correct version:

By default, loading occurs in the main process after validation. For untrusted models or production environments, sandbox=True is strongly recommended to ensure process isolation.

This avoids giving false impression of full isolation by default.

CRITICAL ISSUE 3 — Threat threshold table contains logical inconsistency

You wrote:

Default max_threat_score is 20 (allows SAFE, LOW, MEDIUM).


But your MEDIUM range is:

MEDIUM: 16–35


If max_threat_score = 20, only MEDIUM scores 16–20 are allowed.

Scores 21–35 would be blocked.

Correct wording:

Default max_threat_score is 20 (allows SAFE, LOW, and lower MEDIUM scores).


This correction is necessary for mathematical consistency.

CRITICAL ISSUE 4 — Pickle format detection description is slightly inaccurate

You wrote:

Pickle: Specific opcodes (PROTO, STOP) or ZIP header.


ZIP header is used for TorchScript and PyTorch archive format, not pickle itself.

Clarify separation:

Correct version:

Pickle-based PyTorch models: detected via pickle protocol opcodes or PyTorch archive ZIP format.


This avoids confusion between pickle and zip container.

IMPORTANT IMPROVEMENT 1 — weights_only=True enforcement needs clarification

You wrote:

weights_only True — enforced for torch.load unless overridden


This is excellent security practice, but must clarify compatibility implications:

Add:

Note: weights_only=True prevents execution of arbitrary classes during load but may not support legacy models that rely on full object reconstruction.


Otherwise users may encounter compatibility surprises.

IMPORTANT IMPROVEMENT 2 — Dangerous modules blocklist should clarify rationale

Your blocklist is excellent, but security reviewers will want rationale.

Add explanation:

These modules enable filesystem access, process execution, dynamic code loading, or memory manipulation and are common targets in pickle deserialization exploits.


This strengthens credibility.

IMPORTANT IMPROVEMENT 3 — Format detection ONNX description slightly too generic

You wrote:

ONNX: \x08 (Varint field 1)


This is protobuf encoding, but not ONNX-specific guarantee.

Safer wording:

ONNX: detected via valid protobuf structure and ONNX graph schema validation.


Avoid implying single-byte detection is sufficient.

What you did exceptionally well

These sections are now excellent and publish-grade:

Threat scoring transparency table
Hardcoded constants disclosure
Sigstore online/offline explanation
Sandbox architecture description
Pickle STACK_GLOBAL explanation
CVE coverage references

These elevate your project above most security tools.

One optional but highly recommended addition (credibility boost)

Add explicit security guarantees section:

Example:

Security Guarantees

secure-torch provides the following guarantees when properly configured:

• Prevents execution of arbitrary code during model loading (pickle opcode validation + sandbox isolation)
• Verifies model authenticity via cryptographic signatures
• Enforces publisher trust policies
• Prevents unauthorized filesystem and network access during loading (sandbox mode)

Limitations:

• Cannot guarantee safety if sandbox=False and validators miss a novel exploit
• Does not secure runtime model execution after loading


This makes your threat model explicit.

Security engineers expect this.