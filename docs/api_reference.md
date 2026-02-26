# API Reference

## `secure_torch.load`

```python
secure_torch.load(
    f,
    *,
    require_signature: bool = False,
    trusted_publishers: list[str] | None = None,
    audit_only: bool = False,
    max_threat_score: int = 20,
    sandbox: bool = False,
    sbom_path: str | None = None,
    sbom_policy_path: str | None = None,
    policy_context: dict | None = None,
    bundle_path: str | None = None,
    pubkey_path: str | None = None,
    map_location=None,
    weights_only: bool = True,
    **kwargs,
) -> Any | tuple[Any, ValidationReport]
```

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `f` | `str \| Path \| IO` | — | Model file path or file-like object |
| `require_signature` | `bool` | `False` | Raise `SignatureRequiredError` if no bundle found |
| `trusted_publishers` | `list[str]` | `None` | Allowlist of trusted signer identities |
| `audit_only` | `bool` | `False` | Load regardless of score; return `(model, report)` |
| `max_threat_score` | `int` | `20` | Block if total score exceeds this |
| `sandbox` | `bool` | `False` | Load in restricted subprocess |
| `sbom_path` | `str` | `None` | Path to SBOM `.spdx.json` file |
| `sbom_policy_path` | `str` | `None` | Path to OPA `.rego` file |
| `policy_context` | `dict` | `None` | Context variable dictionary for Rego |
| `bundle_path` | `str` | `None` | Path to `.sigstore` or `.sig` file |
| `pubkey_path` | `str` | `None` | Path to PEM public key (offline mode) |
| `map_location` | — | `None` | Passed to `torch.load` |
| `weights_only` | `bool` | `True` | Passed to `torch.load` |
| `**kwargs` | — | — | Passed to `torch.load` |

**Returns:** Model object, or `(model, ValidationReport)` if `audit_only=True`.

**Raises:**
- `UnsafePickleError` — dangerous opcode found
- `UnsafeModelError` — threat score exceeds `max_threat_score`
- `SignatureRequiredError` — `require_signature=True` and no bundle found
- `UntrustedPublisherError` — signer not in `trusted_publishers`
- `FormatError` — file format cannot be detected

---

## `secure_torch.save`

```python
secure_torch.save(obj, f, **kwargs) -> None
```

Pass-through to `torch.save`. Included for drop-in compatibility.

---

## `secure_torch.jit.load`

```python
secure_torch.jit.load(f, **kwargs) -> Any
```

Runs the full secure pipeline then loads with `torch.jit.load`.

---

## `secure_torch.hub.load`

```python
secure_torch.hub.load(repo_or_dir, model, **kwargs) -> Any
```

Compatibility wrapper for `torch.hub.load`.

Remote fetches are **not** currently enforced by secure-torch security controls.
If security args are supplied (`require_signature`, `trusted_publishers`, `audit_only`,
`max_threat_score`, `sandbox`, `sbom_*`, `bundle_path`, `pubkey_path`), this call raises
`SecurityError` instead of silently ignoring them.

---

## `secure_torch.from_pretrained`

```python
secure_torch.from_pretrained(model_name_or_path, **kwargs) -> Any
```

Compatibility wrapper for HuggingFace `from_pretrained`.

Remote registry fetches are **not** currently enforced by secure-torch security controls.
If security args are supplied (`require_signature`, `trusted_publishers`, `audit_only`,
`max_threat_score`, `sandbox`, `sbom_*`, `bundle_path`, `pubkey_path`), this call raises
`SecurityError`.

For enforced trust checks, either:
- Download artifacts locally first and use `secure_torch.load()`.
- Or call `secure_torch.patch_huggingface(...)` before your `transformers` workflow.

---

## `secure_torch.patch_huggingface`

```python
secure_torch.patch_huggingface(**security_kwargs) -> None
```

Monkey-patches `huggingface_hub.file_download.hf_hub_download`.
When a downloaded file looks like a model artifact, secure-torch runs format detection,
validators, signature checks, SBOM policy evaluation, and trust-policy enforcement before
returning the local file path.

`security_kwargs` uses the same security controls as `secure_torch.load`
(`require_signature`, `trusted_publishers`, `audit_only`, `max_threat_score`, `sbom_*`,
`bundle_path`, `pubkey_path`, `policy_context`).

---

## `secure_torch.unpatch_huggingface`

```python
secure_torch.unpatch_huggingface() -> None
```

Restores the original `huggingface_hub.file_download.hf_hub_download`.

---

## `ValidationReport`

```python
@dataclass
class ValidationReport:
    path: str
    format: ModelFormat
    threat_level: ThreatLevel
    threat_score: int
    score_breakdown: dict[str, int]
    findings: list[str]
    warnings: list[str]
    size_bytes: int
    load_allowed: bool
    sandbox_active: bool
    provenance: ProvenanceRecord | None = None
    sbom: SBOMRecord | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

---

## `ProvenanceRecord`

```python
@dataclass
class ProvenanceRecord:
    verified: bool
    signer: str | None = None
    issuer: str | None = None
    bundle_path: str | None = None
    mode: str = "sigstore"
    error: str | None = None
```

---

## `ThreatLevel`

```python
class ThreatLevel(str, Enum):
    SAFE     = "SAFE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"
```

---

## `ModelFormat`

```python
class ModelFormat(Enum):
    SAFETENSORS = "safetensors"
    PICKLE      = "pickle"
    ONNX        = "onnx"
    UNKNOWN     = "unknown"
```
