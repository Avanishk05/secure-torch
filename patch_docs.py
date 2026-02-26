import os
import re

file_path = "docs/api_reference.md"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix load() sig
old_load_sig = '''    sbom_path: str | None = None,
    bundle_path: str | None = None,
    pubkey_path: str | None = None,
    map_location=None,
    weights_only: bool = True,
) -> Any | tuple[Any, ValidationReport]'''
new_load_sig = '''    sbom_path: str | None = None,
    sbom_policy_path: str | None = None,
    policy_context: dict | None = None,
    bundle_path: str | None = None,
    pubkey_path: str | None = None,
    map_location=None,
    weights_only: bool = True,
    **kwargs,
) -> Any | tuple[Any, ValidationReport]'''
content = content.replace(old_load_sig, new_load_sig)

# Fix load() param table
old_table = '''| `sandbox` | `bool` | `False` | Load in restricted subprocess |
| `bundle_path` | `str` | `None` | Path to `.sigstore` or `.sig` file |
| `pubkey_path` | `str` | `None` | Path to PEM public key (offline mode) |
| `map_location` | — | `None` | Passed to `torch.load` |
| `weights_only` | `bool` | `True` | Passed to `torch.load` |'''
new_table = '''| `sandbox` | `bool` | `False` | Load in restricted subprocess |
| `sbom_path` | `str` | `None` | Path to SBOM `.spdx.json` file |
| `sbom_policy_path` | `str` | `None` | Path to OPA `.rego` file |
| `policy_context` | `dict` | `None` | Context variable dictionary for Rego |
| `bundle_path` | `str` | `None` | Path to `.sigstore` or `.sig` file |
| `pubkey_path` | `str` | `None` | Path to PEM public key (offline mode) |
| `map_location` | — | `None` | Passed to `torch.load` |
| `weights_only` | `bool` | `True` | Passed to `torch.load` |
| `**kwargs` | — | — | Passed to `torch.load` |'''
content = content.replace(old_table, new_table)

# Fix ValidationReport
old_vr = '''@dataclass
class ValidationReport:
    path: str
    format: ModelFormat
    threat_score: int
    threat_level: ThreatLevel
    score_breakdown: dict[str, int]
    findings: list[str]
    warnings: list[str]
    sha256: str
    size_bytes: int
    load_allowed: bool
    sandbox_active: bool
    provenance: ProvenanceRecord | None'''
new_vr = '''@dataclass
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
    metadata: dict[str, Any] = field(default_factory=dict)'''
content = content.replace(old_vr, new_vr)

# Fix ProvenanceRecord
old_pr = '''@dataclass
class ProvenanceRecord:
    verified: bool
    signer: str | None = None
    issuer: str | None = None
    bundle_path: str | None = None
    mode: str | None = None   # "sigstore" or "pubkey"
    error: str | None = None'''
new_pr = '''@dataclass
class ProvenanceRecord:
    verified: bool
    signer: str | None = None
    issuer: str | None = None
    bundle_path: str | None = None
    mode: str = "sigstore"
    error: str | None = None'''
content = content.replace(old_pr, new_pr)

# Fix ThreatLevel
old_tl = '''class ThreatLevel(Enum):
    SAFE     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4'''
new_tl = '''class ThreatLevel(str, Enum):
    SAFE     = "SAFE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"'''
content = content.replace(old_tl, new_tl)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Docs patched.")
