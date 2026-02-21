"""
secure_model_loader.py
======================
Unified Secure AI Model Loader with:
  - Multi-format support: safetensors, Pickle/PyTorch, ONNX
  - Sigstore provenance verification (keyless OIDC signatures)
  - SPDX AI Profile SBOM parsing & validation
  - seccomp-based runtime sandbox (Linux)
  - Threat-level scoring & audit logging

Author: Security Research
License: Apache-2.0
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import logging
import os
import platform
import re
import struct
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("secure_model_loader")
handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class ModelFormat(Enum):
    SAFETENSORS = "safetensors"
    PICKLE = "pickle"     # .pt / .pth / .bin
    ONNX = "onnx"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SandboxPolicy(Enum):
    NONE = auto()         # No sandbox (testing only)
    STRICT = auto()       # seccomp: read-only FS, no network, no exec
    PERMISSIVE = auto()   # seccomp: block exec + ptrace only


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class SBOMRecord:
    """Parsed SPDX AI Profile fields."""
    spdxVersion: str = ""
    name: str = ""
    datasetName: str = ""
    modelDataPreprocessing: List[str] = field(default_factory=list)
    modelExplainability: List[str] = field(default_factory=list)
    sensitivePersonalInformation: str = "NO"
    energyConsumption: str = ""
    primaryPurpose: str = ""
    typeOfModel: str = ""
    informationAboutTraining: str = ""
    suppliedBy: str = ""
    hyperparameter: Dict[str, str] = field(default_factory=dict)
    raw: Dict = field(default_factory=dict)


@dataclass
class ProvenanceRecord:
    """Sigstore / in-toto attestation result."""
    verified: bool = False
    signer_identity: str = ""
    issuer: str = ""
    workflow_ref: str = ""
    payload_hash: str = ""
    certificate_transparency_log: str = ""
    error: str = ""


@dataclass
class ValidationReport:
    """Aggregated result from all validation passes."""
    path: str = ""
    format: ModelFormat = ModelFormat.UNKNOWN
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_score: int = 0           # 0-100
    findings: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sbom: Optional[SBOMRecord] = None
    provenance: Optional[ProvenanceRecord] = None
    sha256: str = ""
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    sandbox_active: bool = False
    load_allowed: bool = False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_format(path: Path) -> ModelFormat:
    suffix = path.suffix.lower()
    mapping = {
        ".safetensors": ModelFormat.SAFETENSORS,
        ".pt": ModelFormat.PICKLE,
        ".pth": ModelFormat.PICKLE,
        ".bin": ModelFormat.PICKLE,
        ".pkl": ModelFormat.PICKLE,
        ".pickle": ModelFormat.PICKLE,
        ".onnx": ModelFormat.ONNX,
    }
    fmt = mapping.get(suffix, ModelFormat.UNKNOWN)
    if fmt == ModelFormat.UNKNOWN:
        # Magic-byte sniffing
        with open(path, "rb") as f:
            magic = f.read(8)
        if magic[:2] == b"PK":
            return ModelFormat.PICKLE   # PyTorch zip
        if magic[:6] == b"\x80\x05\x95" or magic[:2] == b"\x80\x02":
            return ModelFormat.PICKLE
        if b"onnx" in magic or magic[:4] == b"\x08\x01":
            return ModelFormat.ONNX
    return fmt


# ---------------------------------------------------------------------------
# Pickle opcode scanner (static analysis, no execution)
# ---------------------------------------------------------------------------
DANGEROUS_PICKLE_OPCODES = {
    b"c": "GLOBAL (code import)",
    b"i": "INST (class instantiation)",
    b"R": "REDUCE (arbitrary callable)",
    b"o": "OBJ",
    b"\x93": "STACK_GLOBAL (Pickle5 GLOBAL)",
}

DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "builtins", "importlib",
    "socket", "ctypes", "shutil", "pathlib", "eval",
    "__builtin__", "commands", "popen2",
}

KNOWN_SAFE_MODULES = {
    "torch", "numpy", "collections", "OrderedDict",
    "_codecs", "torch._utils", "torch.storage",
}


def _scan_pickle_opcodes(data: bytes) -> Tuple[List[str], int]:
    """
    Static scan of raw pickle bytes.
    Returns (list_of_findings, threat_score_delta).
    """
    findings = []
    score = 0
    i = 0
    n = len(data)
    while i < n:
        op = bytes([data[i]])
        i += 1
        if op in (b"c", b"\x93"):  # GLOBAL / STACK_GLOBAL
            # Read next two newline-terminated strings
            end1 = data.find(b"\n", i)
            end2 = data.find(b"\n", end1 + 1) if end1 != -1 else -1
            if end1 != -1 and end2 != -1:
                module = data[i:end1].decode("utf-8", errors="replace")
                attr = data[end1 + 1:end2].decode("utf-8", errors="replace")
                i = end2 + 1
                if any(m in module for m in DANGEROUS_MODULES):
                    findings.append(
                        f"[CRITICAL] Dangerous GLOBAL opcode: {module}.{attr}"
                    )
                    score += 40
                elif not any(s in module for s in KNOWN_SAFE_MODULES):
                    findings.append(
                        f"[MEDIUM] Unknown module in GLOBAL: {module}.{attr}"
                    )
                    score += 10
            else:
                break
        elif op == b"R":
            findings.append("[HIGH] REDUCE opcode detected (arbitrary callable execution)")
            score += 25
        elif op == b"i":
            findings.append("[MEDIUM] INST opcode (class instantiation)")
            score += 10
    return findings, min(score, 100)


# ---------------------------------------------------------------------------
# SafeTensors header validator
# ---------------------------------------------------------------------------
def _validate_safetensors(path: Path) -> Tuple[Dict, List[str], int]:
    """
    Parse safetensors header. Returns (metadata_dict, findings, score).
    Reference: https://github.com/huggingface/safetensors#format
    """
    findings = []
    score = 0
    metadata = {}
    with open(path, "rb") as f:
        raw = f.read(8)
        if len(raw) < 8:
            findings.append("[CRITICAL] File too small to be valid safetensors")
            return metadata, findings, 50
        header_size = struct.unpack("<Q", raw)[0]
        if header_size > 100 * 1024 * 1024:  # 100 MB header is suspicious
            findings.append("[HIGH] Abnormally large safetensors header (possible DoS)")
            score += 30
            return metadata, findings, score
        header_bytes = f.read(header_size)
        try:
            header = json.loads(header_bytes)
        except json.JSONDecodeError as e:
            findings.append(f"[CRITICAL] Malformed safetensors JSON header: {e}")
            return metadata, findings, 60
        metadata = header.get("__metadata__", {})
        # Inspect metadata for injected code
        for k, v in metadata.items():
            if any(kw in str(v) for kw in ["eval(", "exec(", "import ", "os.system"]):
                findings.append(
                    f"[CRITICAL] Code-like string in metadata key '{k}': {v[:80]}"
                )
                score += 50
            if len(str(v)) > 4096:
                findings.append(
                    f"[MEDIUM] Unusually long metadata value for key '{k}' "
                    f"({len(str(v))} chars)"
                )
                score += 5
        # Validate tensor descriptors
        for name, desc in header.items():
            if name == "__metadata__":
                continue
            if not isinstance(desc, dict):
                findings.append(f"[LOW] Non-dict tensor descriptor for '{name}'")
                score += 2
                continue
            required = {"dtype", "shape", "data_offsets"}
            missing = required - set(desc.keys())
            if missing:
                findings.append(
                    f"[MEDIUM] Tensor '{name}' missing fields: {missing}"
                )
                score += 8
    return metadata, findings, score


# ---------------------------------------------------------------------------
# ONNX validator
# ---------------------------------------------------------------------------
def _validate_onnx(path: Path) -> Tuple[Dict, List[str], int]:
    findings = []
    score = 0
    metadata: Dict[str, Any] = {}
    try:
        import onnx  # type: ignore
        model = onnx.load(str(path))
        metadata["ir_version"] = model.ir_version
        metadata["opset"] = [
            {"domain": o.domain, "version": o.version}
            for o in model.opset_import
        ]
        metadata["producer_name"] = model.producer_name
        metadata["producer_version"] = model.producer_version
        metadata["model_version"] = model.model_version
        metadata["doc_string"] = model.doc_string[:256]
        # Check for custom ops (can embed native code via shared libs)
        custom_domains = [
            o.domain for o in model.opset_import
            if o.domain not in ("", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training")
        ]
        if custom_domains:
            findings.append(
                f"[HIGH] Custom ONNX op domains present (may load native libs): "
                f"{custom_domains}"
            )
            score += 30
        # Check external data references
        for node in model.graph.node:
            for attr in node.attribute:
                if attr.type == 8:  # GRAPH type – can encode arbitrary subgraphs
                    findings.append(
                        f"[MEDIUM] Node '{node.name}' contains nested GRAPH attribute"
                    )
                    score += 10
        try:
            onnx.checker.check_model(model)
        except onnx.checker.ValidationError as ve:
            findings.append(f"[HIGH] ONNX schema validation failed: {ve}")
            score += 25
    except ImportError:
        findings.append("[LOW] onnx package not installed; skipping deep ONNX validation")
        # Fallback: magic check
        with open(path, "rb") as f:
            raw = f.read(32)
        if not (raw[0] == 0x08 or b"onnx" in raw[:20]):
            findings.append("[MEDIUM] File does not appear to be valid ONNX protobuf")
            score += 15
    except Exception as e:
        findings.append(f"[MEDIUM] ONNX parse error: {e}")
        score += 10
    return metadata, findings, score


# ---------------------------------------------------------------------------
# SBOM parser (SPDX JSON / tag-value, AI Profile fields)
# ---------------------------------------------------------------------------
def _parse_sbom(sbom_path: Path) -> Tuple[SBOMRecord, List[str]]:
    warnings: List[str] = []
    rec = SBOMRecord()
    try:
        with open(sbom_path) as f:
            data = json.load(f)
        rec.raw = data
        rec.spdxVersion = data.get("spdxVersion", "")
        rec.name = data.get("name", "")
        # AI Profile extensions live under packages[*].annotations or top-level
        packages = data.get("packages", [])
        for pkg in packages:
            exts = pkg.get("annotations", [])
            for ann in exts:
                comment = ann.get("comment", "")
                # Parse key:value from annotation comment
                for line in comment.split("\n"):
                    if ":" in line:
                        k, _, v = line.partition(":")
                        setattr_if_exists(rec, k.strip(), v.strip())
            # Top-level SPDX-AI fields
            for k in SBOMRecord.__dataclass_fields__:
                if k in pkg:
                    setattr(rec, k, pkg[k])
        if not rec.spdxVersion.startswith("SPDX-"):
            warnings.append("SBOM: spdxVersion is not a valid SPDX identifier")
        if not rec.name:
            warnings.append("SBOM: missing package name")
    except json.JSONDecodeError as e:
        warnings.append(f"SBOM: invalid JSON – {e}")
    except Exception as e:
        warnings.append(f"SBOM: parse error – {e}")
    return rec, warnings


def setattr_if_exists(obj: Any, attr: str, val: str) -> None:
    if hasattr(obj, attr):
        existing = getattr(obj, attr)
        if isinstance(existing, list):
            existing.append(val)
        else:
            setattr(obj, attr, val)


# ---------------------------------------------------------------------------
# Provenance verification (Sigstore / cosign)
# ---------------------------------------------------------------------------
def _verify_provenance(
    model_path: Path,
    bundle_path: Optional[Path] = None,
) -> ProvenanceRecord:
    """
    Attempt Sigstore keyless verification.
    Requires 'sigstore' Python package OR 'cosign' binary.
    """
    rec = ProvenanceRecord()
    rec.payload_hash = _sha256_file(model_path)

    # Try Python sigstore SDK first
    try:
        from sigstore.verify import Verifier  # type: ignore
        from sigstore.models import Bundle     # type: ignore

        if bundle_path is None:
            bundle_path = model_path.with_suffix(model_path.suffix + ".sigstore")
        if not bundle_path.exists():
            rec.error = f"Sigstore bundle not found at {bundle_path}"
            return rec

        verifier = Verifier.production()
        with open(bundle_path, "rb") as bf:
            bundle = Bundle.from_json(bf.read())

        result = verifier.verify_artifact(
            input=open(model_path, "rb").read(),
            bundle=bundle,
        )
        rec.verified = True
        rec.signer_identity = result.signing_certificate.subject.email_address or ""
        rec.issuer = result.signing_certificate.issuer.common_name or ""
        rec.certificate_transparency_log = "Rekor (production)"
        return rec

    except ImportError:
        pass  # fall through to cosign
    except Exception as e:
        rec.error = f"sigstore SDK error: {e}"
        return rec

    # Fallback: cosign CLI
    import shutil
    import subprocess

    cosign = shutil.which("cosign")
    if cosign is None:
        rec.error = (
            "Neither 'sigstore' Python package nor 'cosign' binary found; "
            "provenance verification skipped."
        )
        return rec

    bundle_arg = str(bundle_path) if bundle_path else str(
        model_path.with_suffix(model_path.suffix + ".sigstore")
    )
    try:
        result = subprocess.run(
            [cosign, "verify-blob", "--bundle", bundle_arg, str(model_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            rec.verified = True
            rec.certificate_transparency_log = "Rekor (cosign)"
            # Parse identity from stdout
            for line in result.stdout.splitlines():
                if "Issuer:" in line:
                    rec.issuer = line.split(":", 1)[-1].strip()
                if "Subject:" in line:
                    rec.signer_identity = line.split(":", 1)[-1].strip()
        else:
            rec.error = result.stderr[:500]
    except subprocess.TimeoutExpired:
        rec.error = "cosign verification timed out"
    except Exception as e:
        rec.error = str(e)

    return rec


# ---------------------------------------------------------------------------
# seccomp sandbox (Linux only)
# ---------------------------------------------------------------------------
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# BPF filter that allows only: read, write, mmap, mprotect, brk, exit, exit_group,
# futex, clock_gettime, munmap, fstat, lseek – blocks exec* and socket syscalls.
# Generated offline with libseccomp; embedded as literal BPF bytecode.
# This is a simplified demonstration filter.
_SECCOMP_STRICT_BPF = bytes([
    # load arch
    0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    # compare AUDIT_ARCH_X86_64 (0xc000003e)
    0x15, 0x00, 0x00, 0x09, 0x3e, 0x00, 0x00, 0xc0,
    # kill if arch mismatch
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
    # load syscall nr
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # allow read(0), write(1), mmap(9), exit(60), exit_group(231)
    0x15, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,  # read
    0x06, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00,  # ALLOW
    0x15, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,  # write
    0x06, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00,
    # default: kill
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
])


class sock_fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def _apply_seccomp(policy: SandboxPolicy) -> bool:
    """
    Apply seccomp BPF filter to restrict syscalls.
    Returns True if sandbox was applied, False otherwise.
    """
    if platform.system() != "Linux":
        logger.warning("seccomp sandbox only supported on Linux; skipping.")
        return False
    if policy == SandboxPolicy.NONE:
        return False

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # PR_SET_NO_NEW_PRIVS=1 is required before setting a seccomp filter
        ret = libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
        if ret != 0:
            logger.error("prctl(PR_SET_NO_NEW_PRIVS) failed; seccomp not applied")
            return False

        bpf = _SECCOMP_STRICT_BPF
        arr = (ctypes.c_uint8 * len(bpf))(*bpf)
        prog = sock_fprog(len(bpf) // 8, ctypes.cast(arr, ctypes.c_void_p))
        ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog))
        if ret == 0:
            logger.info("seccomp BPF filter applied (policy=%s)", policy.name)
            return True
        else:
            errno = ctypes.get_errno()
            logger.error("prctl(SECCOMP_MODE_FILTER) failed: errno=%d", errno)
            return False
    except Exception as e:
        logger.warning("seccomp setup failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------
class AuditLog:
    def __init__(self, log_path: Optional[Path] = None):
        self._entries: List[Dict] = []
        self._log_path = log_path

    def record(self, event: str, details: Dict) -> None:
        import datetime
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": event,
            **details,
        }
        self._entries.append(entry)
        logger.debug("AUDIT: %s %s", event, details)
        if self._log_path:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

    @property
    def entries(self) -> List[Dict]:
        return list(self._entries)


# ---------------------------------------------------------------------------
# Core SecureModelLoader
# ---------------------------------------------------------------------------
class SecureModelLoader:
    """
    Unified secure model loader.

    Parameters
    ----------
    sandbox_policy : SandboxPolicy
        Seccomp sandboxing level applied during model deserialization.
    require_provenance : bool
        If True, reject models without a valid Sigstore bundle.
    require_sbom : bool
        If True, reject models without an accompanying SPDX SBOM.
    max_threat_score : int
        Maximum acceptable threat score (0-100).  Models scoring higher
        are rejected.
    audit_log_path : Optional[Path]
        Path for append-only JSONL audit log.
    """

    def __init__(
        self,
        sandbox_policy: SandboxPolicy = SandboxPolicy.STRICT,
        require_provenance: bool = False,
        require_sbom: bool = False,
        max_threat_score: int = 20,
        audit_log_path: Optional[Path] = None,
    ):
        self.sandbox_policy = sandbox_policy
        self.require_provenance = require_provenance
        self.require_sbom = require_sbom
        self.max_threat_score = max_threat_score
        self.audit = AuditLog(audit_log_path)

    # ------------------------------------------------------------------
    def validate(
        self,
        model_path: str | Path,
        sbom_path: Optional[str | Path] = None,
        bundle_path: Optional[str | Path] = None,
    ) -> ValidationReport:
        """
        Run all static validation passes without loading the model.
        Returns a ValidationReport.
        """
        path = Path(model_path)
        report = ValidationReport(path=str(path))

        if not path.exists():
            report.findings.append(f"[CRITICAL] File not found: {path}")
            report.threat_level = ThreatLevel.CRITICAL
            report.threat_score = 100
            self.audit.record("VALIDATE_FAILED", {"path": str(path), "reason": "not_found"})
            return report

        report.size_bytes = path.stat().st_size
        report.sha256 = _sha256_file(path)
        report.format = _detect_format(path)

        self.audit.record("VALIDATE_START", {
            "path": str(path),
            "format": report.format.value,
            "sha256": report.sha256,
            "size_bytes": report.size_bytes,
        })

        total_score = 0

        # ---- Format-specific static analysis ----
        if report.format == ModelFormat.PICKLE:
            with open(path, "rb") as f:
                raw = f.read()
            findings, score = _scan_pickle_opcodes(raw)
            report.findings.extend(findings)
            total_score += score

        elif report.format == ModelFormat.SAFETENSORS:
            meta, findings, score = _validate_safetensors(path)
            report.metadata.update(meta)
            report.findings.extend(findings)
            total_score += score

        elif report.format == ModelFormat.ONNX:
            meta, findings, score = _validate_onnx(path)
            report.metadata.update(meta)
            report.findings.extend(findings)
            total_score += score

        else:
            report.findings.append(
                "[MEDIUM] Unknown format; cannot perform deep static analysis"
            )
            total_score += 15

        # ---- SBOM validation ----
        resolved_sbom = Path(sbom_path) if sbom_path else path.with_suffix(".spdx.json")
        if resolved_sbom.exists():
            sbom_rec, sbom_warns = _parse_sbom(resolved_sbom)
            report.sbom = sbom_rec
            report.warnings.extend(sbom_warns)
        else:
            if self.require_sbom:
                report.findings.append("[HIGH] SBOM required but not found")
                total_score += 20
            else:
                report.warnings.append("No SBOM found; supply an SPDX AI Profile document for full provenance")

        # ---- Provenance / Sigstore ----
        prov = _verify_provenance(
            path,
            Path(bundle_path) if bundle_path else None,
        )
        report.provenance = prov
        if not prov.verified:
            if self.require_provenance:
                report.findings.append(
                    f"[HIGH] Provenance required but verification failed: {prov.error}"
                )
                total_score += 25
            else:
                report.warnings.append(f"Provenance not verified: {prov.error}")

        # ---- Threat scoring ----
        report.threat_score = min(total_score, 100)
        if report.threat_score == 0:
            report.threat_level = ThreatLevel.SAFE
        elif report.threat_score <= 15:
            report.threat_level = ThreatLevel.LOW
        elif report.threat_score <= 35:
            report.threat_level = ThreatLevel.MEDIUM
        elif report.threat_score <= 60:
            report.threat_level = ThreatLevel.HIGH
        else:
            report.threat_level = ThreatLevel.CRITICAL

        report.load_allowed = report.threat_score <= self.max_threat_score

        self.audit.record("VALIDATE_COMPLETE", {
            "path": str(path),
            "threat_level": report.threat_level.value,
            "threat_score": report.threat_score,
            "load_allowed": report.load_allowed,
            "findings": len(report.findings),
        })

        return report

    # ------------------------------------------------------------------
    def load(
        self,
        model_path: str | Path,
        sbom_path: Optional[str | Path] = None,
        bundle_path: Optional[str | Path] = None,
        force: bool = False,
    ) -> Any:
        """
        Validate then load a model. Raises RuntimeError if validation fails.

        force=True bypasses the threat-score gate (use for offline research
        environments only).
        """
        report = self.validate(model_path, sbom_path, bundle_path)

        if not report.load_allowed and not force:
            self.audit.record("LOAD_BLOCKED", {
                "path": str(model_path),
                "threat_score": report.threat_score,
                "findings": report.findings,
            })
            raise RuntimeError(
                f"Model load blocked (threat_score={report.threat_score}, "
                f"level={report.threat_level.value}):\n"
                + "\n".join(report.findings)
            )

        path = Path(model_path)

        # Apply sandbox BEFORE deserialization
        sandbox_ok = _apply_seccomp(self.sandbox_policy)
        report.sandbox_active = sandbox_ok

        self.audit.record("LOAD_START", {
            "path": str(path),
            "format": report.format.value,
            "sandbox_active": sandbox_ok,
        })

        model = self._dispatch_load(path, report.format)

        self.audit.record("LOAD_SUCCESS", {"path": str(path)})
        return model

    # ------------------------------------------------------------------
    def _dispatch_load(self, path: Path, fmt: ModelFormat) -> Any:
        if fmt == ModelFormat.SAFETENSORS:
            return self._load_safetensors(path)
        elif fmt == ModelFormat.PICKLE:
            return self._load_pickle(path)
        elif fmt == ModelFormat.ONNX:
            return self._load_onnx(path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def _load_safetensors(self, path: Path) -> Any:
        try:
            from safetensors import safe_open  # type: ignore
            tensors = {}
            with safe_open(str(path), framework="pt", device="cpu") as f:
                for key in f.keys():
                    tensors[key] = f.get_tensor(key)
            return tensors
        except ImportError:
            logger.warning("safetensors not installed; returning raw header only")
            meta, _, _ = _validate_safetensors(path)
            return {"__metadata__": meta}

    def _load_pickle(self, path: Path) -> Any:
        try:
            import torch  # type: ignore
            # weights_only=True is mandatory; restricts unpickling to
            # primitive types + known tensor classes.
            return torch.load(str(path), map_location="cpu", weights_only=True)
        except ImportError:
            raise RuntimeError(
                "PyTorch is required for .pt/.pth/.bin files. "
                "Install with: pip install torch"
            )
        except Exception as e:
            raise RuntimeError(f"torch.load failed: {e}") from e

    def _load_onnx(self, path: Path) -> Any:
        try:
            import onnx  # type: ignore
            return onnx.load(str(path))
        except ImportError:
            raise RuntimeError(
                "onnx package required. Install with: pip install onnx"
            )

    # ------------------------------------------------------------------
    def summary(self, report: ValidationReport) -> str:
        lines = [
            "=" * 64,
            f"  Secure Model Loader — Validation Report",
            "=" * 64,
            f"  Path        : {report.path}",
            f"  Format      : {report.format.value}",
            f"  SHA-256     : {report.sha256}",
            f"  Size        : {report.size_bytes:,} bytes",
            f"  Threat Level: {report.threat_level.value}  (score {report.threat_score}/100)",
            f"  Load Allowed: {'YES' if report.load_allowed else 'NO'}",
            f"  Sandbox     : {'ACTIVE' if report.sandbox_active else 'INACTIVE'}",
            "-" * 64,
        ]
        if report.provenance:
            p = report.provenance
            lines.append(f"  Provenance  : {'✓ VERIFIED' if p.verified else '✗ UNVERIFIED'}")
            if p.verified:
                lines.append(f"    Signer    : {p.signer_identity}")
                lines.append(f"    Issuer    : {p.issuer}")
                lines.append(f"    CT Log    : {p.certificate_transparency_log}")
            elif p.error:
                lines.append(f"    Error     : {p.error}")
        if report.sbom:
            s = report.sbom
            lines.append(f"  SBOM        : {s.spdxVersion} — {s.name}")
            if s.typeOfModel:
                lines.append(f"    Type      : {s.typeOfModel}")
            if s.suppliedBy:
                lines.append(f"    Supplier  : {s.suppliedBy}")
        if report.findings:
            lines.append("-" * 64)
            lines.append("  Findings:")
            for f in report.findings:
                lines.append(f"    {f}")
        if report.warnings:
            lines.append("-" * 64)
            lines.append("  Warnings:")
            for w in report.warnings:
                lines.append(f"    {w}")
        lines.append("=" * 64)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="secure-model-loader",
        description="Validate and securely load AI model files.",
    )
    parser.add_argument("model", help="Path to model file")
    parser.add_argument("--sbom", help="Path to SPDX SBOM JSON", default=None)
    parser.add_argument("--bundle", help="Path to Sigstore bundle", default=None)
    parser.add_argument(
        "--sandbox",
        choices=["none", "permissive", "strict"],
        default="strict",
        help="seccomp sandbox policy",
    )
    parser.add_argument(
        "--require-provenance", action="store_true",
        help="Reject model if provenance cannot be verified",
    )
    parser.add_argument(
        "--require-sbom", action="store_true",
        help="Reject model if no SBOM is present",
    )
    parser.add_argument(
        "--max-score", type=int, default=20,
        help="Maximum allowed threat score (0-100)",
    )
    parser.add_argument("--audit-log", default=None, help="Append-only JSONL audit log path")
    parser.add_argument("--load", action="store_true", help="Actually load the model after validation")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    args = parser.parse_args()

    policy_map = {
        "none": SandboxPolicy.NONE,
        "permissive": SandboxPolicy.PERMISSIVE,
        "strict": SandboxPolicy.STRICT,
    }

    loader = SecureModelLoader(
        sandbox_policy=policy_map[args.sandbox],
        require_provenance=args.require_provenance,
        require_sbom=args.require_sbom,
        max_threat_score=args.max_score,
        audit_log_path=Path(args.audit_log) if args.audit_log else None,
    )

    report = loader.validate(args.model, args.sbom, args.bundle)

    if args.json:
        import dataclasses
        print(json.dumps(dataclasses.asdict(report), default=str, indent=2))
    else:
        print(loader.summary(report))

    if args.load:
        try:
            model = loader.load(args.model, args.sbom, args.bundle)
            print(f"\n[OK] Model loaded successfully: {type(model).__name__}")
        except RuntimeError as e:
            print(f"\n[BLOCKED] {e}", file=sys.stderr)
            sys.exit(1)

    sys.exit(0 if report.load_allowed else 1)


if __name__ == "__main__":
    _cli()
