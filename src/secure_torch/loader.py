"""
Central loader pipeline.

Fixed pipeline order:
  1. Format detection
  2. Signature verification
  3. Threat scoring
  4. Policy enforcement
  5. Sandbox load
  6. Return model
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Optional, Union, IO

from secure_torch.exceptions import SecurityError, SignatureRequiredError, UnsafeModelError
from secure_torch.format_detect import detect_format
from secure_torch.models import ModelFormat, ProvenanceRecord, SBOMRecord, ValidationReport
from secure_torch.threat_score import (
    SCORE_PROVENANCE_UNVERIFIABLE,
    SCORE_SBOM_MISSING,
    SCORE_UNSIGNED_MODEL,
    ThreatScorer,
)

PathLike = Union[str, Path]


def _sha256(path: Path) -> str:
    """Compute SHA256 hash of file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def secure_load(
    f: Union[PathLike, IO[bytes]],
    *,
    require_signature: bool = False,
    trusted_publishers: Optional[list[str]] = None,
    audit_only: bool = False,
    max_threat_score: int = 20,
    sandbox: bool = False,
    sbom_path: Optional[str] = None,
    sbom_policy_path: Optional[str] = None,
    policy_context: Optional[dict[str, Any]] = None,
    bundle_path: Optional[str] = None,
    pubkey_path: Optional[str] = None,
    map_location=None,
    weights_only: bool = True,
    _jit_mode: bool = False,
    **kwargs,
) -> Any:
    """
    Unified secure model loader.
    """

    # Explicit typing for MyPy safety
    path: Optional[Path] = Path(f) if isinstance(f, (str, Path)) else None

    if path is not None:
        _path: Path = path  # narrowed, non-Optional for use below
        fmt: ModelFormat = detect_format(_path)
        sha: str = _sha256(_path)
        size: int = _path.stat().st_size

        # Signature bundle auto-detect
        if bundle_path is None:
            if pubkey_path:
                candidate = Path(str(_path) + ".sig")
                if candidate.exists():
                    bundle_path = str(candidate)

            if bundle_path is None:
                candidate = Path(str(_path) + ".sigstore")
                if candidate.exists():
                    bundle_path = str(candidate)

        # SBOM auto-detect
        if sbom_path is None:
            candidate = Path(str(_path) + ".spdx.json")
            if candidate.exists():
                sbom_path = str(candidate)

    else:
        fmt = ModelFormat.PICKLE
        sha = "unknown"
        size = 0

    scorer = ThreatScorer()

    provenance: Optional[ProvenanceRecord] = None

    if path is not None:
        provenance = _verify_signature(
            path=path,
            bundle_path=bundle_path,
            pubkey_path=pubkey_path,
            require_signature=require_signature,
            trusted_publishers=trusted_publishers,
            scorer=scorer,
        )

    _run_validators(f, fmt, scorer, path=path)

    sbom = _evaluate_sbom_policy(
        sbom_path=sbom_path,
        sbom_policy_path=sbom_policy_path,
        policy_context=policy_context,
        scorer=scorer,
        audit_only=audit_only,
    )

    _enforce_policy(
        provenance=provenance,
        trusted_publishers=trusted_publishers,
        scorer=scorer,
        audit_only=audit_only,
    )

    load_allowed: bool = not scorer.is_blocked(max_threat_score)

    report = ValidationReport(
        path=str(f),
        format=fmt,
        threat_level=scorer.threat_level,
        threat_score=scorer.total,
        score_breakdown=scorer.breakdown,
        findings=scorer.findings,
        warnings=scorer.warnings,
        sha256=sha,
        size_bytes=size,
        load_allowed=load_allowed or audit_only,
        sandbox_active=sandbox,
        provenance=provenance,
        sbom=sbom,
    )

    if not load_allowed and not audit_only:
        raise UnsafeModelError(
            f"Model blocked: threat score {scorer.total} > max {max_threat_score}.\n"
            f"Breakdown: {scorer.breakdown}"
        )

    # Safe sandbox invocation
    if sandbox and path is not None:
        _path = path  # narrowed for mypy
        model = _sandbox_load(
            _path,
            fmt,
            map_location=map_location,
            weights_only=weights_only,
        )
    else:
        model = _direct_load(
            f,
            fmt,
            map_location=map_location,
            weights_only=weights_only,
            _jit_mode=_jit_mode,
            **kwargs,
        )

    return (model, report) if audit_only else model


def _verify_signature(
    path: Path,
    bundle_path: Optional[str],
    pubkey_path: Optional[str],
    require_signature: bool,
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
) -> Optional[ProvenanceRecord]:

    from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

    verifier = SigstoreVerifier()

    if bundle_path and Path(bundle_path).exists():

        if pubkey_path:
            provenance = verifier.verify_with_pubkey(path, bundle_path, pubkey_path)
        else:
            provenance = verifier.verify_with_sigstore(
                path, bundle_path, trusted_publishers
            )

        if require_signature and not provenance.verified:
            raise SignatureRequiredError("Signature verification failed")

        if not provenance.verified:
            scorer.add("provenance_unverifiable", SCORE_PROVENANCE_UNVERIFIABLE)
            scorer.warn("Signature verification failed")

        return provenance

    if require_signature:
        raise SignatureRequiredError("Missing signature")

    scorer.add("unsigned_model", SCORE_UNSIGNED_MODEL)
    scorer.warn("Model is unsigned")

    return ProvenanceRecord(verified=False, error="Missing signature")


def _run_validators(
    f: Union[PathLike, IO[bytes]],
    fmt: ModelFormat,
    scorer: ThreatScorer,
    path: Optional[Path],
) -> None:

    if fmt == ModelFormat.PICKLE:
        from secure_torch.formats.pickle_safe import validate_pickle

        if path is not None:
            validate_pickle(path.read_bytes(), scorer)

    elif fmt == ModelFormat.SAFETENSORS:
        from secure_torch.formats.safetensors import validate_safetensors

        if path is not None:
            validate_safetensors(path, scorer)

    elif fmt == ModelFormat.ONNX:
        from secure_torch.formats.onnx_loader import validate_onnx

        if path is not None:
            validate_onnx(path, scorer)


def _evaluate_sbom_policy(
    sbom_path: Optional[str],
    sbom_policy_path: Optional[str],
    policy_context: Optional[dict[str, Any]],
    scorer: ThreatScorer,
    audit_only: bool,
) -> Optional[SBOMRecord]:

    if sbom_path is None:
        return None

    from secure_torch.sbom.spdx_parser import parse_sbom

    sbom = parse_sbom(sbom_path)

    if sbom is None:
        scorer.add("sbom_missing", SCORE_SBOM_MISSING)
        return None

    if not sbom_policy_path:
        return sbom

    from secure_torch.sbom.opa_runner import OPAPolicyRunner

    denials = OPAPolicyRunner(sbom_policy_path).evaluate(
        sbom,
        context=policy_context or {},
    )

    for i, denial in enumerate(denials):
        scorer.add(f"sbom_policy_denial:{i}", 30)
        scorer.warn(denial)

    if denials and not audit_only:
        raise SecurityError("SBOM policy denied model")

    return sbom


def _enforce_policy(
    provenance: Optional[ProvenanceRecord],
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
    audit_only: bool,
) -> None:

    if not trusted_publishers:
        return

    if provenance and provenance.signer:
        if not any(pub in provenance.signer for pub in trusted_publishers):
            scorer.add("untrusted_publisher", 20)


def _direct_load(
    f: Union[PathLike, IO[bytes]],
    fmt: ModelFormat,
    map_location=None,
    weights_only: bool = True,
    _jit_mode: bool = False,
    **kwargs,
) -> Any:

    if fmt == ModelFormat.SAFETENSORS:
        import safetensors.torch as st

        return st.load_file(str(f))

    if fmt == ModelFormat.PICKLE:
        import torch

        if _jit_mode:
            return torch.jit.load(f, map_location=map_location)

        return torch.load(
            f,
            map_location=map_location,
            weights_only=weights_only,
        )

    if fmt == ModelFormat.ONNX:
        import onnx

        return onnx.load(str(f))

    raise ValueError("Unsupported format")


def _sandbox_load(
    path: Path,
    fmt: ModelFormat,
    map_location=None,
    weights_only: bool = True,
) -> Any:

    from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox

    sandbox = SubprocessSandbox()

    return sandbox.load(
        path,
        fmt,
        map_location=map_location,
        weights_only=weights_only,
    )


def secure_save(obj: Any, f: PathLike, **kwargs) -> None:

    import torch

    torch.save(obj, f, **kwargs)