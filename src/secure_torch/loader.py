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

import logging
from pathlib import Path
from typing import Any, Optional, Union, IO

from secure_torch.exceptions import SecurityError, SignatureRequiredError, UnsafeModelError
from secure_torch.format_detect import detect_format
from secure_torch.models import ModelFormat, ProvenanceRecord, SBOMRecord, ValidationReport
from secure_torch.threat_score import (
    SCORE_PROVENANCE_UNVERIFIABLE,
    SCORE_SBOM_MISSING,
    SCORE_SBOM_POLICY_DENIAL,
    SCORE_UNSIGNED_MODEL,
    SCORE_UNTRUSTED_PUBLISHER,
    ThreatScorer,
)

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def scan_file(
    path: Union[str, Path],
    *,
    require_signature: bool = False,
    trusted_publishers: Optional[list[str]] = None,
    max_threat_score: int = 20,
    sbom_path: Optional[str] = None,
    sbom_policy_path: Optional[str] = None,
    policy_context: Optional[dict[str, Any]] = None,
    bundle_path: Optional[str] = None,
    pubkey_path: Optional[str] = None,
) -> ValidationReport:
    """Validate a model file without loading it into memory.

    Runs the full security pipeline (format detection, signature verification,
    threat scoring, policy enforcement) and returns a ``ValidationReport``.
    The model is never loaded — safe for untrusted files.
    """
    result = secure_load(
        path,
        require_signature=require_signature,
        trusted_publishers=trusted_publishers,
        audit_only=True,
        max_threat_score=max_threat_score,
        sandbox=False,
        sbom_path=sbom_path,
        sbom_policy_path=sbom_policy_path,
        policy_context=policy_context,
        bundle_path=bundle_path,
        pubkey_path=pubkey_path,
        skip_load=True,
    )
    # secure_load returns (model, report) when audit_only=True or skip_load=True
    _, report = result
    return report


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
    skip_load: bool = False,
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
        fmt = detect_format(f)
        size = 0

    scorer = ThreatScorer()

    provenance: Optional[ProvenanceRecord] = None

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
        require_signature=require_signature,
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
        size_bytes=size,
        load_allowed=load_allowed or audit_only,
        sandbox_active=sandbox,
        provenance=provenance,
        sbom=sbom,
    )

    if not load_allowed and not audit_only:
        import json

        logger.error(
            json.dumps(
                {
                    "event": "model_blocked",
                    "path": str(f),
                    "format": fmt.value if hasattr(fmt, "value") else str(fmt),
                    "threat_score": scorer.total,
                    "findings": scorer.findings,
                }
            )
        )
        raise UnsafeModelError(
            f"Model blocked: threat score {scorer.total} > max {max_threat_score}.\n"
            f"Breakdown: {scorer.breakdown}"
        )

    # Safe sandbox invocation
    if skip_load:
        model = None
    elif sandbox and path is not None:
        _path = path  # narrowed for mypy
        model = _sandbox_load(
            _path,
            fmt,
            map_location=map_location,
            weights_only=weights_only,
            **kwargs,
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

    return (model, report) if (audit_only or skip_load) else model


def _verify_signature(
    path: Optional[Path],
    bundle_path: Optional[str],
    pubkey_path: Optional[str],
    require_signature: bool,
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
) -> Optional[ProvenanceRecord]:
    if path is None:
        if require_signature:
            raise SignatureRequiredError(
                "Missing signature (file-like object cannot have external signature bundle)"
            )

        scorer.add("unsigned_model", SCORE_UNSIGNED_MODEL)
        scorer.warn("Model is unsigned (loaded from file-like object)")
        return ProvenanceRecord(verified=False, error="Missing signature")

    from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

    verifier = SigstoreVerifier()

    if bundle_path and Path(bundle_path).exists():
        if pubkey_path:
            provenance = verifier.verify_with_pubkey(path, bundle_path, pubkey_path)
        else:
            provenance = verifier.verify_with_sigstore(path, bundle_path, trusted_publishers)

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
        else:
            if hasattr(f, "read"):
                current_pos = f.tell() if hasattr(f, "tell") else 0
                if hasattr(f, "seek"):
                    f.seek(0)
                data = f.read()
                if hasattr(f, "seek"):
                    f.seek(current_pos)
                validate_pickle(data, scorer)

    elif fmt == ModelFormat.SAFETENSORS:
        from secure_torch.formats.safetensors import validate_safetensors

        if path is not None:
            validate_safetensors(path, scorer)
        else:
            scorer.warn("Safetensors validation for file-like objects is not fully supported")

    elif fmt == ModelFormat.ONNX:
        from secure_torch.formats.onnx_loader import validate_onnx

        if path is not None:
            validate_onnx(path, scorer)
        else:
            scorer.warn("ONNX validation for file-like objects is not fully supported")


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
        scorer.add(f"sbom_policy_denial:{i}", SCORE_SBOM_POLICY_DENIAL)
        scorer.warn(denial)

    if denials and not audit_only:
        raise SecurityError("SBOM policy denied model")

    return sbom


def _enforce_policy(
    provenance: Optional[ProvenanceRecord],
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
    audit_only: bool,
    require_signature: bool = False,
) -> None:

    if not trusted_publishers:
        return

    if provenance and provenance.signer:
        from secure_torch.policy.trust_policy import _publisher_matches

        if not any(_publisher_matches(provenance.signer, pub) for pub in trusted_publishers):
            scorer.add("untrusted_publisher", SCORE_UNTRUSTED_PUBLISHER)

    if not audit_only:
        from secure_torch.policy.trust_policy import enforce_publisher_policy

        enforce_publisher_policy(provenance, trusted_publishers, require_signature)


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
            return torch.jit.load(f, map_location=map_location, **kwargs)

        return torch.load(  # nosec B614 -- weights_only= is set; secure_torch has already validated opcodes
            f,
            map_location=map_location,
            weights_only=weights_only,
            **kwargs,
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
    **kwargs,
) -> Any:

    from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox

    sandbox = SubprocessSandbox()

    return sandbox.load(
        path,
        fmt,
        map_location=map_location,
        weights_only=weights_only,
        **kwargs,
    )


def secure_save(obj: Any, f: PathLike, **kwargs) -> None:

    import torch

    torch.save(obj, f, **kwargs)
