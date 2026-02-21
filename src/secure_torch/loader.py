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
from typing import Any, Optional

from secure_torch.exceptions import SecurityError, SignatureRequiredError, UnsafeModelError
from secure_torch.format_detect import detect_format
from secure_torch.models import ModelFormat, ProvenanceRecord, SBOMRecord, ValidationReport
from secure_torch.threat_score import (
    SCORE_PROVENANCE_UNVERIFIABLE,
    SCORE_SBOM_MISSING,
    SCORE_UNSIGNED_MODEL,
    ThreatScorer,
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def secure_load(
    f,
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

    Args:
        f: File path (str/Path) or file-like object.
        require_signature: Raise if no valid signature.
        trusted_publishers: Allowlist of trusted publisher identities.
        audit_only: Load anyway but return (model, ValidationReport).
        max_threat_score: Block if score exceeds this threshold.
        sandbox: Load inside restricted subprocess.
        sbom_path: SPDX SBOM JSON path (auto-detected if None).
        sbom_policy_path: Optional OPA/Rego policy path for SBOM enforcement.
        policy_context: Optional context passed to SBOM policy evaluation.
        bundle_path: Signature bundle path (auto-detected if None).
        pubkey_path: Public key path for offline verification.
        map_location: Passed to torch.load/torch.jit.load.
        weights_only: Passed to torch.load.

    Returns:
        Loaded model object, or (model, ValidationReport) if audit_only=True.
    """
    is_path = isinstance(f, (str, Path))
    path = Path(f) if is_path else None

    if is_path:
        fmt = detect_format(path)
        sha = _sha256(path)
        size = path.stat().st_size

        if bundle_path is None:
            # For offline pubkey mode we look for <model>.sig first.
            if pubkey_path:
                candidate = Path(str(path) + ".sig")
                bundle_path = str(candidate) if candidate.exists() else None
            if bundle_path is None:
                candidate = Path(str(path) + ".sigstore")
                bundle_path = str(candidate) if candidate.exists() else None

        if sbom_path is None:
            candidate = Path(str(path) + ".spdx.json")
            sbom_path = str(candidate) if candidate.exists() else None
    else:
        fmt = ModelFormat.PICKLE
        sha = "unknown"
        size = 0

    scorer = ThreatScorer()

    provenance: Optional[ProvenanceRecord] = None
    if is_path:
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

    load_allowed = not scorer.is_blocked(max_threat_score)
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
            f"Breakdown: {scorer.breakdown}\n"
            f"Use audit_only=True to load anyway and inspect the report."
        )

    if sandbox and is_path:
        model = _sandbox_load(path, fmt, map_location=map_location, weights_only=weights_only)
    else:
        model = _direct_load(
            f,
            fmt,
            map_location=map_location,
            weights_only=weights_only,
            _jit_mode=_jit_mode,
            **kwargs,
        )

    if audit_only:
        return model, report
    return model


def _verify_signature(
    path: Path,
    bundle_path: Optional[str],
    pubkey_path: Optional[str],
    require_signature: bool,
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
) -> Optional[ProvenanceRecord]:
    """Run signature verification. Returns ProvenanceRecord or None."""
    from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

    verifier = SigstoreVerifier()

    if bundle_path and Path(bundle_path).exists():
        provenance: ProvenanceRecord
        if pubkey_path:
            provenance = verifier.verify_with_pubkey(path, bundle_path, pubkey_path)
        else:
            provenance = verifier.verify_with_sigstore(path, bundle_path, trusted_publishers)

        if require_signature and not provenance.verified:
            detail = provenance.error or "signature verification failed"
            raise SignatureRequiredError(
                f"require_signature=True but signature verification failed for '{path}': {detail}"
            )

        if not provenance.verified:
            scorer.add("provenance_unverifiable", SCORE_PROVENANCE_UNVERIFIABLE, finding=False)
            scorer.warn(f"Signature verification failed: {provenance.error or 'unknown error'}")

        return provenance

    if require_signature:
        expected = str(path) + (".sig" if pubkey_path else ".sigstore")
        raise SignatureRequiredError(
            f"require_signature=True but no signature bundle found for '{path}'. "
            f"Expected: {expected}"
        )

    scorer.add("unsigned_model", SCORE_UNSIGNED_MODEL, finding=False)
    scorer.warn("No signature bundle found - model is unsigned")
    return ProvenanceRecord(verified=False, error="No bundle found")


def _run_validators(f, fmt: ModelFormat, scorer: ThreatScorer, path: Optional[Path]) -> None:
    """Dispatch to format-specific validators."""
    if fmt == ModelFormat.PICKLE:
        from secure_torch.formats.pickle_safe import validate_pickle

        if path:
            with open(path, "rb") as fh:
                target = fh.read()
        elif hasattr(f, "read"):
            position = f.tell() if hasattr(f, "tell") else None
            target = f.read()
            if position is not None and hasattr(f, "seek"):
                f.seek(position)
        else:
            target = b""
        validate_pickle(target, scorer)

    elif fmt == ModelFormat.SAFETENSORS:
        from secure_torch.formats.safetensors import validate_safetensors

        if path:
            validate_safetensors(path, scorer)

    elif fmt == ModelFormat.ONNX:
        from secure_torch.formats.onnx_loader import validate_onnx

        if path:
            validate_onnx(path, scorer)


def _evaluate_sbom_policy(
    sbom_path: Optional[str],
    sbom_policy_path: Optional[str],
    policy_context: Optional[dict[str, Any]],
    scorer: ThreatScorer,
    audit_only: bool,
) -> Optional[SBOMRecord]:
    """Parse and optionally enforce SBOM policy."""
    if sbom_path is None:
        if sbom_policy_path:
            scorer.add("sbom_missing", SCORE_SBOM_MISSING, finding=False)
            scorer.warn("SBOM policy was provided but no SBOM file was found")
        return None

    from secure_torch.sbom.spdx_parser import parse_sbom

    sbom = parse_sbom(sbom_path)
    if sbom is None:
        scorer.add("sbom_parse_failed", SCORE_SBOM_MISSING, finding=False)
        scorer.warn(f"SBOM parsing failed for '{sbom_path}'")
        return None

    if not sbom_policy_path:
        return sbom

    from secure_torch.sbom.opa_runner import OPAPolicyRunner

    denials = OPAPolicyRunner(sbom_policy_path).evaluate(sbom, context=policy_context or {})
    if not denials:
        return sbom

    if not audit_only:
        raise SecurityError(f"SBOM policy denied model load: {'; '.join(denials)}")

    for idx, message in enumerate(denials, start=1):
        scorer.add(f"sbom_policy_denial_{idx}", 30)
        scorer.warn(f"SBOM policy denial: {message}")
    return sbom


def _enforce_policy(
    provenance: Optional[ProvenanceRecord],
    trusted_publishers: Optional[list[str]],
    scorer: ThreatScorer,
    audit_only: bool,
) -> None:
    """Check trusted_publishers policy."""
    if not trusted_publishers:
        return

    if provenance and provenance.verified and provenance.signer:
        signer = provenance.signer
        if not any(pub in signer for pub in trusted_publishers):
            from secure_torch.exceptions import UntrustedPublisherError

            if not audit_only:
                raise UntrustedPublisherError(
                    f"Signer '{signer}' is not in trusted_publishers: {trusted_publishers}"
                )
            scorer.add("untrusted_publisher", 20)
    else:
        scorer.add("unknown_publisher", 20)


def _direct_load(
    f,
    fmt: ModelFormat,
    map_location=None,
    weights_only: bool = True,
    _jit_mode: bool = False,
    **kwargs,
) -> Any:
    """Load model using the appropriate backend."""
    if fmt == ModelFormat.SAFETENSORS:
        try:
            import safetensors.torch as st

            return st.load_file(str(f) if isinstance(f, Path) else f)
        except ImportError:
            raise ImportError("safetensors required. pip install safetensors")

    if fmt == ModelFormat.PICKLE:
        try:
            import torch

            if _jit_mode:
                return torch.jit.load(f, map_location=map_location, **kwargs)
            return torch.load(
                f,
                map_location=map_location,
                weights_only=weights_only,
                **kwargs,
            )
        except ImportError:
            raise ImportError("torch required for .pt/.pth/.bin files. pip install torch")

    if fmt == ModelFormat.ONNX:
        try:
            import onnx

            return onnx.load(str(f) if isinstance(f, Path) else f)
        except ImportError:
            raise ImportError("onnx required. pip install onnx")

    raise ValueError(f"Unsupported format: {fmt}")


def _sandbox_load(path: Path, fmt: ModelFormat, map_location=None, weights_only: bool = True) -> Any:
    """Load model inside a restricted subprocess."""
    from secure_torch.sandbox.subprocess_sandbox import SubprocessSandbox

    sandbox = SubprocessSandbox()
    return sandbox.load(path, fmt, map_location=map_location, weights_only=weights_only)


def secure_save(obj, f, **kwargs) -> None:
    """Pass-through to torch.save."""
    try:
        import torch

        torch.save(obj, f, **kwargs)
    except ImportError:
        raise ImportError("torch required for save(). pip install torch")
