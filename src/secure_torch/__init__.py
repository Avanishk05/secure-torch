"""
secure_torch - Model Trust Gateway.

Usage:
    import secure_torch as torch
    model = torch.load("model.pt")
"""

from __future__ import annotations

from secure_torch.exceptions import (
    SecurityError,
    SignatureRequiredError,
    UnsafeModelError,
    UnsafePickleError,
    UntrustedPublisherError,
)
from secure_torch.loader import secure_load, secure_save
from secure_torch.models import ModelFormat, ThreatLevel, ValidationReport


def _raise_remote_security_not_supported(surface: str, **security_args) -> None:
    active = [name for name, value in security_args.items() if value]
    if not active:
        return
    raise SecurityError(
        f"secure_torch.{surface} does not currently enforce security controls for remote fetches. "
        f"Unsupported security args: {', '.join(active)}. "
        f"Download artifacts first, then use secure_torch.load() on local files."
    )


def load(
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
):
    """Drop-in replacement for torch.load() with trust enforcement."""
    return secure_load(
        f,
        require_signature=require_signature,
        trusted_publishers=trusted_publishers,
        audit_only=audit_only,
        max_threat_score=max_threat_score,
        sandbox=sandbox,
        sbom_path=sbom_path,
        sbom_policy_path=sbom_policy_path,
        policy_context=policy_context,
        bundle_path=bundle_path,
        pubkey_path=pubkey_path,
        map_location=map_location,
        weights_only=weights_only,
        **kwargs,
    )


def save(obj, f, **kwargs):
    """Pass-through to torch.save."""
    return secure_save(obj, f, **kwargs)


class _JitModule:
    """Namespace for torch.jit.load drop-in."""

    def load(self, f, *, require_signature: bool = False, **kwargs):
        return secure_load(
            f,
            require_signature=require_signature,
            _jit_mode=True,
            **kwargs,
        )


jit = _JitModule()


class _HubModule:
    """Namespace for torch.hub.load drop-in."""

    def load(
        self,
        repo_or_dir,
        model,
        *args,
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
        **kwargs,
    ):
        _raise_remote_security_not_supported(
            "hub.load",
            require_signature=require_signature,
            trusted_publishers=trusted_publishers,
            audit_only=audit_only,
            max_threat_score=max_threat_score != 20,
            sandbox=sandbox,
            sbom_path=sbom_path,
            sbom_policy_path=sbom_policy_path,
            bundle_path=bundle_path,
            pubkey_path=pubkey_path,
            policy_context=policy_context,
        )
        try:
            import torch

            return torch.hub.load(repo_or_dir, model, *args, **kwargs)
        except ImportError:
            raise ImportError("torch is required for hub.load(). pip install torch")


hub = _HubModule()


def from_pretrained(
    model_name_or_path: str,
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
    **kwargs,
):
    """
    HuggingFace-style from_pretrained.

    Remote registry loading does not currently support secure_torch security checks.
    """
    _raise_remote_security_not_supported(
        "from_pretrained",
        require_signature=require_signature,
        trusted_publishers=trusted_publishers,
        audit_only=audit_only,
        max_threat_score=max_threat_score != 20,
        sandbox=sandbox,
        sbom_path=sbom_path,
        sbom_policy_path=sbom_policy_path,
        policy_context=policy_context,
        bundle_path=bundle_path,
        pubkey_path=pubkey_path,
    )
    try:
        from transformers import AutoModel

        return AutoModel.from_pretrained(model_name_or_path, **kwargs)
    except ImportError:
        raise ImportError("transformers is required for from_pretrained(). pip install transformers")


__all__ = [
    "load",
    "save",
    "jit",
    "hub",
    "from_pretrained",
    "ValidationReport",
    "ThreatLevel",
    "ModelFormat",
    "UnsafePickleError",
    "SecurityError",
    "SignatureRequiredError",
    "UntrustedPublisherError",
    "UnsafeModelError",
]
