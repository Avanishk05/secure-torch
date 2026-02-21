"""
secure-torch integration examples for LangChain, LlamaIndex, and Haystack.

These examples enforce secure-torch controls on local model artifacts.
Remote registry fetch APIs (e.g., from_pretrained/hub) are currently
compatibility passthroughs and are not security-enforced.
"""

# ── LangChain ─────────────────────────────────────────────────────────────────

from __future__ import annotations

from pathlib import Path
from typing import Any


def langchain_secure_loader(
    model_path: str,
    *,
    require_signature: bool = False,
    trusted_publishers: list[str] | None = None,
    audit_only: bool = False,
    max_threat_score: int = 20,
) -> Any:
    """
    Drop-in secure model loader for LangChain pipelines.

    Usage::

        from examples.integrations import langchain_secure_loader

        model = langchain_secure_loader(
            "models/llama-7b.safetensors",
            trusted_publishers=["huggingface.co/meta"],
            require_signature=True,
        )

    """
    import secure_torch as st

    return st.load(
        model_path,
        require_signature=require_signature,
        trusted_publishers=trusted_publishers,
        audit_only=audit_only,
        max_threat_score=max_threat_score,
    )


# ── LlamaIndex ────────────────────────────────────────────────────────────────

def llamaindex_secure_from_pretrained(
    model_name_or_path: str,
    *,
    require_signature: bool = False,
    trusted_publishers: list[str] | None = None,
    audit_only: bool = False,
    max_threat_score: int = 20,
    **kwargs: Any,
) -> Any:
    """
    Local-path secure loader helper for LlamaIndex.

    Remote registry IDs are not currently security-enforced. This helper
    requires a local artifact path and then runs secure_torch.load().

    Usage::

        from examples.integrations import llamaindex_secure_from_pretrained

        model = llamaindex_secure_from_pretrained(
            "models/all-MiniLM-L6-v2.safetensors",
            trusted_publishers=["huggingface.co/sentence-transformers"],
        )

    """
    path = Path(model_name_or_path)
    if not path.exists():
        raise ValueError(
            "Remote model IDs are not security-enforced by secure_torch. "
            "Download artifacts first and pass a local file path."
        )

    import secure_torch as st

    return st.load(
        str(path),
        require_signature=require_signature,
        trusted_publishers=trusted_publishers,
        audit_only=audit_only,
        max_threat_score=max_threat_score,
        **kwargs,
    )


# ── Haystack ──────────────────────────────────────────────────────────────────

class SecureHaystackModelLoader:
    """
    Haystack-compatible model loader with secure-torch trust enforcement for
    local model artifacts.

    Usage::

        from examples.integrations import SecureHaystackModelLoader

        loader = SecureHaystackModelLoader(
            trusted_publishers=["huggingface.co/deepset"],
            require_signature=True,
        )
        model = loader.load("models/roberta-base.pt")

    """

    def __init__(
        self,
        *,
        require_signature: bool = False,
        trusted_publishers: list[str] | None = None,
        audit_only: bool = False,
        max_threat_score: int = 20,
    ) -> None:
        self.require_signature = require_signature
        self.trusted_publishers = trusted_publishers
        self.audit_only = audit_only
        self.max_threat_score = max_threat_score

    def load(self, model_path: str, **kwargs: Any) -> Any:
        import secure_torch as st

        return st.load(
            model_path,
            require_signature=self.require_signature,
            trusted_publishers=self.trusted_publishers,
            audit_only=self.audit_only,
            max_threat_score=self.max_threat_score,
            **kwargs,
        )

    def from_pretrained(self, model_name_or_path: str, **kwargs: Any) -> Any:
        path = Path(model_name_or_path)
        if not path.exists():
            raise ValueError(
                "Remote model IDs are not security-enforced by secure_torch. "
                "Download artifacts first and pass a local file path."
            )
        return self.load(str(path), **kwargs)


# ── Gradual adoption example ──────────────────────────────────────────────────

def audit_and_report(model_path: str) -> None:
    """
    Audit a model without blocking — print a human-readable trust report.
    Useful for evaluating secure-torch before enabling enforcement.
    """
    import secure_torch as st

    model, report = st.load(model_path, audit_only=True)

    print(f"\n{'='*60}")
    print(f"  Model Trust Report: {Path(model_path).name}")
    print(f"{'='*60}")
    print(f"  Format:       {report.format.value}")
    print(f"  SHA-256:      {report.sha256[:16]}...")
    print(f"  Threat Level: {report.threat_level.name}")
    print(f"  Score:        {report.threat_score}")
    print(f"\n  Score Breakdown:")
    for key, score in report.score_breakdown.items():
        print(f"    {key:40s} +{score}")
    if report.warnings:
        print(f"\n  Warnings:")
        for w in report.warnings:
            print(f"    ⚠  {w}")
    if report.provenance:
        prov = report.provenance
        print(f"\n  Provenance:")
        print(f"    Verified: {prov.verified}")
        if prov.signer:
            print(f"    Signer:   {prov.signer}")
        if prov.error:
            print(f"    Error:    {prov.error}")
    print(f"{'='*60}\n")
