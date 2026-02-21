"""
Trust policy enforcement — Phase 2.

Checks trusted_publishers allowlist against the model's signer identity.
Fails closed: if require_signature=True and no valid signature, raises SecurityError.
"""

from __future__ import annotations

from typing import Optional

from secure_torch.models import ProvenanceRecord
from secure_torch.exceptions import UntrustedPublisherError, SignatureRequiredError


def enforce_publisher_policy(
    provenance: Optional[ProvenanceRecord],
    trusted_publishers: list[str],
    require_signature: bool = False,
) -> None:
    """
    Enforce trusted_publishers policy.

    Args:
        provenance: Result of signature verification.
        trusted_publishers: Allowlist of trusted publisher identities.
        require_signature: If True, raise if no valid signature.

    Raises:
        SignatureRequiredError: If require_signature=True and provenance is unverified.
        UntrustedPublisherError: If signer is not in trusted_publishers.
    """
    if not trusted_publishers:
        return

    if provenance is None or not provenance.verified:
        if require_signature:
            raise SignatureRequiredError(
                "require_signature=True but model signature could not be verified."
            )
        return

    signer = provenance.signer or ""
    if not any(pub in signer for pub in trusted_publishers):
        raise UntrustedPublisherError(
            f"Model signer '{signer}' is not in trusted_publishers: {trusted_publishers}. "
            f"Use trusted_publishers=None to disable this check."
        )
