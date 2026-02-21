"""
Sigstore provenance verifier — Phase 2.

Two verification modes:
  Mode 1: verify_with_sigstore() — keyless/online via Rekor transparency log
  Mode 2: verify_with_pubkey()   — key-based/offline, no Rekor required

Enterprise environments often block Rekor access — offline mode is essential.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from secure_torch.models import ProvenanceRecord


class SigstoreVerifier:
    """Verifies model provenance using Sigstore (online) or public key (offline)."""

    def verify_with_sigstore(
        self,
        model_path: Path,
        bundle_path: str,
        trusted_publishers: Optional[list[str]] = None,
    ) -> ProvenanceRecord:
        """
        Mode 1: Keyless online verification via Rekor transparency log.

        Verifies:
        - File hash matches bundle payload
        - Signing certificate chains to Fulcio CA
        - Entry is present in the Rekor transparency log

        Args:
            model_path: Path to model file.
            bundle_path: Path to .sigstore bundle file.
            trusted_publishers: Optional list of trusted publisher identities.

        Returns:
            ProvenanceRecord with verified=True if all checks pass.
        """
        try:
            from sigstore.verify import Verifier
            from sigstore.verify.policy import AnyOf, Identity
            from sigstore.models import Bundle
        except ImportError:
            return ProvenanceRecord(
                verified=False,
                mode="sigstore",
                error="sigstore package not installed. pip install sigstore",
            )

        try:
            bundle = Bundle.from_file(bundle_path)
            verifier = Verifier.production()

            # Build identity policy
            if trusted_publishers:
                identities = [Identity(identity=pub) for pub in trusted_publishers]
                policy = AnyOf(identities)
            else:
                # No publisher restriction — verify chain only
                policy = AnyOf([Identity(identity=None)])  # accept any valid identity

            with open(model_path, "rb") as f:
                artifact_bytes = f.read()

            result = verifier.verify_artifact(
                input=artifact_bytes,
                bundle=bundle,
                policy=policy,
            )

            return ProvenanceRecord(
                verified=True,
                signer=str(result.cert_identity) if hasattr(result, "cert_identity") else None,
                issuer=None,
                bundle_path=bundle_path,
                mode="sigstore",
            )

        except Exception as e:
            return ProvenanceRecord(
                verified=False,
                bundle_path=bundle_path,
                mode="sigstore",
                error=str(e),
            )

    def verify_with_pubkey(
        self,
        model_path: Path,
        signature_path: str,
        pubkey_path: str,
    ) -> ProvenanceRecord:
        """
        Mode 2: Offline key-based verification. No Rekor access required.

        Verifies the model file's SHA-256 hash against a detached signature
        using the provided public key (Ed25519 or RSA).

        Args:
            model_path: Path to model file.
            signature_path: Path to detached signature file (.sig).
            pubkey_path: Path to PEM-encoded public key.

        Returns:
            ProvenanceRecord with verified=True if signature is valid.
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
        except ImportError:
            return ProvenanceRecord(
                verified=False,
                mode="pubkey",
                error="cryptography package not installed. pip install cryptography",
            )

        try:
            # Load public key
            with open(pubkey_path, "rb") as f:
                pubkey = serialization.load_pem_public_key(f.read())

            # Load signature
            with open(signature_path, "rb") as f:
                signature = f.read()

            # Load model bytes
            with open(model_path, "rb") as f:
                model_bytes = f.read()

            # Verify based on key type
            if isinstance(pubkey, ed25519.Ed25519PublicKey):
                pubkey.verify(signature, model_bytes)  # Ed25519 verifies raw bytes
            elif isinstance(pubkey, rsa.RSAPublicKey):
                try:
                    pubkey.verify(
                        signature,
                        model_bytes,
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                except Exception:
                    # Support RSA-PSS signatures when upstream signers use that mode.
                    pubkey.verify(
                        signature,
                        model_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pubkey.verify(signature, model_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                return ProvenanceRecord(
                    verified=False,
                    bundle_path=signature_path,
                    mode="pubkey",
                    error=f"Unsupported public key type: {type(pubkey).__name__}",
                )

            return ProvenanceRecord(
                verified=True,
                bundle_path=signature_path,
                mode="pubkey",
                signer=f"pubkey:{Path(pubkey_path).name}",
            )

        except Exception as e:
            return ProvenanceRecord(
                verified=False,
                bundle_path=signature_path,
                mode="pubkey",
                error=str(e),
            )
