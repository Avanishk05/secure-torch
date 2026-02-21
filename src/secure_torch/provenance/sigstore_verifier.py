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

    def verify_with_sigstore(
        self,
        model_path: Path,
        bundle_path: str,
        trusted_publishers: Optional[list[str]] = None,
    ) -> ProvenanceRecord:

        try:
            from sigstore.verify import Verifier
            from sigstore.verify.policy import AnyOf, Identity
            from sigstore.models import Bundle
        except ImportError:
            return ProvenanceRecord(
                verified=False,
                error="sigstore not installed",
                mode="sigstore",
            )

        try:
            verifier = Verifier.production()

            with open(bundle_path, "rb") as f:
                bundle = Bundle.from_json(f.read())

            with open(model_path, "rb") as f:
                artifact = f.read()

            if trusted_publishers:
                policy = AnyOf([Identity(identity=pub) for pub in trusted_publishers])  # type: ignore[arg-type]
            else:
                policy = AnyOf([Identity(identity=None)])  # type: ignore[arg-type]

            result = verifier.verify_artifact(  # type: ignore
                input=artifact,  # type: ignore
                bundle=bundle,
                policy=policy,
            )

            signer: Optional[str] = getattr(result, "cert_identity", None)
            if signer is not None:
                signer = str(signer)

            return ProvenanceRecord(
                verified=True,
                signer=signer,
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

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        try:
            pubkey = serialization.load_pem_public_key(
                Path(pubkey_path).read_bytes()
            )

            signature = Path(signature_path).read_bytes()
            data = Path(model_path).read_bytes()

            if isinstance(pubkey, ed25519.Ed25519PublicKey):
                pubkey.verify(signature, data)
            elif isinstance(pubkey, rsa.RSAPublicKey):
                try:
                    pubkey.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
                except Exception:
                    pubkey.verify(
                        signature, data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pubkey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            else:
                return ProvenanceRecord(
                    verified=False,
                    bundle_path=signature_path,
                    mode="pubkey",
                    error=f"Unsupported key type: {type(pubkey).__name__}",
                )

            return ProvenanceRecord(
                verified=True,
                signer=f"pubkey:{Path(pubkey_path).name}",
                bundle_path=signature_path,
                mode="pubkey",
            )

        except Exception as e:
            return ProvenanceRecord(
                verified=False,
                bundle_path=signature_path,
                mode="pubkey",
                error=str(e),
            )