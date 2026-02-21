"""
Integration tests — Phase 2: Signature Verification.

Tests both verification modes:
  Mode 1: verify_with_sigstore() — online/Rekor (mocked for CI)
  Mode 2: verify_with_pubkey()   — offline/key-based (fully testable without network)

Offline mode is fully tested with real Ed25519 key generation.
Online mode is tested with a mock to avoid Rekor network dependency in CI.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_temp_model(content: bytes = b"fake model weights") -> Path:
    """Write a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def generate_ed25519_keypair():
    """Generate a real Ed25519 keypair for offline verification tests."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, priv_pem, pub_pem


def sign_file_ed25519(private_key, file_path: Path) -> bytes:
    """Sign a file with Ed25519 private key. Returns raw signature bytes."""
    with open(file_path, "rb") as f:
        data = f.read()
    return private_key.sign(data)


def generate_rsa_keypair():
    """Generate an RSA keypair for offline verification tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, pub_pem


def sign_file_rsa(private_key, file_path: Path) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(file_path, "rb") as f:
        data = f.read()
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def generate_ecdsa_keypair():
    """Generate an ECDSA keypair for offline verification tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, pub_pem


def sign_file_ecdsa(private_key, file_path: Path) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    with open(file_path, "rb") as f:
        data = f.read()
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


# ── Offline pubkey verification tests (Mode 2) ────────────────────────────────


class TestOfflinePubkeyVerification:
    """
    Fully offline tests — no network required.
    Uses real Ed25519 key generation and signing.
    """

    def test_valid_signature_verifies(self):
        """A correctly signed model must verify successfully."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        private_key, priv_pem, pub_pem = generate_ed25519_keypair()
        model_path = make_temp_model(b"safe model weights v1")

        # Write public key and signature to temp files
        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        sig_bytes = sign_file_ed25519(private_key, model_path)
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(sig_bytes)
            sig_path = sf.name

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(model_path, sig_path, pubkey_path)

            assert result.verified is True, f"Expected verified=True, got error: {result.error}"
            assert result.mode == "pubkey"
            assert result.signer is not None
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)

    def test_tampered_model_fails_verification(self):
        """A model tampered after signing must fail verification."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        private_key, priv_pem, pub_pem = generate_ed25519_keypair()
        model_path = make_temp_model(b"original model weights")

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        sig_bytes = sign_file_ed25519(private_key, model_path)
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(sig_bytes)
            sig_path = sf.name

        # Tamper with the model after signing
        with open(model_path, "ab") as f:
            f.write(b"\x00\x00\x00TAMPERED")

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(model_path, sig_path, pubkey_path)

            assert result.verified is False, "Tampered model must NOT verify"
            assert result.error is not None
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)

    def test_wrong_key_fails_verification(self):
        """Signature from a different key must fail verification."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        private_key_1, _, _ = generate_ed25519_keypair()
        _, _, pub_pem_2 = generate_ed25519_keypair()  # different key

        model_path = make_temp_model(b"model weights")

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem_2)  # wrong public key
            pubkey_path = pf.name

        sig_bytes = sign_file_ed25519(private_key_1, model_path)
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(sig_bytes)
            sig_path = sf.name

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(model_path, sig_path, pubkey_path)
            assert result.verified is False, "Wrong key must NOT verify"
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)

    def test_missing_signature_file_returns_unverified(self):
        """Missing signature file must return unverified, not raise."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        _, _, pub_pem = generate_ed25519_keypair()
        model_path = make_temp_model(b"model weights")

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(
                model_path,
                "/nonexistent/path/model.sig",
                pubkey_path,
            )
            assert result.verified is False
            assert result.error is not None
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)

    def test_valid_rsa_signature_verifies(self):
        """RSA signatures must verify with the matching public key."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        private_key, pub_pem = generate_rsa_keypair()
        model_path = make_temp_model(b"rsa model weights")

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        sig_bytes = sign_file_rsa(private_key, model_path)
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(sig_bytes)
            sig_path = sf.name

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(model_path, sig_path, pubkey_path)
            assert result.verified is True, (
                f"Expected RSA verification success, got: {result.error}"
            )
            assert result.mode == "pubkey"
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)

    def test_valid_ecdsa_signature_verifies(self):
        """ECDSA signatures must verify with the matching public key."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        private_key, pub_pem = generate_ecdsa_keypair()
        model_path = make_temp_model(b"ecdsa model weights")

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        sig_bytes = sign_file_ecdsa(private_key, model_path)
        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
            sf.write(sig_bytes)
            sig_path = sf.name

        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_pubkey(model_path, sig_path, pubkey_path)
            assert result.verified is True, (
                f"Expected ECDSA verification success, got: {result.error}"
            )
            assert result.mode == "pubkey"
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)


# ── Online Sigstore verification tests (Mode 1) ───────────────────────────────


class TestOnlineSigstoreVerification:
    """
    Online Sigstore tests — mocked to avoid Rekor network dependency in CI.
    Real Rekor integration is tested manually / in nightly CI.
    """

    def test_no_bundle_returns_unverified(self):
        """Missing bundle file must return unverified ProvenanceRecord."""
        from secure_torch.provenance.sigstore_verifier import SigstoreVerifier

        model_path = make_temp_model(b"model weights")
        try:
            verifier = SigstoreVerifier()
            result = verifier.verify_with_sigstore(
                model_path,
                "/nonexistent/model.sigstore",
                trusted_publishers=None,
            )
            assert result.verified is False
            assert result.mode == "sigstore"
            assert result.error is not None
        finally:
            os.unlink(model_path)

    def test_sigstore_not_installed_returns_unverified(self, monkeypatch):
        """If sigstore package is not installed, must return unverified gracefully."""
        from secure_torch.provenance import sigstore_verifier
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name.startswith("sigstore"):
                raise ImportError("sigstore not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        model_path = make_temp_model(b"model weights")
        bundle_path = model_path.with_suffix(".sigstore")
        bundle_path.write_bytes(b"{}")  # fake bundle

        try:
            verifier = sigstore_verifier.SigstoreVerifier()
            result = verifier.verify_with_sigstore(model_path, str(bundle_path))
            assert result.verified is False
            assert "not installed" in (result.error or "")
        finally:
            os.unlink(model_path)
            if bundle_path.exists():
                os.unlink(bundle_path)


# ── require_signature pipeline integration ────────────────────────────────────


class TestRequireSignaturePipeline:
    def test_require_signature_with_valid_offline_sig_passes(self):
        """
        Full pipeline: require_signature=True with a valid offline pubkey sig
        must load successfully.
        """
        import json
        import struct
        import secure_torch as st

        private_key, _, pub_pem = generate_ed25519_keypair()

        # Build a minimal safetensors file
        header = {"__metadata__": {"model": "test"}}
        header_bytes = json.dumps(header).encode("utf-8")
        content = struct.pack("<Q", len(header_bytes)) + header_bytes

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            model_path = Path(f.name)

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        sig_bytes = sign_file_ed25519(private_key, model_path)
        sig_path = str(model_path) + ".sig"
        with open(sig_path, "wb") as sf:
            sf.write(sig_bytes)

        try:
            model = st.load(
                str(model_path),
                require_signature=True,
                pubkey_path=pubkey_path,
                bundle_path=sig_path,
            )
            assert model is not None
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)

    def test_require_signature_with_invalid_signature_fails_closed(self):
        """require_signature=True must fail when verification returns unverified."""
        import json
        import struct
        import secure_torch as st
        from secure_torch.exceptions import SignatureRequiredError

        private_key, _, pub_pem = generate_ed25519_keypair()
        wrong_private_key, _, _ = generate_ed25519_keypair()

        header = {"__metadata__": {"model": "test"}}
        header_bytes = json.dumps(header).encode("utf-8")
        content = struct.pack("<Q", len(header_bytes)) + header_bytes

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(content)
            model_path = Path(f.name)

        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as pf:
            pf.write(pub_pem)
            pubkey_path = pf.name

        # Sign with a different key so verification must fail.
        sig_bytes = sign_file_ed25519(wrong_private_key, model_path)
        sig_path = str(model_path) + ".sig"
        with open(sig_path, "wb") as sf:
            sf.write(sig_bytes)

        try:
            try:
                st.load(
                    str(model_path),
                    require_signature=True,
                    pubkey_path=pubkey_path,
                    bundle_path=sig_path,
                )
                assert False, "Expected SignatureRequiredError"
            except SignatureRequiredError:
                pass
        finally:
            os.unlink(model_path)
            os.unlink(pubkey_path)
            os.unlink(sig_path)
