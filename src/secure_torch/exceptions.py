"""Custom exceptions for secure_torch."""

from __future__ import annotations


class SecureTorchError(Exception):
    """Base class for all secure_torch errors."""


class UnsafePickleError(SecureTorchError):
    """Raised when a dangerous pickle opcode is detected."""


class UnsafeModelError(SecureTorchError):
    """Raised when a model fails threat scoring gate."""


class SecurityError(SecureTorchError):
    """Raised when a security policy is violated."""


class SignatureRequiredError(SecurityError):
    """Raised when require_signature=True but no valid signature is found."""


class UntrustedPublisherError(SecurityError):
    """Raised when the model's signer is not in trusted_publishers."""


class SBOMError(SecureTorchError):
    """Raised when SBOM parsing or policy evaluation fails."""


class SandboxError(SecureTorchError):
    """Raised when the sandbox subprocess fails unexpectedly."""


class FormatError(SecureTorchError):
    """Raised when the model format cannot be detected or is unsupported."""
