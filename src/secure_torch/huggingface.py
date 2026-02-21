"""
Hugging Face integration for secure_torch.

This module provides `patch_huggingface`, which monkeys-patches
`huggingface_hub` to ensure all downloaded model files are scanned
by `secure_torch` before they are loaded by `transformers` or other
downstream libraries.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

_ORIGINAL_HF_HUB_DOWNLOAD: Callable | None = None
_PATCHED = False

# Known extensions for model weights
_MODEL_EXTENSIONS = {".pt", ".pth", ".bin", ".safetensors", ".onnx", ".h5", ".keras"}


def _is_model_file(filename: str) -> bool:
    """Check if the filename looks like a model file."""
    # Sometimes it's a URL or a complicated path. We just look at the end.
    lower_name = filename.lower()
    return any(lower_name.endswith(ext) for ext in _MODEL_EXTENSIONS)


def patch_huggingface(**security_kwargs: Any) -> None:
    """
    Monkey-patch Hugging Face Hub to automatically scan downloaded models.
    
    When `huggingface_hub.hf_hub_download` (which is used internally by
    `transformers.PreTrainedModel.from_pretrained`) downloads a file,
    this patch will intercept the cached file path. If it's a model file,
    it runs `secure_torch.load(..., audit_only=True/False, **security_kwargs)`
    to validate it before returning control to the caller.
    
    Args:
        security_kwargs: Security parameters passed to `secure_torch.load`.
            e.g., `max_threat_score`, `trusted_publishers`, `require_signature`.
    """
    global _ORIGINAL_HF_HUB_DOWNLOAD, _PATCHED
    
    if _PATCHED:
        logger.warning("secure_torch.patch_huggingface() called multiple times. Ignored.")
        return

    try:
        import huggingface_hub.file_download
    except ImportError:
        logger.warning(
            "huggingface_hub is not installed. "
            "secure_torch.patch_huggingface() has no effect."
        )
        return

    _ORIGINAL_HF_HUB_DOWNLOAD = huggingface_hub.file_download.hf_hub_download

    def patched_hf_hub_download(*args, **kwargs) -> str:
        # Call the original download function first
        file_path = _ORIGINAL_HF_HUB_DOWNLOAD(*args, **kwargs)
        
        # Check if we should scan are turning a file path
        if file_path and isinstance(file_path, (str, Path)):
            str_path = str(file_path)
            # We only scan actual files that look like models
            if os.path.isfile(str_path) and _is_model_file(str_path):
                logger.info(f"secure_torch: Scanning downloaded Hugging Face model: {str_path}")
                # We do an audit (if requested) or a full check.
                # However, since hf_hub_download expects just a path return,
                # we don't return the model object itself here, just let the check happen.
                
                # By default, we might not want to execute the code, so we just
                # do a "mock" load by passing format detect + validations
                
                # Actually, the safest way is to call secure_load with a dummy mechanism 
                # or just use audit_only to see the score, but if we want to block, we 
                # can't load the model into memory just yet or we waste memory,
                # especially since transformers will load it independently.
                
                # BUT secure_load currently loads the model. We should use audit_only
                # so it gives us a report or throws an error.
                # Wait, secure_load returns (model, report) if audit_only=True.
                # If audit_only=False, it returns model. 
                # Loading heavy models twice (once here, once in transformers) is bad for memory.
                
                # We need a dedicated 'audit_file' endpoint, or we just trust secure_load to not
                # execute bad code during the validation phase.
                
                # Let's extract the validators logic to an endpoint that doesn't instantiate the tensors,
                # OR we just use `load` but pass a flag. Wait, safetensors and pickle validations 
                # are done *before* loading. 
                pass
                
                try:
                    # To avoid returning the heavy model, we can try to call an internal method,
                    # but for public API compatibility, we will just call secure_torch.load
                    # but maybe we can close it? 
                    # Actually, if weights_only=True, torch.load creates tensors.
                    
                    # For now, let's call load. If memory is an issue, users will complain,
                    # and we can add a `scan_only` argument to secure_load.
                    # As a temporary workaround, if the file is very large, this will double RAM.
                    # A better way right now is to use the internal validators.
                    from secure_torch.loader import _run_validators, _verify_signature, _evaluate_sbom_policy, _enforce_policy
                    from secure_torch.format_detect import detect_format
                    from secure_torch.threat_score import ThreatScorer
                    
                    p = Path(str_path)
                    fmt = detect_format(p)
                    scorer = ThreatScorer()
                    
                    req_sig = security_kwargs.get("require_signature", False)
                    t_pub = security_kwargs.get("trusted_publishers", None)
                    max_score = security_kwargs.get("max_threat_score", 20)
                    a_only = security_kwargs.get("audit_only", False)
                    bundle = security_kwargs.get("bundle_path")
                    pubkey = security_kwargs.get("pubkey_path")
                    sbom = security_kwargs.get("sbom_path")
                    sbom_pol = security_kwargs.get("sbom_policy_path")
                    pol_ctx = security_kwargs.get("policy_context")

                    prov = _verify_signature(
                        path=p,
                        bundle_path=bundle,
                        pubkey_path=pubkey,
                        require_signature=req_sig,
                        trusted_publishers=t_pub,
                        scorer=scorer,
                    )
                    
                    _run_validators(str_path, fmt, scorer, path=p)
                    
                    _evaluate_sbom_policy(
                        sbom_path=sbom,
                        sbom_policy_path=sbom_pol,
                        policy_context=pol_ctx,
                        scorer=scorer,
                        audit_only=a_only,
                    )
                    
                    _enforce_policy(
                        provenance=prov,
                        trusted_publishers=t_pub,
                        scorer=scorer,
                        audit_only=a_only,
                    )
                    
                    if not a_only and scorer.is_blocked(max_score):
                        from secure_torch.exceptions import UnsafeModelError
                        raise UnsafeModelError(
                            f"Hugging Face model {str_path} blocked: threat score {scorer.total} > max {max_score}.\n"
                            f"Breakdown: {scorer.breakdown}"
                        )
                        
                except Exception as e:
                    # If it's our own exception, re-raise it
                    from secure_torch.exceptions import SecurityError
                    if isinstance(e, SecurityError):
                        raise
                    # Otherwise, log it but don't crash the download necessarily unless strict
                    logger.error(f"secure_torch failed to scan {str_path}: {e}")
                    raise

        return file_path

    # Apply the patch
    huggingface_hub.file_download.hf_hub_download = patched_hf_hub_download
    _PATCHED = True
    logger.info("secure_torch: Successfully patched huggingface_hub")


def unpatch_huggingface() -> None:
    """Remove the Hugging Face monkey-patch if it was applied."""
    global _ORIGINAL_HF_HUB_DOWNLOAD, _PATCHED
    
    if not _PATCHED or _ORIGINAL_HF_HUB_DOWNLOAD is None:
        return
        
    import huggingface_hub.file_download
    huggingface_hub.file_download.hf_hub_download = _ORIGINAL_HF_HUB_DOWNLOAD
    _ORIGINAL_HF_HUB_DOWNLOAD = None
    _PATCHED = False
    logger.info("secure_torch: Removed huggingface_hub patch")
