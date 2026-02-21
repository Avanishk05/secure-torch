import pytest
from unittest.mock import patch
import os
import secure_torch
from secure_torch.huggingface import patch_huggingface, unpatch_huggingface
from secure_torch.exceptions import UnsafeModelError, SecurityError
from secure_torch.models import ThreatLevel

def test_huggingface_patch_blocks_unsafe_model(tmp_path):
    # Create a dummy malicious model file
    fake_model_path = tmp_path / "malicious.bin"
    fake_model_path.write_text("fake malicious content")
    
    # Mock huggingface_hub.file_download.hf_hub_download to return our fake file path
    with patch("huggingface_hub.file_download.hf_hub_download", return_value=str(fake_model_path)):
        try:
            # Apply our patch with strict security settings
            patch_huggingface(max_threat_score=10) # 10 is very low
            
            import huggingface_hub
            
            # The download should be intercepted and blocked by secure_torch
            # since we expect threat score to be higher for unsigned/unknown format files
            # (e.g. unsigned = 40)
            with pytest.raises(UnsafeModelError) as excinfo:
                huggingface_hub.file_download.hf_hub_download(repo_id="fake/repo", filename="malicious.bin")
                
            assert "blocked: threat score" in str(excinfo.value)
            
        finally:
            unpatch_huggingface()

def test_huggingface_patch_allows_safe_model(tmp_path):
    # Test that standard usage doesn't block arbitrarily
    # We create a dummy safe format (or pretend we did)
    # Actually just set max_threat_score very high
    fake_model_path = tmp_path / "safe.bin"
    fake_model_path.write_text("safe content")
    
    with patch("huggingface_hub.file_download.hf_hub_download", return_value=str(fake_model_path)):
        try:
            # Apply our patch with permissive settings
            patch_huggingface(max_threat_score=1000) 
            
            import huggingface_hub
            
            # This should NOT raise an error
            result = huggingface_hub.file_download.hf_hub_download(repo_id="fake/repo", filename="safe.bin")
            assert result == str(fake_model_path)
            
        finally:
            unpatch_huggingface()
