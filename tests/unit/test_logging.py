import pytest
import json
import logging
import secure_torch as st
from secure_torch.exceptions import UnsafeModelError


def test_blocked_model_json_log(tmp_path, caplog):
    # Create an artificially blocked model. We'll use a valid pickle but set max_threat_score=0
    # and require signature to generate a threat score > 0.
    import torch

    model_path = tmp_path / "model.pt"
    torch.save({"test": 1}, str(model_path))

    with caplog.at_level(logging.ERROR):
        with pytest.raises(UnsafeModelError):
            st.load(str(model_path), require_signature=False, max_threat_score=0)

    # Check that a JSON log was emitted
    log_records = caplog.records
    assert len(log_records) > 0

    # One of the logs should be valid JSON
    json_log = None
    for record in log_records:
        try:
            data = json.loads(record.getMessage())
            if data.get("event") == "model_blocked":
                json_log = data
                break
        except json.JSONDecodeError:
            continue

    assert json_log is not None, "No JSON log representing a blocked model was found"
    assert json_log["path"] == str(model_path)
    assert json_log["format"] == "pickle"
    assert json_log["threat_score"] > 0
    assert any("unsigned_model" in f for f in json_log["findings"])
