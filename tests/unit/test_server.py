import pytest
from fastapi.testclient import TestClient
import secure_torch as st
from secure_torch.models import ThreatLevel


def test_health_endpoint():
    try:
        from secure_torch.server import create_app

        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "version": st.__version__}
    except ImportError:
        pytest.skip("FastAPI not installed")


def test_validate_endpoint_safe_model(tmp_path):
    try:
        from secure_torch.server import create_app
        import torch

        app = create_app()
        client = TestClient(app)

        model_path = tmp_path / "model.pt"
        torch.save({"test": 123}, str(model_path))

        response = client.post("/validate", json={"model_path": str(model_path)})
        assert response.status_code == 200
        data = response.json()
        assert data["path"] == str(model_path)
        assert data["threat_level"] in (ThreatLevel.SAFE.value, ThreatLevel.MEDIUM.value)
    except ImportError:
        pytest.skip("FastAPI not installed")


def test_validate_endpoint_unsafe_model(tmp_path):
    try:
        from secure_torch.server import create_app

        app = create_app()
        client = TestClient(app)

        # Test an invalid/missing file
        response = client.post("/validate", json={"model_path": "/fake/not_exist.pt"})
        assert response.status_code == 500
        error_detail = response.json()["detail"].lower()
        assert "no such file" in error_detail or "cannot find the path" in error_detail
    except ImportError:
        pytest.skip("FastAPI not installed")
