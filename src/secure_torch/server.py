"""
REST API Server for secure-torch validation.

Run a lightweight HTTP server to validate models from non-Python applications.
"""

from __future__ import annotations

import logging
from typing import Any

import secure_torch as st
from secure_torch.exceptions import SecurityError

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError:
    FastAPI = None


class ValidationRequest(BaseModel):
    model_path: str
    require_signature: bool = False
    trusted_publishers: list[str] | None = None
    max_threat_score: int = 20
    sandbox: bool = False
    sbom_path: str | None = None
    sbom_policy_path: str | None = None
    bundle_path: str | None = None
    pubkey_path: str | None = None


def create_app() -> "FastAPI":
    if FastAPI is None:
        raise RuntimeError(
            "FastAPI is not installed. To run the secure-torch server, "
            "install with `pip install secure-torch[server]`."
        )

    app = FastAPI(
        title="secure-torch validation API",
        description="REST API for model validation",
        version=st.__version__,
    )

    @app.post("/validate")
    def validate_model(req: ValidationRequest) -> dict[str, Any]:
        """Validate a model file without loading it."""
        try:
            report = st.scan_file(
                req.model_path,
                require_signature=req.require_signature,
                trusted_publishers=req.trusted_publishers,
                max_threat_score=req.max_threat_score,
                sbom_path=req.sbom_path,
                sbom_policy_path=req.sbom_policy_path,
                bundle_path=req.bundle_path,
                pubkey_path=req.pubkey_path,
            )
        except Exception as e:
            logger.exception("Validation failed")
            raise HTTPException(status_code=500, detail=str(e))

        from secure_torch.cli import _report_to_dict

        return _report_to_dict(report)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": st.__version__}

    return app


def run_server(port: int = 8080, host: str = "127.0.0.1") -> None:
    try:
        import uvicorn
    except ImportError:
        raise RuntimeError(
            "uvicorn is not installed. Install with `pip install secure-torch[server]`."
        )

    app = create_app()
    uvicorn.run(app, host=host, port=port)
