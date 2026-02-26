"""
SPDX AI Profile SBOM parser — Phase 3 (Experimental).

Note: SPDX AI Profile is not widely used yet (as of early 2026).
This parser is forward-looking. secure-torch is helping create the standard.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from secure_torch.models import SBOMRecord

logger = logging.getLogger(__name__)


def parse_sbom(sbom_path: str) -> Optional[SBOMRecord]:
    """
    Parse an SPDX 2.3 / 3.0 AI Profile JSON file.

    Args:
        sbom_path: Path to .spdx.json file.

    Returns:
        SBOMRecord if parsing succeeds, None otherwise.
    """
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    record = SBOMRecord(raw=data)
    record.spdx_version = data.get("spdxVersion")
    record.name = data.get("name")

    # Extract from packages list (SPDX 2.3 structure)
    packages = data.get("packages", [])
    if packages and isinstance(packages, list):
        pkg = packages[0]
        record.supplied_by = pkg.get("suppliedBy") or pkg.get("originator")
        record.model_type = pkg.get("typeOfModel")
        record.sensitive_pii = pkg.get("sensitivePersonalInformation")
        record.training_info = pkg.get("informationAboutTraining")

    # SPDX 3.0 AI Profile structure
    ai_profile = data.get("aiProfile", {})
    if ai_profile:
        record.model_type = record.model_type or ai_profile.get("modelType")
        record.training_info = record.training_info or str(ai_profile.get("trainingDatasets", ""))

    return record
