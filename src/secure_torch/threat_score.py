"""
Threat scoring engine — explainable, named contributors.

Score is a dict of named reasons, not a magic number.
Users see exactly WHY a model scored what it scored.
"""

from __future__ import annotations

from secure_torch.models import ThreatLevel


# Score contribution constants
SCORE_UNSIGNED_MODEL = 40
SCORE_CUSTOM_OPS_DETECTED = 30
SCORE_UNKNOWN_PUBLISHER = 20
SCORE_PICKLE_REDUCE_OPCODE = 25
SCORE_PICKLE_GLOBAL_DANGEROUS = 40
SCORE_PICKLE_GLOBAL_UNKNOWN = 10
SCORE_PICKLE_INST_OPCODE = 10
SCORE_ONNX_NESTED_GRAPH = 10
SCORE_SAFETENSORS_CODE_IN_METADATA = 50
SCORE_SBOM_MISSING = 20
SCORE_PROVENANCE_UNVERIFIABLE = 25
SCORE_HEADER_OVERSIZED = 15
SCORE_DTYPE_UNSAFE = 35


class ThreatScorer:
    """Accumulates named threat score contributions."""

    def __init__(self) -> None:
        self._breakdown: dict[str, int] = {}
        self._findings: list[str] = []
        self._warnings: list[str] = []

    def add(self, reason: str, score: int, finding: bool = True) -> None:
        """Add a named score contribution."""
        self._breakdown[reason] = self._breakdown.get(reason, 0) + score
        if finding:
            self._findings.append(f"{reason} (+{score})")
        else:
            self._warnings.append(f"{reason} (advisory)")

    def warn(self, message: str) -> None:
        """Add a non-blocking advisory warning."""
        self._warnings.append(message)

    @property
    def total(self) -> int:
        return sum(self._breakdown.values())

    @property
    def breakdown(self) -> dict[str, int]:
        return dict(self._breakdown)

    @property
    def findings(self) -> list[str]:
        return list(self._findings)

    @property
    def warnings(self) -> list[str]:
        return list(self._warnings)

    @property
    def threat_level(self) -> ThreatLevel:
        return ThreatLevel.from_score(self.total)

    def is_blocked(self, max_score: int) -> bool:
        return self.total > max_score
