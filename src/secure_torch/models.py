"""Data models shared across secure_torch."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ModelFormat(str, Enum):
    SAFETENSORS = "safetensors"
    PICKLE = "pickle"
    ONNX = "onnx"
    UNKNOWN = "unknown"


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int) -> "ThreatLevel":
        if score == 0:
            return cls.SAFE
        elif score <= 15:
            return cls.LOW
        elif score <= 35:
            return cls.MEDIUM
        elif score <= 60:
            return cls.HIGH
        else:
            return cls.CRITICAL


@dataclass
class ProvenanceRecord:
    verified: bool
    signer: Optional[str] = None
    issuer: Optional[str] = None
    bundle_path: Optional[str] = None
    mode: str = "sigstore"  # "sigstore" | "pubkey"
    error: Optional[str] = None


@dataclass
class SBOMRecord:
    spdx_version: Optional[str] = None
    name: Optional[str] = None
    supplied_by: Optional[str] = None
    model_type: Optional[str] = None
    sensitive_pii: Optional[str] = None
    training_info: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class ValidationReport:
    path: str
    format: ModelFormat
    threat_level: ThreatLevel
    threat_score: int
    score_breakdown: dict[str, int]  # explainable: {"unsigned_model": 40, ...}
    findings: list[str]  # blocking issues
    warnings: list[str]  # non-blocking advisories
    size_bytes: int
    load_allowed: bool
    sandbox_active: bool
    provenance: Optional[ProvenanceRecord] = None
    sbom: Optional[SBOMRecord] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"Model:        {self.path}",
            f"Format:       {self.format.value}",
            f"Size:         {self.size_bytes:,} bytes",
            f"Threat Level: {self.threat_level.value} (score={self.threat_score})",
            f"Load Allowed: {'YES' if self.load_allowed else 'NO'}",
            f"Sandbox:      {'active' if self.sandbox_active else 'off'}",
        ]
        if self.score_breakdown:
            lines.append("Score Breakdown:")
            for k, v in self.score_breakdown.items():
                lines.append(f"  +{v:3d}  {k}")
        if self.findings:
            lines.append("Findings:")
            for f in self.findings:
                lines.append(f"  [BLOCK] {f}")
        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  [WARN]  {w}")
        if self.provenance:
            prov = self.provenance
            lines.append(
                f"Provenance:   {'✓ verified' if prov.verified else '✗ unverified'} ({prov.mode})"
            )
            if prov.signer:
                lines.append(f"  Signer: {prov.signer}")
        return "\n".join(lines)
