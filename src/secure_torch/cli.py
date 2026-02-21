"""Command-line interface for secure_torch."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

import secure_torch as st
from secure_torch.exceptions import SecurityError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-torch",
        description="Audit model artifacts with secure_torch validation.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {st.__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="Run validation and print a trust report.")
    audit.add_argument("model_path", help="Path to model artifact")
    audit.add_argument("--require-signature", action="store_true", help="Require a valid signature")
    audit.add_argument(
        "--trusted-publisher",
        action="append",
        default=None,
        help="Publisher allowlist entry (repeatable)",
    )
    audit.add_argument(
        "--max-threat-score",
        type=int,
        default=20,
        help="Threat score threshold used for allow/deny evaluation",
    )
    audit.add_argument("--sandbox", action="store_true", help="Load in sandboxed subprocess")
    audit.add_argument("--sbom-path", default=None, help="Path to SPDX SBOM JSON")
    audit.add_argument("--sbom-policy-path", default=None, help="Path to OPA/Rego policy")
    audit.add_argument("--bundle-path", default=None, help="Path to .sigstore/.sig bundle")
    audit.add_argument("--pubkey-path", default=None, help="Path to PEM public key")
    audit.add_argument("--json", action="store_true", help="Print report as JSON")
    return parser


def _report_to_dict(report: Any) -> dict[str, Any]:
    data = {
        "path": report.path,
        "format": report.format.value,
        "threat_level": report.threat_level.value,
        "threat_score": report.threat_score,
        "score_breakdown": report.score_breakdown,
        "findings": report.findings,
        "warnings": report.warnings,
        "sha256": report.sha256,
        "size_bytes": report.size_bytes,
        "load_allowed": report.load_allowed,
        "sandbox_active": report.sandbox_active,
    }
    if report.provenance:
        data["provenance"] = {
            "verified": report.provenance.verified,
            "signer": report.provenance.signer,
            "issuer": report.provenance.issuer,
            "bundle_path": report.provenance.bundle_path,
            "mode": report.provenance.mode,
            "error": report.provenance.error,
        }
    if report.sbom:
        data["sbom"] = {
            "spdx_version": report.sbom.spdx_version,
            "name": report.sbom.name,
            "supplied_by": report.sbom.supplied_by,
            "model_type": report.sbom.model_type,
            "sensitive_pii": report.sbom.sensitive_pii,
            "training_info": report.sbom.training_info,
        }
    return data


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command != "audit":
        return 2

    try:
        _, report = st.load(
            args.model_path,
            require_signature=args.require_signature,
            trusted_publishers=args.trusted_publisher,
            audit_only=True,
            max_threat_score=args.max_threat_score,
            sandbox=args.sandbox,
            sbom_path=args.sbom_path,
            sbom_policy_path=args.sbom_policy_path,
            bundle_path=args.bundle_path,
            pubkey_path=args.pubkey_path,
        )
    except (OSError, SecurityError, ImportError, ValueError) as exc:
        print(f"secure-torch: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(_report_to_dict(report), indent=2, sort_keys=True))
    else:
        print(report.summary())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
