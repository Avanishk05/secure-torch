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

    scan = subparsers.add_parser("scan", help="Lightweight scan without model loading.")
    scan.add_argument("model_path", help="Path to model artifact")
    scan.add_argument("--require-signature", action="store_true", help="Require a valid signature")
    scan.add_argument(
        "--trusted-publisher",
        action="append",
        default=None,
        help="Publisher allowlist entry (repeatable)",
    )
    scan.add_argument(
        "--max-threat-score",
        type=int,
        default=20,
        help="Threat score threshold used for allow/deny evaluation",
    )
    scan.add_argument("--sbom-path", default=None, help="Path to SPDX SBOM JSON")
    scan.add_argument("--sbom-policy-path", default=None, help="Path to OPA/Rego policy")
    scan.add_argument("--bundle-path", default=None, help="Path to .sigstore/.sig bundle")
    scan.add_argument("--pubkey-path", default=None, help="Path to PEM public key")
    scan.add_argument("--json", action="store_true", help="Print report as JSON")
    return parser


def _report_to_dict(report: Any) -> dict[str, Any]:
    data = {
        "path": report.path,
        "format": report.format.name if hasattr(report.format, "name") else str(report.format),
        "threat_level": report.threat_level.name
        if hasattr(report.threat_level, "name")
        else str(report.threat_level),
        "threat_score": report.threat_score,
        "score_breakdown": report.score_breakdown,
        "findings": report.findings,
        "warnings": report.warnings,
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


def _print_rich_report(report: Any) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        print(report.summary())
        return

    console = Console()

    # Determine Threat Color
    # ThreatLevel ranges conceptually: SAFE (0), LOW (1-19), MEDIUM (20-49), HIGH (50-79), CRITICAL (80+)
    score = report.threat_score
    if score == 0:
        level_color = "green"
    elif score < 20:
        level_color = "yellow"
    elif score < 50:
        level_color = "orange3"
    elif score < 80:
        level_color = "red"
    else:
        level_color = "bold red"

    tl_name = (
        report.threat_level.name
        if hasattr(report.threat_level, "name")
        else str(report.threat_level)
    )

    header_text = Text()
    header_text.append(f"Model: {report.path}\n", style="bold")
    header_text.append(
        f"Format: {report.format.name if hasattr(report.format, 'name') else str(report.format)}\n"
    )
    header_text.append(f"Threat Score: {score} ", style="bold")
    header_text.append(f"[{tl_name}]\n", style=level_color)
    header_text.append("Status: ", style="bold")
    if report.load_allowed:
        header_text.append("ALLOWED\n", style="bold green")
    else:
        header_text.append("BLOCKED\n", style="bold red")

    console.print(
        Panel(header_text, title="Secure-Torch Security Report", border_style=level_color)
    )

    # Breakdown Table
    if report.score_breakdown:
        table = Table(title="Threat Score Breakdown", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right", style="red")

        for key, val in report.score_breakdown.items():
            table.add_row(str(key), str(val))

        console.print(table)

    # Provenance
    if report.provenance:
        prov_text = Text()
        if report.provenance.verified:
            prov_text.append("✔ Signature Verified\n", style="bold green")
            if report.provenance.signer:
                prov_text.append(f"Signer: {report.provenance.signer}\n")
            if report.provenance.issuer:
                prov_text.append(f"Issuer: {report.provenance.issuer}")
        else:
            prov_text.append("✖ Signature Unverified\n", style="bold red")
            if report.provenance.error:
                prov_text.append(f"Error: {report.provenance.error}", style="red")

        console.print(Panel(prov_text, title="Provenance (Sigstore/Crypto)", border_style="blue"))

    # SBOM
    if report.sbom:
        sbom_text = Text()
        sbom_text.append(f"Name: {report.sbom.name or 'Unknown'}\n")
        sbom_text.append(f"Supplied By: {report.sbom.supplied_by or 'Unknown'}\n")
        sbom_text.append(f"PII: {report.sbom.sensitive_pii or 'Not specified'}\n")
        console.print(Panel(sbom_text, title="SBOM Verification", border_style="cyan"))

    # Warnings
    if report.warnings:
        warn_text = Text()
        for w in report.warnings:
            warn_text.append(f"• {w}\n")
        console.print(Panel(warn_text, title="Warnings", border_style="yellow"))


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        try:
            report = st.scan_file(
                args.model_path,
                require_signature=args.require_signature,
                trusted_publishers=args.trusted_publisher,
                max_threat_score=args.max_threat_score,
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
            _print_rich_report(report)

        return 0

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
        _print_rich_report(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
