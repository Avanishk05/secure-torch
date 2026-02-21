"""
ONNX inspector — Phase 1.

Inspects ONNX model protobuf for:
- Custom operator domains
- Nested GRAPH attributes
- External data references
- Metadata code injection
"""

from __future__ import annotations

from pathlib import Path

from secure_torch.threat_score import (
    ThreatScorer,
    SCORE_CUSTOM_OPS_DETECTED,
    SCORE_ONNX_NESTED_GRAPH,
)

# Standard ONNX operator domains — anything else is a custom op
STANDARD_DOMAINS: frozenset[str] = frozenset(
    {
        "",  # default ONNX domain
        "ai.onnx",
        "ai.onnx.ml",
        "ai.onnx.training",
        "com.microsoft",  # widely used ONNX Runtime extensions
    }
)

CODE_PATTERNS: tuple[str, ...] = (
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "__import__",
)


def validate_onnx(path: Path, scorer: ThreatScorer) -> None:
    """
    Validate an ONNX model file.

    Args:
        path: Path to .onnx file.
        scorer: ThreatScorer to accumulate findings.
    """
    try:
        import onnx
    except ImportError:
        scorer.warn("onnx not installed — skipping ONNX validation. pip install onnx")
        return

    try:
        model = onnx.load(str(path))
    except Exception as e:
        scorer.warn(f"ONNX load for inspection failed: {e}")
        return

    _check_opsets(model, scorer)
    _check_graph_nodes(model, scorer)
    _check_metadata(model, scorer)
    _check_external_data(model, scorer)


def _check_opsets(model, scorer: ThreatScorer) -> None:
    """Check opset imports for custom/unknown domains."""
    for opset in model.opset_import:
        domain = opset.domain
        if domain not in STANDARD_DOMAINS:
            scorer.add(
                f"onnx_custom_op_domain:{domain}",
                SCORE_CUSTOM_OPS_DETECTED,
            )


def _check_graph_nodes(model, scorer: ThreatScorer) -> None:
    """Check graph nodes for custom ops and nested graphs."""
    import onnx

    for node in model.graph.node:
        # Custom op domain
        if node.domain and node.domain not in STANDARD_DOMAINS:
            scorer.add(
                f"onnx_custom_op_node:{node.op_type}@{node.domain}",
                SCORE_CUSTOM_OPS_DETECTED,
            )

        # Nested GRAPH attributes (can embed sub-graphs with custom ops)
        for attr in node.attribute:
            if attr.type == onnx.AttributeProto.GRAPH:
                scorer.add(
                    f"onnx_nested_graph:{node.op_type}",
                    SCORE_ONNX_NESTED_GRAPH,
                )


def _check_metadata(model, scorer: ThreatScorer) -> None:
    """Check metadata_props for code injection patterns."""
    for prop in model.metadata_props:
        value = prop.value
        for pattern in CODE_PATTERNS:
            if pattern in value:
                scorer.add(
                    f"onnx_code_in_metadata:{prop.key}",
                    50,  # same weight as safetensors metadata injection
                )
                break


def _check_external_data(model, scorer: ThreatScorer) -> None:
    """Check for external data references (can point to arbitrary files)."""
    for initializer in model.graph.initializer:
        for segment in initializer.external_data:
            if segment.key == "location":
                location = segment.value
                # Flag absolute paths or paths escaping the model directory
                if location.startswith("/") or ".." in location:
                    scorer.add(
                        f"onnx_suspicious_external_data_path:{location}",
                        30,
                    )
                else:
                    scorer.warn(f"ONNX external data reference: {location}")
