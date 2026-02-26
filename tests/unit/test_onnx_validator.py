"""
Unit tests — formats/onnx_loader.py

Covers:
- Standard opset accepted (no score)
- Custom opset domain scored
- Custom op node in graph scored
- Nested GRAPH attribute scored
- Code injection in metadata
- External data absolute/relative paths
- onnx not installed: graceful warning
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from secure_torch.threat_score import ThreatScorer
from typing import Optional


def _onnx_available():
    try:
        __import__("onnx")
        return True
    except ImportError:
        return False


def make_onnx_model(
    custom_opset_domain: Optional[str] = None,
    custom_node_domain: Optional[str] = None,
    nested_graph: bool = False,
    metadata: Optional[dict] = None,
    external_data_path: Optional[str] = None,
):
    """Build a minimal ONNX model with optional dangerous attributes."""
    from onnx import helper, TensorProto

    nodes = []
    if custom_node_domain:
        node = helper.make_node("CustomOp", inputs=[], outputs=["Y"], domain=custom_node_domain)
        nodes.append(node)

    if nested_graph:
        sub_node = helper.make_node("Identity", inputs=["X"], outputs=["Y"])
        sub_graph = helper.make_graph(
            [sub_node],
            "subgraph",
            [helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])],
            [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])],
        )
        nested_attr = helper.make_attribute("body", sub_graph)
        loop_node = helper.make_node("Loop", inputs=[], outputs=["out"])
        loop_node.attribute.append(nested_attr)
        nodes.append(loop_node)

    graph = helper.make_graph(nodes, "test_graph", [], [])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])

    if custom_opset_domain:
        opset = model.opset_import.add()
        opset.domain = custom_opset_domain
        opset.version = 1

    if metadata:
        for k, v in metadata.items():
            entry = model.metadata_props.add()
            entry.key = k
            entry.value = v

    if external_data_path:
        # Create an initializer with external data reference
        init = model.graph.initializer.add()
        init.name = "ext_data"
        init.data_type = TensorProto.FLOAT
        seg = init.external_data.add()
        seg.key = "location"
        seg.value = external_data_path

    return model


def write_onnx(model) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".onnx", delete=False)
    f.write(model.SerializeToString())
    f.close()
    return Path(f.name)


@pytest.mark.skipif(not _onnx_available(), reason="onnx not installed")
class TestOnnxOpsets:
    def test_standard_onnx_opset_no_score(self):
        """Standard onnx opset must produce zero score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model()
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total == 0, f"Expected 0, got {scorer.breakdown}"
        finally:
            os.unlink(path)

    def test_custom_opset_domain_scored(self):
        """Custom opset domain must add to threat score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(custom_opset_domain="com.evil.custom")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total > 0
            assert any("custom_op" in k for k in scorer.breakdown)
        finally:
            os.unlink(path)

    def test_microsoft_opset_no_score(self):
        """com.microsoft is an allowed domain — must not score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(custom_opset_domain="com.microsoft")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total == 0
        finally:
            os.unlink(path)


@pytest.mark.skipif(not _onnx_available(), reason="onnx not installed")
class TestOnnxGraphNodes:
    def test_custom_op_node_scored(self):
        """A graph node with a custom domain must be scored."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(custom_node_domain="com.attacker")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total > 0
        finally:
            os.unlink(path)

    def test_nested_graph_attribute_scored(self):
        """A GRAPH-type attribute (nested subgraph) must add to score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(nested_graph=True)
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total > 0
            assert any("nested_graph" in k for k in scorer.breakdown)
        finally:
            os.unlink(path)


@pytest.mark.skipif(not _onnx_available(), reason="onnx not installed")
class TestOnnxMetadata:
    def test_code_in_metadata_eval_scored(self):
        """eval( in metadata_props must score high."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(metadata={"prompt": "eval(os.system('id'))"})
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total >= 50
        finally:
            os.unlink(path)

    def test_clean_metadata_no_score(self):
        """Clean metadata must produce zero score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(metadata={"description": "A perfectly safe model"})
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total == 0
        finally:
            os.unlink(path)


@pytest.mark.skipif(not _onnx_available(), reason="onnx not installed")
class TestOnnxExternalData:
    def test_absolute_external_data_path_scored(self):
        """Absolute path in external data must be flagged."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(external_data_path="/etc/passwd")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total > 0
        finally:
            os.unlink(path)

    def test_dotdot_external_data_path_scored(self):
        """Path traversal (../secret) in external data must be flagged."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(external_data_path="../../../etc/shadow")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            assert scorer.total > 0
        finally:
            os.unlink(path)

    def test_relative_external_data_path_warns_only(self):
        """A normal relative external data path should warn but not score."""
        from secure_torch.formats.onnx_loader import validate_onnx

        model = make_onnx_model(external_data_path="model_weights.bin")
        path = write_onnx(model)
        try:
            scorer = ThreatScorer()
            validate_onnx(path, scorer)
            # Relative path is advisory only
            assert len(scorer.warnings) > 0
            assert scorer.total == 0
        finally:
            os.unlink(path)


class TestOnnxNotInstalled:
    def test_onnx_not_installed_warns_gracefully(self, monkeypatch):
        """When onnx is not installed, validate_onnx must warn, not raise."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "onnx":
                raise ImportError("onnx not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        # We need a temp path but won't actually need to read it
        f = tempfile.NamedTemporaryFile(suffix=".onnx", delete=False)
        f.close()
        path = Path(f.name)
        try:
            from secure_torch.formats import onnx_loader

            scorer = ThreatScorer()
            onnx_loader.validate_onnx(path, scorer)
            assert len(scorer.warnings) > 0
        finally:
            os.unlink(path)
