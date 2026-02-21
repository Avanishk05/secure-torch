"""
Unit tests — threat_score.py and models.py (extra coverage)

Covers:
- finding=False goes to warnings, not findings
- warn() message appears in warnings list
- Multiple add() for same key accumulates (sums) the score
- All ThreatLevel boundary scores
- is_blocked() boundary conditions
"""

from __future__ import annotations


from secure_torch.threat_score import ThreatScorer
from secure_torch.models import ThreatLevel


class TestThreatScorerExtras:
    def test_add_with_finding_false_goes_to_warnings(self):
        """add(..., finding=False) must NOT add to findings list."""
        scorer = ThreatScorer()
        scorer.add("unsigned_model", 40, finding=False)
        assert "unsigned_model" in scorer.breakdown
        assert scorer.total == 40
        assert len(scorer.findings) == 0, "finding=False must not produce a finding"
        assert len(scorer.warnings) > 0

    def test_warn_appears_in_warnings(self):
        """warn() must add exactly to warnings, not findings."""
        scorer = ThreatScorer()
        scorer.warn("Something advisory happened")
        assert len(scorer.warnings) == 1
        assert "Something advisory happened" in scorer.warnings[0]
        assert len(scorer.findings) == 0
        assert scorer.total == 0

    def test_multi_add_same_key_accumulates(self):
        """Multiple add() calls with the same key must sum the score."""
        scorer = ThreatScorer()
        scorer.add("repeated_risk", 10)
        scorer.add("repeated_risk", 10)
        scorer.add("repeated_risk", 10)
        assert scorer.breakdown["repeated_risk"] == 30
        assert scorer.total == 30

    def test_multi_add_different_keys_sum(self):
        """Multiple different keys must each appear in breakdown."""
        scorer = ThreatScorer()
        scorer.add("risk_a", 20)
        scorer.add("risk_b", 30)
        assert scorer.total == 50
        assert scorer.breakdown["risk_a"] == 20
        assert scorer.breakdown["risk_b"] == 30

    def test_empty_scorer_total_is_zero(self):
        scorer = ThreatScorer()
        assert scorer.total == 0
        assert scorer.breakdown == {}
        assert scorer.findings == []
        assert scorer.warnings == []

    def test_breakdown_is_copy(self):
        """Mutating the returned breakdown must not affect the scorer."""
        scorer = ThreatScorer()
        scorer.add("risk", 10)
        bd = scorer.breakdown
        bd["injected"] = 999
        assert "injected" not in scorer.breakdown

    def test_findings_is_copy(self):
        scorer = ThreatScorer()
        scorer.add("risk", 10)
        f = scorer.findings
        f.append("injected")
        assert "injected" not in scorer.findings


class TestThreatLevelBoundaries:
    """Exhaustive boundary tests for ThreatLevel.from_score()."""

    def test_score_0_is_safe(self):
        assert ThreatLevel.from_score(0) == ThreatLevel.SAFE

    def test_score_1_is_low(self):
        assert ThreatLevel.from_score(1) == ThreatLevel.LOW

    def test_score_15_is_low(self):
        assert ThreatLevel.from_score(15) == ThreatLevel.LOW

    def test_score_16_is_medium(self):
        assert ThreatLevel.from_score(16) == ThreatLevel.MEDIUM

    def test_score_35_is_medium(self):
        assert ThreatLevel.from_score(35) == ThreatLevel.MEDIUM

    def test_score_36_is_high(self):
        assert ThreatLevel.from_score(36) == ThreatLevel.HIGH

    def test_score_60_is_high(self):
        assert ThreatLevel.from_score(60) == ThreatLevel.HIGH

    def test_score_61_is_critical(self):
        assert ThreatLevel.from_score(61) == ThreatLevel.CRITICAL

    def test_score_100_is_critical(self):
        assert ThreatLevel.from_score(100) == ThreatLevel.CRITICAL

    def test_score_999_is_critical(self):
        assert ThreatLevel.from_score(999) == ThreatLevel.CRITICAL


class TestIsBlockedBoundaries:
    def test_exactly_at_max_not_blocked(self):
        scorer = ThreatScorer()
        scorer.add("risk", 40)
        assert scorer.is_blocked(40) is False  # total == max_score is allowed

    def test_one_above_max_blocked(self):
        scorer = ThreatScorer()
        scorer.add("risk", 41)
        assert scorer.is_blocked(40) is True

    def test_zero_score_not_blocked_for_any_threshold(self):
        scorer = ThreatScorer()
        assert scorer.is_blocked(0) is False  # 0 > 0 is False

    def test_any_score_blocked_at_minus1(self):
        """Negative max_score should always block."""
        scorer = ThreatScorer()
        scorer.add("risk", 1)
        assert scorer.is_blocked(-1) is True
