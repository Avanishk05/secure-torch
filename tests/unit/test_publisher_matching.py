"""
Unit tests — publisher matching security.

Covers:
- Exact signer match
- Email domain suffix match
- Path suffix match
- Spoofed substring attack blocked
- Empty publishers list
"""

from __future__ import annotations

from secure_torch.policy.trust_policy import _publisher_matches


class TestPublisherMatches:
    def test_exact_match(self):
        assert _publisher_matches("user@huggingface.co", "user@huggingface.co") is True

    def test_email_domain_match(self):
        assert _publisher_matches("user@huggingface.co", "huggingface.co") is True

    def test_path_suffix_not_matched(self):
        """Path suffix matching is disabled for security."""
        assert _publisher_matches("github.com/huggingface", "huggingface") is False

    def test_spoofed_substring_blocked(self):
        """evil.com/huggingface.co must NOT match 'huggingface.co'."""
        assert _publisher_matches("evil.com/huggingface.co", "huggingface.co") is False

    def test_embedded_substring_blocked(self):
        """nothuggingface.co must NOT match 'huggingface.co'."""
        assert _publisher_matches("nothuggingface.co", "huggingface.co") is False

    def test_no_match(self):
        assert _publisher_matches("user@example.com", "huggingface.co") is False

    def test_empty_signer(self):
        assert _publisher_matches("", "huggingface.co") is False
