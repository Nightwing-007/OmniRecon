"""Unit tests for the DNS Enumeration module."""

import unittest
from unittest.mock import MagicMock, patch

import dns.resolver

from recon_toolkit.dns_enum import DnsResult, query_dns_records


class TestDnsEnum(unittest.TestCase):
    """Test DNS record resolution, exception handling (NoAnswer, NXDOMAIN), and serialization."""

    def test_dns_result_to_dict(self):
        res = DnsResult(
            domain="test.com",
            records={"A": ["1.2.3.4 (TTL: 300s)"]},
            missing_records=["AAAA"],
            errors={"MX": "Query timed out"},
        )
        d = res.to_dict()
        self.assertEqual(d["domain"], "test.com")
        self.assertTrue(d["domain_exists"])
        self.assertIn("1.2.3.4 (TTL: 300s)", d["records"]["A"])
        self.assertIn("AAAA", d["missing_records"])
        self.assertIn("MX", d["errors"])

    @patch("recon_toolkit.dns_enum.get_configured_resolver")
    def test_query_dns_records_success(self, mock_get_resolver):
        mock_resolver = MagicMock()
        mock_get_resolver.return_value = mock_resolver

        # Mock answers for different record types
        def resolve_side_effect(domain, rdtype):
            mock_ans = MagicMock()
            mock_ans.rrset.ttl = 300
            if rdtype == "A":
                rdata = MagicMock()
                rdata.address = "192.0.2.1"
                mock_ans.__iter__.return_value = [rdata]
                return mock_ans
            elif rdtype == "TXT":
                rdata = MagicMock()
                rdata.strings = [b"v=spf1 -all"]
                mock_ans.__iter__.return_value = [rdata]
                return mock_ans
            else:
                raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        result = query_dns_records("example.com", record_types=["A", "TXT", "AAAA"])
        self.assertTrue(result.domain_exists)
        self.assertIn("192.0.2.1 (TTL: 300s)", result.records["A"])
        self.assertIn("v=spf1 -all", result.records["TXT"])
        self.assertIn("AAAA", result.missing_records)

    @patch("recon_toolkit.dns_enum.get_configured_resolver")
    def test_query_dns_records_nxdomain(self, mock_get_resolver):
        mock_resolver = MagicMock()
        mock_get_resolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = query_dns_records("nonexistent-test-domain.org")
        self.assertFalse(result.domain_exists)
        self.assertIn("A", result.errors)
        self.assertIn("NXDOMAIN", result.errors["A"])


if __name__ == "__main__":
    unittest.main()
