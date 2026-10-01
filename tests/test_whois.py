"""Unit tests for the WHOIS Enumeration module."""

import datetime
import socket
import unittest
from unittest.mock import MagicMock, patch

from recon_toolkit.whois_enum import WhoisResult, lookup_whois


class TestWhoisEnum(unittest.TestCase):
    """Test WHOIS resolution, date normalization, error recovery, and dataclass serialization."""

    def test_whois_result_to_dict(self):
        res = WhoisResult(
            domain="example.com",
            registrar="MarkMonitor",
            is_registered=True,
            name_servers=["ns1.example.com", "ns2.example.com"],
        )
        d = res.to_dict()
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(d["registrar"], "MarkMonitor")
        self.assertTrue(d["is_registered"])
        self.assertEqual(len(d["name_servers"]), 2)

    @patch("whois.whois")
    def test_lookup_whois_success(self, mock_whois):
        mock_entry = MagicMock()
        mock_entry.domain_name = "example.com"
        mock_entry.get.side_effect = lambda key: {
            "registrar": "Example Registrar LLC",
            "whois_server": "whois.example.com",
            "creation_date": datetime.datetime(2000, 1, 1, 12, 0, 0),
            "expiration_date": datetime.datetime(2030, 1, 1, 12, 0, 0),
            "updated_date": datetime.datetime(2025, 1, 1, 12, 0, 0),
            "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "status": ["clientTransferProhibited"],
            "name": "Domain Admin",
            "org": "Example Corp",
            "emails": ["admin@example.com"],
            "country": "US",
            "dnssec": "unsigned",
            "text": "Raw Whois Data",
        }.get(key)

        mock_whois.return_value = mock_entry

        result = lookup_whois("example.com", timeout=5)
        self.assertTrue(result.is_registered)
        self.assertEqual(result.registrar, "Example Registrar LLC")
        self.assertIn("2000-01-01 12:00:00 UTC", str(result.creation_date))
        self.assertIn("NS1.EXAMPLE.COM", result.name_servers)
        self.assertEqual(result.country, "US")
        self.assertIsNone(result.error)

    @patch("whois.whois")
    @patch("recon_toolkit.whois_enum._lookup_rdap_fallback")
    def test_lookup_whois_unregistered_domain(self, mock_rdap, mock_whois):
        mock_entry = MagicMock()
        mock_entry.domain_name = None
        mock_entry.text = "No match for domain 'unregistered-domain-12345.com'"
        mock_whois.return_value = mock_entry
        mock_rdap.return_value = None

        result = lookup_whois("unregistered-domain-12345.com", timeout=5)
        self.assertFalse(result.is_registered)
        self.assertIn("unregistered", str(result.error).lower())

    @patch("whois.whois")
    @patch("recon_toolkit.whois_enum._lookup_rdap_fallback")
    def test_lookup_whois_timeout_with_rdap_recovery(self, mock_rdap, mock_whois):
        # Simulate port 43 timeout
        mock_whois.side_effect = socket.timeout("Port 43 timed out")

        # Simulate successful RDAP fallback
        mock_rdap.return_value = WhoisResult(
            domain="firewalled.com",
            registrar="RDAP Registrar Inc",
            whois_server="RDAP Gateway (HTTPS port 443)",
            is_registered=True,
            name_servers=["ns1.firewalled.com"],
        )

        result = lookup_whois("firewalled.com", timeout=2)
        self.assertTrue(result.is_registered)
        self.assertEqual(result.registrar, "RDAP Registrar Inc")
        self.assertIn("RDAP Gateway", str(result.whois_server))


if __name__ == "__main__":
    unittest.main()
