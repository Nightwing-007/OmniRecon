"""Unit tests for the Subdomain Enumeration module (aiodns async engine)."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import requests

from recon_toolkit.subdomain_enum import (
    SubdomainResult,
    async_detect_wildcard_dns,
    async_resolve_candidate,
    passive_enumeration_crtsh,
)


class TestSubdomainEnum(unittest.TestCase):
    """Test passive Certificate Transparency parsing, async wildcard detection, and aiodns resolving."""

    def test_subdomain_result_to_dict(self):
        res = SubdomainResult(domain="example.com", total_found=0)
        d = res.to_dict()
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(d["total_found"], 0)
        self.assertFalse(d["wildcard_detected"])
        self.assertEqual(d["subdomains"], [])

    @patch("requests.get")
    def test_passive_enumeration_crtsh_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "api.example.com\nadmin.example.com"},
            {"name_value": "*.internal.example.com"},
            {"name_value": "out-of-scope.other.com"},
        ]
        mock_get.return_value = mock_resp

        subs, err = passive_enumeration_crtsh("example.com")
        self.assertIsNone(err)
        self.assertIn("api.example.com", subs)
        self.assertIn("admin.example.com", subs)
        self.assertIn("internal.example.com", subs)
        self.assertNotIn("out-of-scope.other.com", subs)

    @patch("requests.get")
    def test_passive_enumeration_crtsh_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("crt.sh timed out")
        subs, err = passive_enumeration_crtsh("example.com")
        self.assertEqual(len(subs), 0)
        self.assertIsNotNone(err)
        self.assertIn("timed out", err.lower())

    def test_detect_wildcard_dns_negative(self):
        async def run_test():
            mock_resolver = MagicMock()
            with patch("recon_toolkit.subdomain_enum.async_query_a_record", new_callable=AsyncMock) as mock_query:
                # Queries return empty lists (non-existent domain)
                mock_query.return_value = []
                is_wildcard, ips = await async_detect_wildcard_dns("example.com", mock_resolver)
                self.assertFalse(is_wildcard)
                self.assertEqual(len(ips), 0)

        asyncio.run(run_test())

    def test_detect_wildcard_dns_positive(self):
        async def run_test():
            mock_resolver = MagicMock()
            with patch("recon_toolkit.subdomain_enum.async_query_a_record", new_callable=AsyncMock) as mock_query:
                # Queries return wildcard IP
                mock_query.return_value = ["203.0.113.50"]
                is_wildcard, ips = await async_detect_wildcard_dns("wildcard-domain.com", mock_resolver)
                self.assertTrue(is_wildcard)
                self.assertIn("203.0.113.50", ips)

        asyncio.run(run_test())

    def test_resolve_candidate_filters_wildcard(self):
        async def run_test():
            mock_resolver = MagicMock()
            semaphore = asyncio.Semaphore(10)
            wildcard_ips = {"203.0.113.50"}

            with patch("recon_toolkit.subdomain_enum.async_query_a_record", new_callable=AsyncMock) as mock_query:
                # 1. Candidate resolves to wildcard IP -> should be filtered out (return None)
                mock_query.return_value = ["203.0.113.50"]
                res = await async_resolve_candidate(
                    "fake.example.com", mock_resolver, semaphore, wildcard_ips
                )
                self.assertIsNone(res)

                # 2. Candidate resolves to real IP distinct from wildcard -> should be kept
                mock_query.return_value = ["198.51.100.99"]
                res2 = await async_resolve_candidate(
                    "real.example.com", mock_resolver, semaphore, wildcard_ips
                )
                self.assertIsNotNone(res2)
                self.assertEqual(res2[0], "real.example.com")
                self.assertEqual(res2[1], ["198.51.100.99"])

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
