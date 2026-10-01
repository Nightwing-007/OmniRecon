"""Unit tests for utility functions (normalization, validation, and exports)."""

import json
import os
import tempfile
import unittest

from recon_toolkit.utils import (
    export_subdomains_to_csv,
    export_to_json,
    is_valid_domain,
    normalize_domain,
)


class TestUtils(unittest.TestCase):
    """Test domain normalization and syntax validation routines."""

    def test_normalize_domain_clean_input(self):
        self.assertEqual(normalize_domain("example.com"), "example.com")
        self.assertEqual(normalize_domain("  example.com  "), "example.com")
        self.assertEqual(normalize_domain("EXAMPLE.COM"), "example.com")

    def test_normalize_domain_with_schemes(self):
        self.assertEqual(normalize_domain("http://example.com"), "example.com")
        self.assertEqual(normalize_domain("https://example.com"), "example.com")
        self.assertEqual(normalize_domain("https://sub.example.com/"), "sub.example.com")

    def test_normalize_domain_with_paths_and_ports(self):
        self.assertEqual(normalize_domain("http://example.com:8080/index.php"), "example.com")
        self.assertEqual(normalize_domain("example.com:443/login?user=admin"), "example.com")
        self.assertEqual(normalize_domain("sub.domain.co.uk/path/to/page"), "sub.domain.co.uk")

    def test_is_valid_domain(self):
        self.assertTrue(is_valid_domain("example.com"))
        self.assertTrue(is_valid_domain("sub.example.com"))
        self.assertTrue(is_valid_domain("my-site.org.uk"))
        self.assertTrue(is_valid_domain("a.b.c.d.com"))

        self.assertFalse(is_valid_domain(""))
        self.assertFalse(is_valid_domain("-invalid.com"))
        self.assertFalse(is_valid_domain("invalid-.com"))
        self.assertFalse(is_valid_domain("domain..com"))
        self.assertFalse(is_valid_domain("nodots"))
        self.assertFalse(is_valid_domain("http://example.com"))  # Must be normalized first

    def test_export_to_json(self):
        sample_data = {"domain": "test.com", "records": {"A": ["1.2.3.4"]}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            export_to_json(sample_data, tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["domain"], "test.com")
            self.assertEqual(loaded["records"]["A"], ["1.2.3.4"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_export_subdomains_to_csv(self):
        sample_subs = [
            {"subdomain": "api.test.com", "ip_addresses": ["1.1.1.1"], "sources": ["Active"]},
            {"subdomain": "dev.test.com", "ip_addresses": ["2.2.2.2"], "sources": ["Passive"]},
        ]
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            export_subdomains_to_csv(sample_subs, tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Subdomain,IP_Addresses,Sources", content)
            self.assertIn("api.test.com", content)
            self.assertIn("1.1.1.1", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
