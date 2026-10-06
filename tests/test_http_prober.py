"""Unit tests for the HTTP/HTTPS Service Prober and Subdomain Takeover Detector."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from recon_toolkit.http_prober import (
    HttpProbeRecord,
    HttpProberResult,
    check_subdomain_takeover,
    extract_html_title,
    probe_single_endpoint,
    probe_subdomains,
)


class TestHttpProber(unittest.TestCase):
    """Test HTML title extraction, takeover signature matching, and async endpoint probing."""

    def test_extract_html_title(self):
        html_simple = "<html><head><title>Dashboard Login</title></head><body></body></html>"
        self.assertEqual(extract_html_title(html_simple), "Dashboard Login")

        html_multiline = (
            "<html><head><title>\n  Internal Portal  \n &amp; Admin \n</title></head></html>"
        )
        self.assertEqual(extract_html_title(html_multiline), "Internal Portal & Admin")

        html_no_title = "<html><head></head><body><h1>Hello</h1></body></html>"
        self.assertIsNone(extract_html_title(html_no_title))

        self.assertIsNone(extract_html_title(""))

    def test_check_subdomain_takeover_aws_s3(self):
        s3_body = "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
        is_vuln, service = check_subdomain_takeover(s3_body)
        self.assertTrue(is_vuln)
        self.assertIn("AWS S3", service)

    def test_check_subdomain_takeover_github_pages(self):
        gh_body = "<html><body>404: There isn't a GitHub Pages site here.</body></html>"
        is_vuln, service = check_subdomain_takeover(gh_body)
        self.assertTrue(is_vuln)
        self.assertIn("GitHub Pages", service)

    def test_check_subdomain_takeover_heroku(self):
        heroku_body = "<html><body>No such app - There is nothing here!</body></html>"
        is_vuln, service = check_subdomain_takeover(heroku_body)
        self.assertTrue(is_vuln)
        self.assertIn("Heroku", service)

    def test_check_subdomain_takeover_benign(self):
        benign_body = (
            "<html><head><title>Welcome</title></head><body>All systems operational</body></html>"
        )
        is_vuln, service = check_subdomain_takeover(benign_body)
        self.assertFalse(is_vuln)
        self.assertIsNone(service)

    def test_probe_record_to_dict(self):
        record = HttpProbeRecord(
            subdomain="api.example.com",
            url="https://api.example.com",
            port=443,
            scheme="https",
            status_code=200,
            title="API Gateway",
            server_header="cloudflare",
            content_length=1024,
            takeover_vulnerable=False,
        )
        d = record.to_dict()
        self.assertEqual(d["subdomain"], "api.example.com")
        self.assertEqual(d["status_code"], 200)
        self.assertFalse(d["takeover_vulnerable"])
        self.assertEqual(d["port"], 443)

    def test_probe_single_endpoint_success(self):
        async def run_test():
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><head><title>Admin Console</title></head></html>"
            mock_resp.content = b"<html><head><title>Admin Console</title></head></html>"
            mock_resp.headers = {"server": "nginx"}
            mock_resp.url = httpx.URL("https://admin.example.com")
            mock_client.get.return_value = mock_resp

            semaphore = asyncio.Semaphore(5)
            record = await probe_single_endpoint(
                client=mock_client,
                subdomain="admin.example.com",
                port=443,
                scheme="https",
                semaphore=semaphore,
            )

            self.assertEqual(record.status_code, 200)
            self.assertEqual(record.title, "Admin Console")
            self.assertEqual(record.server_header, "nginx")
            self.assertFalse(record.takeover_vulnerable)

        asyncio.run(run_test())

    def test_probe_single_endpoint_takeover_detection(self):
        async def run_test():
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.text = "NoSuchBucket: The specified bucket does not exist"
            mock_resp.content = mock_resp.text.encode()
            mock_resp.headers = {}
            mock_resp.url = httpx.URL("http://assets.example.com")
            mock_client.get.return_value = mock_resp

            semaphore = asyncio.Semaphore(5)
            record = await probe_single_endpoint(
                client=mock_client,
                subdomain="assets.example.com",
                port=80,
                scheme="http",
                semaphore=semaphore,
            )

            self.assertEqual(record.status_code, 404)
            self.assertTrue(record.takeover_vulnerable)
            self.assertIn("AWS S3", record.takeover_service)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
