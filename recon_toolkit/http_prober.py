"""
Asynchronous HTTP/HTTPS Service Prober and Subdomain Takeover Detector.

Leverages httpx and asyncio to concurrently probe discovered subdomains on ports
80 (HTTP) and 443 (HTTPS), extracting HTTP status codes, HTML <title> elements,
and inspecting response bodies for dangling cloud provider signatures indicative
of Subdomain Takeover vulnerabilities.

Under the Hood:
- Subdomain Takeover occurs when a DNS record (typically a CNAME or A record) points
  to a third-party cloud service (e.g., AWS S3, GitHub Pages, Heroku, Azure Web Apps)
  that has been deleted or unclaimed.
- If the original tenant deletes the bucket/app but forgets to remove the DNS record,
  a malicious third party can create an asset with the same identifier and hijack the
  subdomain, serving arbitrary content under the legitimate organization's domain.
- This module analyzes response patterns and error bodies against known provider fingerprints.
"""

import asyncio
from dataclasses import dataclass, field
import html
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .utils import Colors, print_error, print_info, print_success, print_warning

# Regex to safely extract HTML <title> contents regardless of casing or whitespace
TITLE_REGEX = re.compile(r"<title(?:\s+[^>]*)?>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Signatures of dangling cloud services vulnerable to Subdomain Takeover
# Mapping: Provider Name -> (Fingerprint string, Suggested cloud platform)
TAKEOVER_SIGNATURES: Dict[str, Tuple[str, str]] = {
    "AWS S3": (
        "NoSuchBucket",
        "Amazon Web Services S3 Bucket (unclaimed bucket name)",
    ),
    "AWS S3 Alternate": (
        "The specified bucket does not exist",
        "Amazon Web Services S3 Bucket",
    ),
    "GitHub Pages": (
        "There isn't a GitHub Pages site here",
        "GitHub Pages (unclaimed repository or custom domain)",
    ),
    "Heroku": (
        "No such app",
        "Heroku Platform (unclaimed Heroku app name)",
    ),
    "Heroku Error Page": (
        "herokucdn.com/error-pages/no-such-app.html",
        "Heroku Platform (unclaimed Heroku app)",
    ),
    "Shopify": (
        "Sorry, this shop is currently unavailable.",
        "Shopify Storefront (unclaimed custom domain)",
    ),
    "Fastly": (
        "Fastly error: unknown domain:",
        "Fastly CDN (unregistered service configuration)",
    ),
    "Azure Web App": (
        "404 Web Site not found",
        "Microsoft Azure App Service (unclaimed app slot)",
    ),
    "Surge.sh": (
        "project not found",
        "Surge.sh Static Hosting (unclaimed project)",
    ),
    "Zendesk": (
        "Help Center Closed",
        "Zendesk Support Portal (unclaimed account)",
    ),
    "Tumblr": (
        "Whatever you were looking for doesn't seem to exist at this address.",
        "Tumblr Blog (unclaimed custom domain)",
    ),
    "WordPress.com": (
        "Do you want to register ",
        "WordPress.com Hosted Site (unclaimed custom domain)",
    ),
    "Bitbucket": (
        "Repository not found",
        "Bitbucket Cloud (unclaimed repository)",
    ),
    "Ghost": (
        "The thing you were looking for is no longer here, or never was",
        "Ghost CMS (unclaimed Ghost publication)",
    ),
    "Fly.io": (
        "404 Not Found: Could not find target app",
        "Fly.io Application (unclaimed application instance)",
    ),
}


@dataclass
class HttpProbeRecord:
    """
    Result of an individual HTTP/HTTPS endpoint probe.

    Attributes:
        subdomain: Hostname probed.
        url: Full URL contacted (e.g., 'https://api.example.com').
        port: Destination port (80 or 443).
        scheme: Protocol ('http' or 'https').
        status_code: Returned HTTP status code (e.g. 200, 404), or None if connection failed.
        title: Extracted HTML <title> tag, if present.
        final_url: Destination URL after following redirects.
        server_header: Server response header (e.g., 'cloudflare', 'nginx/1.18').
        content_length: Response payload size in bytes.
        takeover_vulnerable: True if a dangling cloud signature was detected.
        takeover_service: Name of the identified cloud provider if vulnerable.
        error: Network or connection error description, if any.
    """

    subdomain: str
    url: str
    port: int
    scheme: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    final_url: Optional[str] = None
    server_header: Optional[str] = None
    content_length: Optional[int] = None
    takeover_vulnerable: bool = False
    takeover_service: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert probe record to a dictionary for JSON export."""
        return {
            "subdomain": self.subdomain,
            "url": self.url,
            "port": self.port,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "title": self.title,
            "final_url": self.final_url,
            "server_header": self.server_header,
            "content_length": self.content_length,
            "takeover_vulnerable": self.takeover_vulnerable,
            "takeover_service": self.takeover_service,
            "error": self.error,
        }


@dataclass
class HttpProberResult:
    """
    Container for aggregated HTTP/HTTPS probe findings across all subdomains.

    Attributes:
        domain: Apex domain analyzed.
        probes: List of HttpProbeRecord entries.
        vulnerable_count: Count of subdomains flagging takeover signatures.
        live_count: Count of subdomains responding with valid HTTP status codes.
    """

    domain: str
    probes: List[HttpProbeRecord] = field(default_factory=list)
    vulnerable_count: int = 0
    live_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a structured dictionary."""
        return {
            "domain": self.domain,
            "total_probed": len(self.probes),
            "live_endpoints": self.live_count,
            "vulnerable_takeovers": self.vulnerable_count,
            "results": [p.to_dict() for p in self.probes],
        }

    def print_summary(self) -> None:
        """Render a formatted, color-coded terminal report of probed web services."""
        print_info(
            f"HTTP Probing Complete: {Colors.BOLD}{Colors.GREEN}{self.live_count}{Colors.RESET} "
            f"live web endpoints discovered across {len(self.probes)} probed URLs."
        )

        if self.vulnerable_count > 0:
            print_error(
                f"{Colors.BOLD}{Colors.RED}POTENTIAL SUBDOMAIN TAKEOVER DETECTED on "
                f"{self.vulnerable_count} endpoint(s)!{Colors.RESET}"
            )

        if not self.probes:
            print(f"  {Colors.DIM}No web endpoints responded.{Colors.RESET}")
            return

        # Print header
        print(
            f"\n  {Colors.BOLD}{'STATUS':<8} {'URL':<38} {'TITLE / ERROR':<32} {'TAKEOVER RISK'}{Colors.RESET}"
        )
        print(f"  {'-' * 8} {'-' * 38} {'-' * 32} {'-' * 15}")

        for rec in self.probes:
            # 1. Status Code Column (8 chars padded)
            code_raw = f"[{rec.status_code}]" if rec.status_code else "[FAIL]"
            code_padded = f"{code_raw:<8}"
            if rec.status_code:
                if 200 <= rec.status_code < 300:
                    status_col = f"{Colors.GREEN}{code_padded}{Colors.RESET}"
                elif 300 <= rec.status_code < 400:
                    status_col = f"{Colors.YELLOW}{code_padded}{Colors.RESET}"
                elif 400 <= rec.status_code < 500:
                    status_col = f"{Colors.CYAN}{code_padded}{Colors.RESET}"
                else:
                    status_col = f"{Colors.RED}{code_padded}{Colors.RESET}"
            else:
                status_col = f"{Colors.DIM}{code_padded}{Colors.RESET}"

            # 2. URL Column (38 chars padded)
            url_raw = rec.url if len(rec.url) <= 36 else rec.url[:33] + "..."
            url_col = f"{url_raw:<38}"

            # 3. Title / Error Column (32 chars padded)
            if rec.title:
                clean_title = " ".join(rec.title.split())
                title_raw = clean_title if len(clean_title) <= 30 else clean_title[:27] + "..."
                info_col = f"{Colors.WHITE}{title_raw:<32}{Colors.RESET}"
            elif rec.error:
                err_raw = rec.error.split(":")[0]
                err_clean = err_raw if len(err_raw) <= 30 else err_raw[:27] + "..."
                info_col = f"{Colors.DIM}{err_clean:<32}{Colors.RESET}"
            else:
                info_col = f"{Colors.DIM}{'No title':<32}{Colors.RESET}"

            # 4. Takeover Column
            if rec.takeover_vulnerable:
                takeover_col = f"{Colors.BOLD}{Colors.RED}[!] VULNERABLE ({rec.takeover_service}){Colors.RESET}"
            else:
                takeover_col = f"{Colors.DIM}None{Colors.RESET}"

            print(f"  {status_col} {url_col} {info_col} {takeover_col}")


def check_subdomain_takeover(body_text: str) -> Tuple[bool, Optional[str]]:
    """
    Inspect an HTTP response body against known dangling cloud provider error signatures.

    Args:
        body_text: Raw or decoded HTTP response body string.

    Returns:
        Tuple of (is_vulnerable: bool, service_name: Optional[str]).
    """
    if not body_text:
        return False, None

    for service_name, (signature, description) in TAKEOVER_SIGNATURES.items():
        if signature.lower() in body_text.lower():
            return True, f"{service_name}: {description}"

    return False, None


def extract_html_title(body_text: str) -> Optional[str]:
    """
    Extract and unescape the HTML <title> string from response content.

    Args:
        body_text: HTML body text.

    Returns:
        Cleaned, unescaped title string or None.
    """
    if not body_text:
        return None
    match = TITLE_REGEX.search(body_text)
    if match:
        raw_title = match.group(1).strip()
        unescaped = html.unescape(raw_title)
        # Collapse multiple internal whitespace / newline characters
        return " ".join(unescaped.split())
    return None


async def probe_single_endpoint(
    client: httpx.AsyncClient,
    subdomain: str,
    port: int,
    scheme: str,
    semaphore: asyncio.Semaphore,
) -> HttpProbeRecord:
    """
    Probe a single host endpoint (HTTP port 80 or HTTPS port 443) asynchronously.

    Throttled by an asyncio.Semaphore to prevent socket/file descriptor exhaustion.

    Args:
        client: Shared httpx.AsyncClient instance.
        subdomain: Hostname (e.g. 'api.example.com').
        port: 80 or 443.
        scheme: 'http' or 'https'.
        semaphore: Concurrency limiter.

    Returns:
        Populated HttpProbeRecord.
    """
    url = f"{scheme}://{subdomain}"
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        url = f"{scheme}://{subdomain}:{port}"

    async with semaphore:
        try:
            response = await client.get(url)
            body_text = response.text

            title = extract_html_title(body_text)
            server_header = response.headers.get("server")
            content_length = len(response.content)
            is_vuln, vuln_service = check_subdomain_takeover(body_text)

            return HttpProbeRecord(
                subdomain=subdomain,
                url=url,
                port=port,
                scheme=scheme,
                status_code=response.status_code,
                title=title,
                final_url=str(response.url),
                server_header=server_header,
                content_length=content_length,
                takeover_vulnerable=is_vuln,
                takeover_service=vuln_service,
                error=None,
            )

        except httpx.ConnectTimeout:
            return HttpProbeRecord(
                subdomain=subdomain,
                url=url,
                port=port,
                scheme=scheme,
                error="Connection timed out",
            )
        except (httpx.ConnectError, httpx.NetworkError) as net_err:
            return HttpProbeRecord(
                subdomain=subdomain,
                url=url,
                port=port,
                scheme=scheme,
                error=f"Connect error: {net_err.__class__.__name__}",
            )
        except httpx.HTTPError as http_err:
            return HttpProbeRecord(
                subdomain=subdomain,
                url=url,
                port=port,
                scheme=scheme,
                error=f"HTTP protocol error: {http_err.__class__.__name__}",
            )
        except Exception as err:
            return HttpProbeRecord(
                subdomain=subdomain,
                url=url,
                port=port,
                scheme=scheme,
                error=f"Unexpected error: {err}",
            )


async def probe_subdomains_async(
    subdomains: List[str],
    concurrency: int = 15,
    timeout: float = 5.0,
) -> HttpProberResult:
    """
    Concurrently probe a list of subdomains across ports 80 (HTTP) and 443 (HTTPS).

    Args:
        subdomains: List of discovered subdomain hostnames.
        concurrency: Max simultaneous async connections managed by Semaphore.
        timeout: HTTP request timeout in seconds.

    Returns:
        HttpProberResult containing all probe records and takeover alerts.
    """
    semaphore = asyncio.Semaphore(concurrency)
    result = HttpProberResult(domain=subdomains[0] if subdomains else "")

    if not subdomains:
        return result

    # Deduplicate subdomains
    unique_subs = sorted(list(set(subdomains)))

    # Use custom headers and disable SSL verification to handle internal / self-signed certificates
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconToolkit/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # Limits and transport config for high-speed concurrent probing
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    timeout_cfg = httpx.Timeout(timeout, connect=timeout)

    tasks = []
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers=headers,
        limits=limits,
        timeout=timeout_cfg,
    ) as client:
        for sub in unique_subs:
            # Probe Port 80 (HTTP)
            tasks.append(
                probe_single_endpoint(client, sub, port=80, scheme="http", semaphore=semaphore)
            )
            # Probe Port 443 (HTTPS)
            tasks.append(
                probe_single_endpoint(client, sub, port=443, scheme="https", semaphore=semaphore)
            )

        probe_outputs = await asyncio.gather(*tasks, return_exceptions=True)

    for record in probe_outputs:
        if isinstance(record, HttpProbeRecord):
            result.probes.append(record)
            if record.status_code is not None:
                result.live_count += 1
            if record.takeover_vulnerable:
                result.vulnerable_count += 1

    return result


def probe_subdomains(
    subdomains: List[str],
    concurrency: int = 15,
    timeout: float = 5.0,
) -> HttpProberResult:
    """
    Synchronous wrapper to execute the asynchronous HTTP prober via asyncio.run().

    Args:
        subdomains: List of discovered subdomain hostnames.
        concurrency: Max simultaneous async requests (governed by Semaphore).
        timeout: Request timeout in seconds.

    Returns:
        HttpProberResult populated with findings.
    """
    return asyncio.run(
        probe_subdomains_async(subdomains=subdomains, concurrency=concurrency, timeout=timeout)
    )
