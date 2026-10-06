"""
Subdomain Enumeration Module for Recon Toolkit (High-Concurrency AsyncIO Engine).

Discovers subdomains through two complementary methodologies:
1. Passive Enumeration via Open APIs:
   - Queries Certificate Transparency (CT) logs via crt.sh API (RFC 6962).
   - Generates ZERO network noise or packets directed at the target's nameservers.
2. High-Concurrency Active DNS Brute-Forcing (aiodns + asyncio):
   - Fully asynchronous DNS resolution utilizing aiodns and pycares C-ares engine.
   - Throttled safely by an asyncio.Semaphore to prevent file descriptor and socket exhaustion.
   - Fully integrated Wildcard DNS detection and automated false-positive filtering.

Under the Hood:
- Traditional thread pools (ThreadPoolExecutor) incur substantial OS context-switching
  overhead and thread management latency.
- The AsyncIO engine runs a single non-blocking event loop communicating with the
  asynchronous C-ares library, capable of sustaining 1,000+ queries per second with
  negligible CPU and memory utilization.
"""

import asyncio
from dataclasses import dataclass, field
import os
import random
import string
from typing import Any, Dict, List, Optional, Set, Tuple

import aiodns
import requests

from .utils import Colors, print_error, print_info, print_success, print_warning

# Default high-performance public DNS resolvers (used as reliable fallbacks)
DEFAULT_ASYNC_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Path to the bundled default wordlist
DEFAULT_WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists",
    "subdomains_common.txt",
)


@dataclass
class SubdomainRecord:
    """Represents a discovered subdomain with its IP addresses and discovery sources."""

    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "subdomain": self.subdomain,
            "ip_addresses": self.ip_addresses,
            "sources": self.sources,
        }


@dataclass
class SubdomainResult:
    """
    Container for subdomain enumeration results across passive and active channels.

    Attributes:
        domain: The base domain scanned.
        discovered_subdomains: List of SubdomainRecord objects.
        wildcard_detected: True if the target zone employs wildcard DNS resolution.
        wildcard_ips: IP addresses returned by wildcard probes.
        total_found: Count of unique discovered subdomains.
        errors: List of non-fatal warning/error strings encountered during scanning.
    """

    domain: str
    discovered_subdomains: List[SubdomainRecord] = field(default_factory=list)
    wildcard_detected: bool = False
    wildcard_ips: List[str] = field(default_factory=list)
    total_found: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a structured dictionary for JSON/CSV export."""
        return {
            "domain": self.domain,
            "total_found": self.total_found,
            "wildcard_detected": self.wildcard_detected,
            "wildcard_ips": self.wildcard_ips,
            "subdomains": [sub.to_dict() for sub in self.discovered_subdomains],
            "errors": self.errors,
        }

    def print_summary(self) -> None:
        """Render a formatted terminal table of discovered subdomains and resolved IPs."""
        if self.errors:
            for err in self.errors:
                print_warning(err)

        if self.wildcard_detected:
            print_warning(
                f"Wildcard DNS detected for '*.{self.domain}' -> {', '.join(self.wildcard_ips)}. "
                "Filtered out matching wildcard hosts to eliminate false positives."
            )

        print_info(
            f"Total Unique Subdomains Discovered: {Colors.BOLD}{Colors.GREEN}{self.total_found}{Colors.RESET}"
        )

        if not self.discovered_subdomains:
            print(f"  {Colors.DIM}No subdomains identified during this scan.{Colors.RESET}")
            return

        # Print header
        print(
            f"\n  {Colors.BOLD}{'SUBDOMAIN':<45} {'RESOLVED IP(S)':<30} {'SOURCE(S)'}{Colors.RESET}"
        )
        print(f"  {'-' * 45} {'-' * 30} {'-' * 15}")

        for sub in sorted(self.discovered_subdomains, key=lambda s: s.subdomain):
            sub_name = sub.subdomain
            ips_str = (
                ", ".join(sub.ip_addresses)
                if sub.ip_addresses
                else f"{Colors.DIM}Unresolved{Colors.RESET}"
            )
            sources_str = ", ".join(sub.sources)
            print(
                f"  {Colors.CYAN}{sub_name:<45}{Colors.RESET} {ips_str:<30} {Colors.DIM}{sources_str}{Colors.RESET}"
            )


# ============================================================================
# aiodns Async DNS Helper Functions
# ============================================================================
def get_async_resolver(
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
) -> aiodns.DNSResolver:
    """
    Construct an asynchronous aiodns.DNSResolver instance.

    Uses provided nameservers or defaults to reliable public resolvers (1.1.1.1 / 8.8.8.8).

    Args:
        nameservers: Optional list of DNS server IP strings.
        timeout: Query timeout in seconds.

    Returns:
        Configured aiodns.DNSResolver.
    """
    ns = nameservers or DEFAULT_ASYNC_NAMESERVERS
    try:
        resolver = aiodns.DNSResolver(nameservers=ns, timeout=timeout)
    except TypeError:
        resolver = aiodns.DNSResolver(nameservers=ns)
    return resolver


async def async_query_a_record(
    resolver: aiodns.DNSResolver,
    hostname: str,
) -> List[str]:
    """
    Query IPv4 'A' records for a hostname asynchronously using aiodns.

    Compatible with both aiodns 4.x (query_dns) and aiodns 3.x (query).

    Args:
        resolver: aiodns.DNSResolver instance.
        hostname: Hostname to resolve.

    Returns:
        List of resolved IPv4 address strings.
    """
    ips: List[str] = []
    try:
        if hasattr(resolver, "query_dns"):
            res = await resolver.query_dns(hostname, "A")
            if hasattr(res, "answer"):
                for rec in res.answer:
                    if hasattr(rec, "data") and hasattr(rec.data, "addr"):
                        ips.append(str(rec.data.addr))
                    elif hasattr(rec, "host"):
                        ips.append(str(rec.host))
        else:
            res = await resolver.query(hostname, "A")
            if isinstance(res, list):
                for rec in res:
                    if hasattr(rec, "host"):
                        ips.append(str(rec.host))
                    elif hasattr(rec, "data") and hasattr(rec.data, "addr"):
                        ips.append(str(rec.data.addr))
    except (aiodns.error.DNSError, Exception):
        return []
    return ips


# ============================================================================
# Wildcard DNS Detection (Async)
# ============================================================================
async def async_detect_wildcard_dns(
    domain: str,
    resolver: aiodns.DNSResolver,
) -> Tuple[bool, List[str]]:
    """
    Asynchronously test whether the target domain has a wildcard DNS record (*.domain.com).

    Sends queries for 3 randomly generated, non-existent subdomains.
    If they resolve, wildcard DNS is active, and their IP addresses are recorded
    to filter out identical brute-force hits.

    Args:
        domain: Base target domain.
        resolver: Configured aiodns.DNSResolver.

    Returns:
        Tuple of (is_wildcard_active, list_of_wildcard_ips).
    """
    wildcard_ips: Set[str] = set()
    probes_resolved = 0

    tasks = []
    for _ in range(3):
        rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        test_host = f"wildcard-probe-{rand_str}.{domain}"
        tasks.append(async_query_a_record(resolver, test_host))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, list) and res:
            probes_resolved += 1
            wildcard_ips.update(res)

    is_wildcard = probes_resolved > 0
    return is_wildcard, sorted(list(wildcard_ips))


# ============================================================================
# Passive Enumeration: Certificate Transparency (crt.sh API)
# ============================================================================
def passive_enumeration_crtsh(domain: str, timeout: int = 15) -> Tuple[Set[str], Optional[str]]:
    """
    Query crt.sh Certificate Transparency search API for historical and active subdomains.

    Certificate Transparency (RFC 6962) mandates that Certificate Authorities (CAs)
    log all newly issued SSL/TLS certificates into append-only public logs.
    Querying crt.sh provides domain intelligence passively with zero target contact.

    Args:
        domain: Base domain (e.g. 'example.com').
        timeout: HTTP request timeout in seconds.

    Returns:
        Tuple of (set_of_discovered_subdomains, optional_error_message).
    """
    found_subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconToolkit/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            return found_subdomains, f"crt.sh returned HTTP status {response.status_code}"

        data = response.json()
        if not isinstance(data, list):
            return found_subdomains, "Unexpected JSON format from crt.sh API"

        for entry in data:
            name_val = entry.get("name_value", "")
            for raw_name in name_val.split("\n"):
                clean_name = raw_name.strip().lower()

                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]

                if clean_name.endswith(f".{domain}") or clean_name == domain:
                    if clean_name != domain:
                        found_subdomains.add(clean_name)

        return found_subdomains, None

    except requests.exceptions.Timeout:
        return (
            found_subdomains,
            f"crt.sh API request timed out ({timeout}s). Service may be overloaded.",
        )
    except requests.exceptions.RequestException as err:
        return found_subdomains, f"crt.sh API connection error: {err}"
    except ValueError as err:
        return found_subdomains, f"crt.sh API response decode error: {err}"


# ============================================================================
# High-Concurrency Async Active Enumeration (aiodns + Semaphore)
# ============================================================================
async def async_resolve_candidate(
    candidate: str,
    resolver: aiodns.DNSResolver,
    semaphore: asyncio.Semaphore,
    wildcard_ips: Optional[Set[str]] = None,
) -> Optional[Tuple[str, List[str]]]:
    """
    Resolve a single candidate subdomain within an asyncio.Semaphore limit.

    Filters out responses matching the wildcard DNS IP set.

    Args:
        candidate: Hostname to resolve (e.g., 'admin.example.com').
        resolver: aiodns.DNSResolver instance.
        semaphore: Concurrency limiter.
        wildcard_ips: Set of wildcard IPs to discard as false positives.

    Returns:
        Tuple of (candidate, [resolved_ips]) or None.
    """
    async with semaphore:
        ips = await async_query_a_record(resolver, candidate)
        if not ips:
            return None

        # Wildcard DNS filtering: If resolved IPs match the wildcard signature, discard
        if wildcard_ips and set(ips) == wildcard_ips:
            return None

        return candidate, ips


async def active_wordlist_bruteforce_async(
    domain: str,
    wordlist_path: Optional[str] = None,
    concurrency: int = 25,
    timeout: float = 3.0,
    wildcard_ips: Optional[Set[str]] = None,
    nameservers: Optional[List[str]] = None,
) -> List[Tuple[str, List[str]]]:
    """
    Perform high-speed asynchronous DNS brute-forcing using aiodns and asyncio.Semaphore.

    Args:
        domain: Base target domain.
        wordlist_path: Path to custom wordlist, or None to use default.
        concurrency: Max simultaneous DNS queries governed by Semaphore.
        timeout: Query timeout in seconds.
        wildcard_ips: Set of detected wildcard IPs to suppress.
        nameservers: Optional custom nameservers.

    Returns:
        List of (subdomain, [ips]) tuples for all successfully resolved hosts.
    """
    path = wordlist_path or DEFAULT_WORDLIST_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Subdomain wordlist not found at '{path}'")

    words: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            item = line.strip().lower()
            if item and not item.startswith("#"):
                words.append(item)

    words = sorted(list(set(words)))
    candidates = [f"{w}.{domain}" for w in words]

    resolver = get_async_resolver(nameservers=nameservers, timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)

    tasks = [
        async_resolve_candidate(host, resolver, semaphore, wildcard_ips) for host in candidates
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    resolved: List[Tuple[str, List[str]]] = []

    for item in results:
        if isinstance(item, tuple) and item:
            resolved.append(item)

    return resolved


# ============================================================================
# Main Async Coordinator & Synchronous Entrypoint
# ============================================================================
async def enumerate_subdomains_async(
    domain: str,
    mode: str = "both",
    wordlist_path: Optional[str] = None,
    concurrency: int = 25,
    timeout: float = 3.0,
    nameservers: Optional[List[str]] = None,
) -> SubdomainResult:
    """
    Coordinate subdomain discovery combining passive APIs and async aiodns brute-forcing.

    Args:
        domain: Base domain to scan.
        mode: Scanning strategy: 'both' (default), 'passive', or 'wordlist'.
        wordlist_path: Optional path to custom wordlist.
        concurrency: Semaphore limit for concurrent DNS queries.
        timeout: Network timeout per query.
        nameservers: Optional custom resolver IPs.

    Returns:
        SubdomainResult populated with deduplicated records, IP resolutions, and metadata.
    """
    result = SubdomainResult(domain=domain)
    aggregated: Dict[str, Dict[str, Set[str]]] = {}

    resolver = get_async_resolver(nameservers=nameservers, timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)

    # 1. Wildcard DNS Detection (Async)
    wildcard_ip_set: Set[str] = set()
    if mode in ("both", "wordlist"):
        print_info("Testing target domain for Wildcard DNS (*.domain) configuration (async)...")
        is_wildcard, wild_ips = await async_detect_wildcard_dns(domain, resolver)
        result.wildcard_detected = is_wildcard
        result.wildcard_ips = wild_ips
        wildcard_ip_set = set(wild_ips)

        if is_wildcard:
            print_warning(
                f"Wildcard DNS active! Any non-existent subdomain resolves to: {', '.join(wild_ips)}"
            )

    # 2. Passive Enumeration (Certificate Transparency)
    if mode in ("both", "passive"):
        print_info(f"Querying Certificate Transparency logs via crt.sh for '{domain}'...")
        passive_subs, err = passive_enumeration_crtsh(domain)
        if err:
            result.errors.append(f"[crt.sh API] {err}")
        else:
            print_success(f"Discovered {len(passive_subs)} candidate subdomains from CT logs.")

        for sub in passive_subs:
            if sub not in aggregated:
                aggregated[sub] = {"ips": set(), "sources": set()}
            aggregated[sub]["sources"].add("Passive (crt.sh)")

        # Resolve passive subdomains asynchronously
        if passive_subs:
            print_info(
                f"Resolving active IP addresses for {len(passive_subs)} passive subdomains (async)..."
            )
            passive_tasks = [
                async_resolve_candidate(host, resolver, semaphore, wildcard_ip_set)
                for host in passive_subs
            ]
            passive_resolutions = await asyncio.gather(*passive_tasks, return_exceptions=True)
            for res in passive_resolutions:
                if isinstance(res, tuple) and res:
                    host, ips = res
                    aggregated[host]["ips"].update(ips)

    # 3. Active Brute-Forcing (aiodns + asyncio.Semaphore)
    if mode in ("both", "wordlist"):
        wpath = wordlist_path or DEFAULT_WORDLIST_PATH
        print_info(
            f"Running active DNS brute-force (AsyncIO aiodns, concurrency={concurrency}) "
            f"using '{os.path.basename(wpath)}'..."
        )
        try:
            active_results = await active_wordlist_bruteforce_async(
                domain=domain,
                wordlist_path=wpath,
                concurrency=concurrency,
                timeout=timeout,
                wildcard_ips=wildcard_ip_set,
                nameservers=nameservers,
            )
            print_success(
                f"Active brute-force identified {len(active_results)} resolving subdomains."
            )

            for host, ips in active_results:
                if host not in aggregated:
                    aggregated[host] = {"ips": set(), "sources": set()}
                aggregated[host]["ips"].update(ips)
                aggregated[host]["sources"].add("Active (Wordlist)")

        except FileNotFoundError as fnf_err:
            result.errors.append(f"[Active Enumeration] {fnf_err}")
            print_error(str(fnf_err))

    # Compile aggregated dictionary into SubdomainRecord objects
    for host, data in aggregated.items():
        record = SubdomainRecord(
            subdomain=host,
            ip_addresses=sorted(list(data["ips"])),
            sources=sorted(list(data["sources"])),
        )
        result.discovered_subdomains.append(record)

    result.total_found = len(result.discovered_subdomains)
    return result


def enumerate_subdomains(
    domain: str,
    mode: str = "both",
    wordlist_path: Optional[str] = None,
    threads: int = 25,
    timeout: float = 3.0,
    nameservers: Optional[List[str]] = None,
) -> SubdomainResult:
    """
    Synchronous wrapper to execute the asynchronous subdomain discovery pipeline.

    Args:
        domain: Base domain to scan.
        mode: 'both', 'passive', or 'wordlist'.
        wordlist_path: Optional path to custom wordlist.
        threads: Concurrency limit passed to asyncio.Semaphore.
        timeout: Query timeout in seconds.
        nameservers: Optional custom resolver IPs.

    Returns:
        SubdomainResult populated with records and metadata.
    """
    return asyncio.run(
        enumerate_subdomains_async(
            domain=domain,
            mode=mode,
            wordlist_path=wordlist_path,
            concurrency=threads,
            timeout=timeout,
            nameservers=nameservers,
        )
    )
