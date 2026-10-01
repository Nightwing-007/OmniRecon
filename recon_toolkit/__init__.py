"""
Recon Toolkit - WHOIS, DNS, and Subdomain Enumeration Suite.

A modular, clean Python toolkit for reconnaissance, attack surface mapping,
and security footprinting.
"""

from .whois_enum import lookup_whois, WhoisResult
from .dns_enum import query_dns_records, DnsResult
from .subdomain_enum import (
    enumerate_subdomains,
    enumerate_subdomains_async,
    passive_enumeration_crtsh,
    active_wordlist_bruteforce_async,
    SubdomainResult,
)
from .http_prober import (
    probe_subdomains,
    probe_subdomains_async,
    HttpProbeRecord,
    HttpProberResult,
    check_subdomain_takeover,
)
from .utils import normalize_domain, is_valid_domain

__version__ = "1.1.0"
__author__ = "Security Engineering Team"
__all__ = [
    "lookup_whois",
    "WhoisResult",
    "query_dns_records",
    "DnsResult",
    "enumerate_subdomains",
    "enumerate_subdomains_async",
    "passive_enumeration_crtsh",
    "active_wordlist_bruteforce_async",
    "SubdomainResult",
    "probe_subdomains",
    "probe_subdomains_async",
    "HttpProbeRecord",
    "HttpProberResult",
    "check_subdomain_takeover",
    "normalize_domain",
    "is_valid_domain",
]
