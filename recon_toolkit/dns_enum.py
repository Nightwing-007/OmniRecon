"""
DNS Enumeration Module for Recon Toolkit.

Performs core DNS record lookups (A, AAAA, MX, TXT, NS, CNAME, SOA) using dnspython.

Under the Hood:
- The Domain Name System (DNS) is a hierarchical distributed database (RFC 1034, 1035).
- Resolvers ask Root Servers (.) -> TLD Servers (.com) -> Authoritative Servers (ns1.example.com)
  to translate human-readable domain names into machine-routable IP addresses and metadata.
- Query Types:
    * A: IPv4 address mapping (RFC 1035).
    * AAAA: IPv6 address mapping (RFC 3596).
    * MX: Mail Exchange records directing SMTP traffic with priority metrics (RFC 5321).
    * TXT: Arbitrary text records used for SPF (email spoof prevention), DKIM, DMARC,
      and domain verification (RFC 1464 / RFC 7208).
    * NS: Delegation to authoritative name servers for the DNS zone.
    * CNAME: Canonical name alias pointing one name to another (RFC 1035).
    * SOA: Start of Authority indicating primary master server, admin email, serial,
      and refresh/retry intervals.

This module implements robust error handling for missing records (NoAnswer), non-existent
domains (NXDOMAIN), nameserver timeouts, and server failures.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import dns.exception
import dns.rdatatype
import dns.resolver

from .utils import Colors, print_error, print_info, print_warning

# Standard DNS record types queried during reconnaissance
CORE_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

# High-reliability public DNS resolvers used if system resolvers fail or are customized
DEFAULT_NAMESERVERS = [
    "1.1.1.1",  # Cloudflare Primary
    "8.8.8.8",  # Google Primary
    "9.9.9.9",  # Quad9 Primary
]


@dataclass
class DnsRecordEntry:
    """Represents an individual DNS record answer."""

    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # Specific to MX records


@dataclass
class DnsResult:
    """
    Structured container for all discovered DNS records across a target domain.

    Attributes:
        domain: The domain queried.
        records: Dictionary mapping record type strings (e.g. 'A', 'MX') to lists of record strings.
        detailed_records: Dictionary mapping record types to lists of DnsRecordEntry objects.
        missing_records: List of record types that returned NoAnswer (normal behavior for unused types).
        errors: Dictionary mapping record types to error descriptions if a query failed.
        domain_exists: Boolean flag indicating if domain resolves (False if NXDOMAIN).
    """

    domain: str
    records: Dict[str, List[str]] = field(default_factory=dict)
    detailed_records: Dict[str, List[DnsRecordEntry]] = field(default_factory=dict)
    missing_records: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    domain_exists: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert DNS results to a clean dictionary for JSON export."""
        return {
            "domain": self.domain,
            "domain_exists": self.domain_exists,
            "records": self.records,
            "missing_records": self.missing_records,
            "errors": self.errors,
        }

    def print_summary(self) -> None:
        """Render a clean, colorized terminal summary of all DNS records."""
        if not self.domain_exists:
            print_error(f"Domain '{self.domain}' does not exist (NXDOMAIN). Check spelling.")
            return

        for rtype in CORE_RECORD_TYPES:
            entries = self.records.get(rtype, [])
            print(f"\n  {Colors.BOLD}{Colors.CYAN}[{rtype}] Records:{Colors.RESET}")

            if entries:
                for entry in entries:
                    print(f"    - {entry}")
            elif rtype in self.missing_records:
                print(f"    {Colors.DIM}(No {rtype} records published){Colors.RESET}")
            elif rtype in self.errors:
                print(f"    {Colors.RED}Query error: {self.errors[rtype]}{Colors.RESET}")


def get_configured_resolver(
    timeout: float = 3.0,
    nameservers: Optional[List[str]] = None,
) -> dns.resolver.Resolver:
    """
    Construct and configure a dnspython Resolver instance.

    Configures query timeouts, lifetime limits, and optional custom nameservers
    to avoid indefinite socket blocking.

    Args:
        timeout: Query timeout in seconds per individual nameserver probe.
        nameservers: Optional list of IP addresses of DNS resolvers.

    Returns:
        Configured dns.resolver.Resolver instance.
    """
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2.0  # Max total time across all retries

    if nameservers:
        resolver.nameservers = nameservers

    return resolver


def query_dns_records(
    domain: str,
    record_types: Optional[List[str]] = None,
    timeout: float = 3.0,
    custom_nameservers: Optional[List[str]] = None,
) -> DnsResult:
    """
    Query core DNS record types for a target domain.

    Gracefully catches and isolates per-record exceptions so a failure on one
    record (e.g., missing AAAA or NXDOMAIN on a sub-type) does not interrupt
    the discovery of other records.

    Args:
        domain: Clean target domain name (e.g. 'example.com').
        record_types: List of record types to query (defaults to CORE_RECORD_TYPES).
        timeout: Timeout in seconds per query attempt.
        custom_nameservers: Optional custom resolver IPs.

    Returns:
        DnsResult dataclass containing categorized records and error states.
    """
    types_to_query = record_types or CORE_RECORD_TYPES
    result = DnsResult(domain=domain)
    resolver = get_configured_resolver(timeout=timeout, nameservers=custom_nameservers)

    print_info(
        f"Querying DNS records for '{Colors.BOLD}{domain}{Colors.RESET}' ({', '.join(types_to_query)})..."
    )

    for rtype in types_to_query:
        result.records[rtype] = []
        result.detailed_records[rtype] = []

        try:
            # Query the resolver for the specific record type
            answers = resolver.resolve(domain, rtype)

            for rdata in answers:
                record_entry: Optional[DnsRecordEntry] = None

                if rtype == "A":
                    # IPv4 address string (e.g. '93.184.216.34')
                    val = str(rdata.address)
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=val, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(f"{val} (TTL: {answers.rrset.ttl}s)")

                elif rtype == "AAAA":
                    # IPv6 address string (e.g. '2606:2800:220:1:248:1893:25c8:1946')
                    val = str(rdata.address)
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=val, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(f"{val} (TTL: {answers.rrset.ttl}s)")

                elif rtype == "MX":
                    # Mail Exchange: includes integer preference / priority and exchange domain
                    preference = rdata.preference
                    exchange = str(rdata.exchange).rstrip(".")
                    record_entry = DnsRecordEntry(
                        record_type=rtype,
                        value=exchange,
                        ttl=answers.rrset.ttl,
                        priority=preference,
                    )
                    result.records[rtype].append(f"Priority: {preference:<3} Host: {exchange}")

                elif rtype == "TXT":
                    # TXT records can contain multiple chunks or quoted byte strings
                    # Join string parts decoding UTF-8 or ASCII
                    txt_strings = [part.decode("utf-8", errors="replace") for part in rdata.strings]
                    joined_txt = " ".join(txt_strings)
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=joined_txt, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(joined_txt)

                elif rtype == "NS":
                    # Authoritative Nameserver target
                    ns_target = str(rdata.target).rstrip(".")
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=ns_target, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(ns_target)

                elif rtype == "CNAME":
                    # Canonical Name alias target
                    cname_target = str(rdata.target).rstrip(".")
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=cname_target, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(cname_target)

                elif rtype == "SOA":
                    # Start of Authority: mname (primary master), rname (admin email), serial, etc.
                    mname = str(rdata.mname).rstrip(".")
                    rname = str(rdata.rname).rstrip(".").replace(".", "@", 1)  # First dot denotes @
                    soa_info = (
                        f"Primary Master: {mname}, Admin Email: {rname}, "
                        f"Serial: {rdata.serial}, Refresh: {rdata.refresh}s, "
                        f"Retry: {rdata.retry}s, Expire: {rdata.expire}s"
                    )
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=soa_info, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(soa_info)

                else:
                    # Fallback generic string representation
                    val = str(rdata)
                    record_entry = DnsRecordEntry(
                        record_type=rtype, value=val, ttl=answers.rrset.ttl
                    )
                    result.records[rtype].append(val)

                if record_entry:
                    result.detailed_records[rtype].append(record_entry)

        except dns.resolver.NoAnswer:
            # Domain exists, but no record of this specific type was configured.
            # This is normal (e.g. many domains lack AAAA or CNAME).
            result.missing_records.append(rtype)

        except dns.resolver.NXDOMAIN:
            # The domain does not exist in the DNS hierarchy.
            result.domain_exists = False
            result.errors[rtype] = "NXDOMAIN (Non-Existent Domain)"
            # Once NXDOMAIN is established, remaining record queries will also fail
            break

        except dns.resolver.Timeout:
            # DNS query timed out waiting for nameserver response
            result.errors[rtype] = f"Query timed out ({timeout}s)"

        except dns.resolver.NoNameservers:
            # All nameservers failed, returned SERVFAIL, or refused query
            result.errors[rtype] = "No nameservers responded (SERVFAIL or connection refused)"

        except dns.exception.DNSException as err:
            # Any other dnspython exception (e.g. form error, truncation)
            result.errors[rtype] = f"DNS Error: {err}"

        except Exception as err:
            result.errors[rtype] = f"Unexpected Error: {err}"

    return result
