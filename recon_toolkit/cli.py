"""
Command-Line Interface (CLI) for Recon Toolkit.

Orchestrates WHOIS querying, DNS record harvesting, Subdomain enumeration (AsyncIO),
and HTTP/HTTPS service probing with Subdomain Takeover detection.
"""

import argparse
import sys
import time
from typing import Any, Dict, List, Optional

from .dns_enum import CORE_RECORD_TYPES, DnsResult, query_dns_records
from .http_prober import HttpProberResult, probe_subdomains
from .subdomain_enum import SubdomainResult, enumerate_subdomains
from .utils import (
    Colors,
    export_subdomains_to_csv,
    export_to_json,
    is_valid_domain,
    normalize_domain,
    print_banner,
    print_error,
    print_info,
    print_section,
    print_success,
    print_warning,
)
from .whois_enum import WhoisResult, lookup_whois


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct the command-line argument parser with all operational flags.

    Returns:
        Configured argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(
        prog="recon-toolkit",
        description="WHOIS, DNS & Subdomain Enumeration Toolkit with AsyncIO Engine & HTTP Prober",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com --all
  python main.py example.com --whois
  python main.py example.com --dns
  python main.py example.com --subdomains --sub-mode passive
  python main.py example.com --subdomains -t 50 --probe
  python main.py example.com --probe -o live_endpoints.json
  python main.py example.com --all -o results.json
        """,
    )

    # Target Domain Specification
    parser.add_argument(
        "domain",
        type=str,
        help="Target domain name to analyze (e.g., example.com or https://example.com)",
    )

    # Scan Phase Selectors
    scan_group = parser.add_argument_group("Scan Modules")
    scan_group.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Execute all modules: WHOIS, DNS records, Subdomains, and HTTP Service Probing (default)",
    )
    scan_group.add_argument(
        "-w",
        "--whois",
        action="store_true",
        help="Execute WHOIS registry lookup only",
    )
    scan_group.add_argument(
        "--dns",
        action="store_true",
        help="Query core DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) only",
    )
    scan_group.add_argument(
        "-s",
        "--subdomains",
        action="store_true",
        help="Execute Subdomain discovery only",
    )
    scan_group.add_argument(
        "-p",
        "--probe",
        action="store_true",
        help="Probe discovered subdomains on HTTP (80) & HTTPS (443) for status, title, and takeover risks",
    )

    # Subdomain Discovery & Probing Options
    sub_group = parser.add_argument_group("Concurrency & Subdomain Options")
    sub_group.add_argument(
        "--sub-mode",
        choices=["both", "passive", "wordlist"],
        default="both",
        help="Subdomain discovery strategy: 'both' (default), 'passive' (crt.sh API), or 'wordlist'",
    )
    sub_group.add_argument(
        "-W",
        "--wordlist",
        type=str,
        default=None,
        help="Path to custom subdomain wordlist file (defaults to bundled wordlist)",
    )
    sub_group.add_argument(
        "-t",
        "--threads",
        type=int,
        default=25,
        help="Max concurrency limit for AsyncIO Semaphore (controls DNS and HTTP probe concurrency, default: 25)",
    )

    # Network & Resolver Configuration
    net_group = parser.add_argument_group("Network & Resolver Configuration")
    net_group.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Query timeout in seconds for DNS, WHOIS, and HTTP requests (default: 3.0)",
    )
    net_group.add_argument(
        "--nameservers",
        type=str,
        default=None,
        help="Comma-separated list of custom DNS resolver IPs (e.g. '1.1.1.1,8.8.8.8')",
    )

    # Output & Export Flags
    out_group = parser.add_argument_group("Output & Export")
    out_group.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="File path to save scan results (JSON or CSV based on extension, or combined JSON)",
    )
    out_group.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON to standard output (useful for piping into jq)",
    )
    out_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner on startup",
    )

    return parser


def run_cli(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for CLI execution.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if not args.no_banner and not args.json:
        print_banner()

    # 1. Normalize and Validate Domain
    raw_domain = args.domain
    domain = normalize_domain(raw_domain)

    if not is_valid_domain(domain):
        print_error(
            f"Invalid target domain format: '{raw_domain}'. Expected a valid domain (e.g., example.com)."
        )
        return 1

    # Determine module execution flags
    run_whois_flag = args.whois
    run_dns_flag = args.dns
    run_sub_flag = args.subdomains
    run_probe_flag = args.probe

    # If --all or no specific flags were specified, default to running all phases including probing
    if not (run_whois_flag or run_dns_flag or run_sub_flag or run_probe_flag) or args.all:
        run_whois_flag = True
        run_dns_flag = True
        run_sub_flag = True
        run_probe_flag = True

    # If --probe is requested explicitly without --subdomains, enable subdomain discovery to feed endpoints
    if run_probe_flag and not (run_whois_flag or run_dns_flag or run_sub_flag):
        run_sub_flag = True

    custom_resolvers = (
        [ns.strip() for ns in args.nameservers.split(",")] if args.nameservers else None
    )

    # Results aggregation dictionary for structured reporting / export
    full_report: Dict[str, Any] = {
        "metadata": {
            "target": domain,
            "raw_input": raw_domain,
            "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "modules_executed": {
                "whois": run_whois_flag,
                "dns": run_dns_flag,
                "subdomains": run_sub_flag,
                "http_probe": run_probe_flag,
            },
            "async_concurrency_limit": args.threads,
        }
    }

    discovered_hosts: List[str] = [domain]

    try:
        # Phase 1: WHOIS Enumeration
        if run_whois_flag:
            if not args.json:
                print_section(f"Phase 1: WHOIS Registration Data ({domain})")
            whois_res: WhoisResult = lookup_whois(domain, timeout=int(args.timeout))
            full_report["whois"] = whois_res.to_dict()
            if not args.json:
                whois_res.print_summary()

        # Phase 2: Core DNS Records
        if run_dns_flag:
            if not args.json:
                print_section(f"Phase 2: Core DNS Records ({domain})")
            dns_res: DnsResult = query_dns_records(
                domain=domain,
                timeout=args.timeout,
                custom_nameservers=custom_resolvers,
            )
            full_report["dns"] = dns_res.to_dict()
            if not args.json:
                dns_res.print_summary()

        # Phase 3: Subdomain Enumeration (AsyncIO aiodns Engine)
        if run_sub_flag:
            if not args.json:
                print_section(f"Phase 3: Subdomain Enumeration [aiodns] ({domain})")
            sub_res: SubdomainResult = enumerate_subdomains(
                domain=domain,
                mode=args.sub_mode,
                wordlist_path=args.wordlist,
                threads=args.threads,
                timeout=args.timeout,
                nameservers=custom_resolvers,
            )
            full_report["subdomains"] = sub_res.to_dict()
            if not args.json:
                sub_res.print_summary()

            # Harvest discovered subdomains for the HTTP prober
            sub_names = [sub.subdomain for sub in sub_res.discovered_subdomains]
            if sub_names:
                discovered_hosts = sub_names
                if domain not in discovered_hosts:
                    discovered_hosts.insert(0, domain)

        # Phase 4: HTTP/HTTPS Service Probing & Subdomain Takeover Detection (httpx)
        if run_probe_flag:
            if not args.json:
                print_section(
                    f"Phase 4: HTTP/HTTPS Service Probing & Takeover Detection ({domain})"
                )
            print_info(
                f"Probing {len(discovered_hosts)} host(s) on ports 80 & 443 "
                f"(AsyncIO httpx, concurrency={args.threads}, timeout={args.timeout}s)..."
            )
            http_res: HttpProberResult = probe_subdomains(
                subdomains=discovered_hosts,
                concurrency=args.threads,
                timeout=args.timeout,
            )
            full_report["http_probes"] = http_res.to_dict()
            if not args.json:
                http_res.print_summary()

        # Phase 5: Output and Export
        if args.output:
            out_file = args.output
            if out_file.lower().endswith(".csv") and "subdomains" in full_report:
                export_subdomains_to_csv(full_report["subdomains"]["subdomains"], out_file)
                if not args.json:
                    print_success(f"Subdomain records exported to CSV: '{out_file}'")
            else:
                export_to_json(full_report, out_file)
                if not args.json:
                    print_success(f"Full reconnaissance report saved to JSON: '{out_file}'")

        if args.json:
            import json

            print(json.dumps(full_report, indent=2))

        if not args.json:
            print(
                f"\n{Colors.GREEN}{Colors.BOLD}[*] Reconnaissance complete for '{domain}'.{Colors.RESET}\n"
            )

        return 0

    except KeyboardInterrupt:
        print_warning("\nOperation aborted by user (KeyboardInterrupt / Ctrl+C).")
        return 130
    except Exception as err:
        print_error(f"Critical execution error: {err}")
        return 1
