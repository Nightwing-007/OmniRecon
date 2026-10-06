"""
Utility Module for Recon Toolkit.

Provides cross-platform ANSI color helpers, domain normalization and validation,
formatted console output banners, and export utilities (JSON / CSV / TXT).
"""

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# ============================================================================
# Cross-Platform ANSI Color Formatting
# ============================================================================
# Windows 10/11 Command Prompt & PowerShell support ANSI escape codes once
# virtual terminal processing is enabled. Reconfigure stdout to UTF-8 to prevent charmap errors.
if sys.platform.startswith("win"):
    os.system("")
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Check if color output is disabled via standard environment variable
# (see https://no-color.org) or non-interactive terminal pipe
NO_COLOR = bool(os.getenv("NO_COLOR")) or not sys.stdout.isatty()


class Colors:
    """ANSI color codes for formatted terminal output."""

    RESET = "" if NO_COLOR else "\033[0m"
    BOLD = "" if NO_COLOR else "\033[1m"
    DIM = "" if NO_COLOR else "\033[2m"
    UNDERLINE = "" if NO_COLOR else "\033[4m"

    # Standard foreground colors
    RED = "" if NO_COLOR else "\033[91m"
    GREEN = "" if NO_COLOR else "\033[92m"
    YELLOW = "" if NO_COLOR else "\033[93m"
    BLUE = "" if NO_COLOR else "\033[94m"
    MAGENTA = "" if NO_COLOR else "\033[95m"
    CYAN = "" if NO_COLOR else "\033[96m"
    WHITE = "" if NO_COLOR else "\033[97m"


def print_banner() -> None:
    """Print the toolkit ASCII banner and version metadata."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
  ____  _____ ____ ___  _   _   _____ ___   ___  _     _  _______ _____ 
 |  _ \\| ____/ ___/ _ \\| \\ | | |_   _/ _ \\ / _ \\| |   | |/ /_   _|_   _|
 | |_) |  _|| |  | | | |  \\| |   | || | | | | | | |   | ' /  | |   | |  
 |  _ <| |__| |__| |_| | |\\  |   | || |_| | |_| | |___| . \\  | |   | |  
 |_| \\_\\_____\\____\\___/|_| \\_|   |_| \\___/ \\___/|_____|_|\\_\\ |_|   |_|  
 {Colors.YELLOW}WHOIS * DNS Records * Subdomain Enumeration Toolkit v1.0.0{Colors.RESET}
 {Colors.DIM}Reconnaissance & External Attack Surface Footprinting{Colors.RESET}
"""
    print(banner)


def print_section(title: str) -> None:
    """Print a visually distinct section divider header."""
    separator = "=" * 70
    print(f"\n{Colors.BLUE}{Colors.BOLD}{separator}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}[*] {title.upper()}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{separator}{Colors.RESET}")


def print_info(msg: str) -> None:
    """Print an informational status message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def print_success(msg: str) -> None:
    """Print a success confirmation message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    """Print a warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_error(msg: str) -> None:
    """Print an error alert message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


# ============================================================================
# Domain Normalization and RFC Syntax Validation
# ============================================================================
# RFC 1035 / 1123 domain syntax rules:
# - Labels are separated by dots.
# - Each label is 1 to 63 characters long.
# - Labels consist of alphanumeric characters and hyphens, but cannot start/end with a hyphen.
# - Total domain length cannot exceed 253 characters.
# - Must contain at least one dot separating the second-level domain and TLD.
DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def normalize_domain(raw_input: str) -> str:
    """
    Clean and sanitize raw domain user input.

    Handles common user input variations:
      - Strips protocol prefixes: 'http://', 'https://'
      - Strips trailing slashes and paths: '/path/index.html'
      - Strips port numbers: ':8080'
      - Strips query strings: '?foo=bar'
      - Strips surrounding whitespace
      - Converts domain to lowercase

    Args:
        raw_input: Raw string input from CLI or configuration.

    Returns:
        Cleaned domain string (e.g. 'example.com').
    """
    if not raw_input:
        return ""

    cleaned = raw_input.strip()

    # Prepend scheme if missing so urllib.parse can reliably isolate the netloc
    if "://" not in cleaned:
        # If it starts with '//', strip it
        cleaned = cleaned.lstrip("/")
        cleaned = "http://" + cleaned

    parsed = urlparse(cleaned)
    domain = parsed.netloc or parsed.path

    # Extract hostname part in case a port exists (e.g. 'example.com:443')
    if ":" in domain:
        domain = domain.split(":")[0]

    # Remove any stray path elements, trailing dots, or slashes
    domain = domain.split("/")[0].strip(".").strip().lower()

    return domain


def is_valid_domain(domain: str) -> bool:
    """
    Validate whether a normalized domain conforms to RFC 1035/1123 domain specifications.

    Args:
        domain: Cleaned domain string.

    Returns:
        True if the domain is structurally valid, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain))


# ============================================================================
# Export Helpers (JSON / CSV / TXT)
# ============================================================================
def export_to_json(data: Dict[str, Any], filepath: str) -> None:
    """
    Export collected reconnaissance results to a formatted JSON file.

    Serializes datetime objects and sets to standard ISO-8601 strings and lists.

    Args:
        data: Reconnaissance results dictionary.
        filepath: Destination file path.
    """

    def json_default_serializer(obj: Any) -> Any:
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return str(obj)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=json_default_serializer)


def export_subdomains_to_csv(subdomains: List[Dict[str, Any]], filepath: str) -> None:
    """
    Export discovered subdomains and their resolved IP addresses to a CSV file.

    Args:
        subdomains: List of dicts with keys 'subdomain', 'ip_addresses', 'sources'.
        filepath: Destination file path.
    """
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "IP_Addresses", "Sources"])
        for entry in subdomains:
            ips = "; ".join(entry.get("ip_addresses", []))
            sources = "; ".join(entry.get("sources", []))
            writer.writerow([entry.get("subdomain", ""), ips, sources])
