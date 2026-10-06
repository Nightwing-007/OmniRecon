"""
WHOIS Enumeration Module for Recon Toolkit.

Performs WHOIS queries to extract domain registration data, registrar info,
creation and expiration dates, authoritative nameservers, and administrative contacts.

Under the Hood:
- WHOIS is an application-layer query/response protocol (RFC 3912) operating on
  TCP port 43.
- When querying a domain, the client contacts the relevant Top-Level Domain (TLD)
  registry (e.g., whois.verisign-grs.com for .com), which often redirects or refers
  to the registrar's WHOIS server (thin vs. thick WHOIS model).
- Modern WHOIS responses frequently redact contact details due to privacy laws
  (such as GDPR/ICANN Temporary Specification) and proxy services (e.g. Privacy Protect).
- This module handles rate limiting, timeouts, missing fields, and date format variations.
"""

from dataclasses import dataclass, field
from datetime import datetime
import socket
from typing import Any, Dict, List, Optional, Union

import requests
import whois

try:
    from whois.exceptions import (
        PywhoisError,
        WhoisDomainNotFoundError,
        WhoisQuotaExceededError,
    )
except ImportError:
    try:
        from whois.parser import PywhoisError

        WhoisDomainNotFoundError = PywhoisError
        WhoisQuotaExceededError = PywhoisError
    except ImportError:
        PywhoisError = Exception
        WhoisDomainNotFoundError = Exception
        WhoisQuotaExceededError = Exception

from .utils import Colors, print_error, print_info, print_warning


@dataclass
class WhoisResult:
    """
    Structured representation of parsed WHOIS registry data.

    Attributes:
        domain: The domain name queried.
        registrar: Organization or entity through which the domain was registered.
        whois_server: The WHOIS server that served the record.
        creation_date: Original domain creation date(s).
        expiration_date: Expiration date(s) of current domain lease.
        updated_date: Date(s) of most recent record update.
        name_servers: Authoritative name servers listed at the registrar level.
        status: EPP domain status codes (e.g., clientTransferProhibited).
        registrant_name: Name of domain registrant (often redacted by privacy proxy).
        registrant_org: Organization owning the registration.
        emails: Contact emails found in the record.
        country: Country code of registrant.
        dnssec: DNSSEC validation status (signed or unsigned).
        raw_text: Raw WHOIS response text (if needed for forensic review).
        is_registered: Boolean indicating if the domain is registered.
        error: Error message string if lookup failed.
    """

    domain: str
    registrar: Optional[str] = None
    whois_server: Optional[str] = None
    creation_date: Optional[Union[str, List[str]]] = None
    expiration_date: Optional[Union[str, List[str]]] = None
    updated_date: Optional[Union[str, List[str]]] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    emails: List[str] = field(default_factory=list)
    country: Optional[str] = None
    dnssec: Optional[str] = None
    raw_text: Optional[str] = None
    is_registered: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result into a clean, JSON-serializable dictionary."""
        return {
            "domain": self.domain,
            "is_registered": self.is_registered,
            "registrar": self.registrar,
            "whois_server": self.whois_server,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "status": self.status,
            "registrant_name": self.registrant_name,
            "registrant_org": self.registrant_org,
            "emails": self.emails,
            "country": self.country,
            "dnssec": self.dnssec,
            "error": self.error,
        }

    def print_summary(self) -> None:
        """Render a formatted, user-friendly terminal report of the WHOIS data."""
        if self.error:
            print_error(f"WHOIS Lookup Failed: {self.error}")
            return

        if not self.is_registered:
            print_warning(
                f"Domain '{self.domain}' appears to be UNREGISTERED or no WHOIS record was found."
            )
            return

        def _fmt(val: Any) -> str:
            if val is None or val == "" or val == []:
                return f"{Colors.DIM}N/A (Redacted or Not Provided){Colors.RESET}"
            if isinstance(val, list):
                return ", ".join(str(item) for item in val)
            return str(val)

        print(f"  {Colors.BOLD}Domain Name:{Colors.RESET}       {self.domain}")
        print(f"  {Colors.BOLD}Registrar:{Colors.RESET}         {_fmt(self.registrar)}")
        print(f"  {Colors.BOLD}WHOIS Server:{Colors.RESET}      {_fmt(self.whois_server)}")
        print(f"  {Colors.BOLD}Creation Date:{Colors.RESET}     {_fmt(self.creation_date)}")
        print(f"  {Colors.BOLD}Expiration Date:{Colors.RESET}   {_fmt(self.expiration_date)}")
        print(f"  {Colors.BOLD}Updated Date:{Colors.RESET}      {_fmt(self.updated_date)}")
        print(f"  {Colors.BOLD}Registrant Org:{Colors.RESET}    {_fmt(self.registrant_org)}")
        print(f"  {Colors.BOLD}Registrant Name:{Colors.RESET}   {_fmt(self.registrant_name)}")
        print(f"  {Colors.BOLD}Country:{Colors.RESET}           {_fmt(self.country)}")
        print(f"  {Colors.BOLD}Contact Emails:{Colors.RESET}    {_fmt(self.emails)}")
        print(f"  {Colors.BOLD}DNSSEC:{Colors.RESET}            {_fmt(self.dnssec)}")

        print(f"\n  {Colors.BOLD}Authoritative Name Servers:{Colors.RESET}")
        if self.name_servers:
            for ns in self.name_servers:
                print(f"    - {Colors.CYAN}{ns.lower()}{Colors.RESET}")
        else:
            print(f"    {Colors.DIM}No name servers discovered in WHOIS response.{Colors.RESET}")

        print(f"\n  {Colors.BOLD}Domain Status Codes (EPP):{Colors.RESET}")
        if self.status:
            for st in self.status:
                print(f"    - {Colors.YELLOW}{st}{Colors.RESET}")
        else:
            print(f"    {Colors.DIM}No EPP status codes reported.{Colors.RESET}")


def _normalize_date_value(val: Any) -> Optional[Union[str, List[str]]]:
    """
    Format datetime objects into ISO 8601 strings.

    python-whois frequently returns either a single datetime object, a string,
    or a list of datetime objects (e.g. multiple registries returning dates).
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(val, list):
        formatted = []
        for item in val:
            if isinstance(item, datetime):
                formatted.append(item.strftime("%Y-%m-%d %H:%M:%S UTC"))
            elif item:
                formatted.append(str(item))
        # Deduplicate and return clean list or first item if duplicates
        deduped = sorted(list(set(formatted)))
        return deduped if len(deduped) > 1 else (deduped[0] if deduped else None)
    return str(val)


def _normalize_list_value(val: Any) -> List[str]:
    """Ensure multi-value fields (name servers, emails, status) are clean lists of strings."""
    if val is None:
        return []
    if isinstance(val, (list, set, tuple)):
        clean = []
        for item in val:
            if item:
                # Strip spaces and normalize lowercase
                clean.append(str(item).strip())
        return sorted(list(set(clean)))
    return [str(val).strip()]


def _lookup_rdap_fallback(domain: str, timeout: int = 8) -> Optional[WhoisResult]:
    """
    Fallback query using RDAP (Registration Data Access Protocol - RFC 7482/7484) over HTTPS.

    Used automatically when legacy WHOIS TCP port 43 is blocked by a local network
    firewall, times out, or fails to respond.
    """
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 ReconToolkit/1.0"},
            timeout=timeout,
        )

        if resp.status_code == 404:
            return WhoisResult(
                domain=domain,
                is_registered=False,
                error="Domain not registered (RDAP 404 Not Found).",
            )

        if resp.status_code != 200:
            return None

        data = resp.json()

        # Parse event dates
        creation_date = None
        expiration_date = None
        updated_date = None
        for evt in data.get("events", []):
            action = evt.get("eventAction", "")
            edate = evt.get("eventDate", "")
            if action == "registration":
                creation_date = edate
            elif action == "expiration":
                expiration_date = edate
            elif action == "last changed":
                updated_date = edate

        # Parse authoritative name servers
        name_servers = []
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                name_servers.append(ns_name.lower())

        # Parse domain status codes
        status = data.get("status", [])

        # Parse entities (registrar, registrant, contacts)
        registrar = None
        registrant_name = None
        registrant_org = None
        emails = []

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])
            fn = None
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4:
                        prop_name = item[0]
                        prop_val = item[3]
                        if prop_name == "fn" and prop_val:
                            fn = prop_val
                        elif prop_name == "email" and prop_val:
                            emails.append(prop_val)

            if "registrar" in roles:
                registrar = fn or entity.get("handle")
            elif "registrant" in roles:
                registrant_name = fn
                registrant_org = fn

        dnssec = "signed" if data.get("secureDNS", {}).get("delegationSigned") else "unsigned"

        return WhoisResult(
            domain=domain,
            registrar=registrar,
            whois_server="RDAP Gateway (HTTPS port 443)",
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            name_servers=name_servers,
            status=status,
            registrant_name=registrant_name,
            registrant_org=registrant_org,
            emails=emails,
            country=None,
            dnssec=dnssec,
            is_registered=True,
            error=None,
        )
    except Exception:
        return None


def lookup_whois(domain: str, timeout: int = 10) -> WhoisResult:
    """
    Query the WHOIS database for domain registration details.

    Handles network timeouts, unrecognized TLDs, connection resets, and parsing errors.
    Automatically falls back to RDAP over HTTPS if port 43 is blocked or times out.

    Args:
        domain: Target domain name (e.g., 'example.com').
        timeout: Socket timeout in seconds for WHOIS query.

    Returns:
        WhoisResult dataclass instance populated with parsed fields or error details.
    """
    print_info(
        f"Initiating WHOIS query for '{Colors.BOLD}{domain}{Colors.RESET}' (timeout={timeout}s)..."
    )

    # Set default socket timeout so blocked port 43 won't hang the tool indefinitely
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        # Perform WHOIS lookup via python-whois (TCP port 43)
        query_response = whois.whois(domain)

        # In cases where the domain does not exist, python-whois may return an empty object
        # or an object where domain_name is None
        if not query_response or not query_response.domain_name:
            # Check if raw text indicates an unregistered domain
            text = getattr(query_response, "text", "") or ""
            if "no match" in text.lower() or "not found" in text.lower():
                return WhoisResult(
                    domain=domain,
                    is_registered=False,
                    error="Domain not found in registry (unregistered).",
                )
            # Try RDAP fallback before giving up
            rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
            if rdap_res:
                print_warning("Standard WHOIS port 43 returned empty; fallback to RDAP succeeded.")
                return rdap_res
            return WhoisResult(
                domain=domain,
                is_registered=False,
                error="No registration records returned by WHOIS server.",
            )

        # Extract and normalize fields
        registrar = query_response.get("registrar")
        whois_server = query_response.get("whois_server")
        creation_date = _normalize_date_value(query_response.get("creation_date"))
        expiration_date = _normalize_date_value(query_response.get("expiration_date"))
        updated_date = _normalize_date_value(query_response.get("updated_date"))
        name_servers = _normalize_list_value(query_response.get("name_servers"))
        status = _normalize_list_value(query_response.get("status"))
        registrant_name = query_response.get("name")
        registrant_org = query_response.get("org")
        emails = _normalize_list_value(query_response.get("emails"))
        country = query_response.get("country")
        dnssec = query_response.get("dnssec")
        raw_text = query_response.get("text")

        return WhoisResult(
            domain=domain,
            registrar=registrar,
            whois_server=whois_server,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            name_servers=name_servers,
            status=status,
            registrant_name=registrant_name,
            registrant_org=registrant_org,
            emails=emails,
            country=country,
            dnssec=str(dnssec) if dnssec else None,
            raw_text=raw_text,
            is_registered=True,
            error=None,
        )

    except WhoisDomainNotFoundError:
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error="Domain not registered (WhoisDomainNotFoundError).",
        )

    except WhoisQuotaExceededError:
        # If WHOIS server quota is exceeded, try RDAP over HTTPS
        rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
        if rdap_res:
            print_warning(
                "WHOIS port 43 quota exceeded; recovered registration records via RDAP (HTTPS 443)."
            )
            return rdap_res
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error="WHOIS server query quota exceeded (rate limited by registry).",
        )

    except (PywhoisError, whois.WhoisError) as err:
        err_msg = str(err)
        if "no match" in err_msg.lower() or "not found" in err_msg.lower():
            return WhoisResult(
                domain=domain,
                is_registered=False,
                error="Domain not registered (No match found in WHOIS registry).",
            )
        # Try RDAP fallback for parsing errors
        rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
        if rdap_res:
            print_warning(
                "WHOIS port 43 parser error; recovered registration records via RDAP (HTTPS 443)."
            )
            return rdap_res
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error=f"WHOIS Parsing Error: {err_msg}",
        )

    except (socket.timeout, TimeoutError):
        # Port 43 timed out (frequent in firewalled networks); attempt RDAP over HTTPS port 443
        rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
        if rdap_res:
            print_warning(
                "WHOIS port 43 timed out/firewalled; recovered registration records via RDAP (HTTPS 443)."
            )
            return rdap_res
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error=f"Connection timed out while contacting WHOIS server for '{domain}' on port 43 (and RDAP fallback unavailable).",
        )

    except (socket.error, ConnectionResetError, OSError) as err:
        # Socket error connecting to port 43; attempt RDAP over HTTPS port 443
        rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
        if rdap_res:
            print_warning(
                "WHOIS port 43 socket connection blocked; recovered registration records via RDAP (HTTPS 443)."
            )
            return rdap_res
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error=f"Network/Socket error connecting to WHOIS server: {err}",
        )

    except Exception as err:
        rdap_res = _lookup_rdap_fallback(domain, timeout=timeout)
        if rdap_res:
            print_warning(
                "WHOIS query encountered an unexpected error; recovered registration records via RDAP."
            )
            return rdap_res
        return WhoisResult(
            domain=domain,
            is_registered=False,
            error=f"Unexpected error querying WHOIS for '{domain}': {err}",
        )

    finally:
        # Restore the original default socket timeout
        socket.setdefaulttimeout(original_timeout)
