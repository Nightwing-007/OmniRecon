# Recon Toolkit: WHOIS, DNS & Subdomain Enumeration Suite (with AsyncIO & HTTP Prober)

A high-performance, modular reconnaissance and external attack surface footprinting toolkit written in Python. Built for security engineers, penetration testers, and bug bounty researchers.

Powered by an asynchronous **AsyncIO engine (`aiodns`)** and an **asynchronous HTTP/HTTPS web service prober (`httpx`)** with automated **Subdomain Takeover** detection.

---

## 1. Concept Introduction (The Fundamentals)

To effectively perform security footprinting, you must understand the underlying networking primitives that power the Internet. The following concepts build on each other in strict chronological order: from how computers address each other to discovering vulnerable cloud assets during reconnaissance.

```
+-------------------------------------------------------------------------------------------------------+
|                                    THE RECONNAISSANCE LIFECYCLE                                       |
|                                                                                                       |
|  [1. IP & Domains] -> [2. DNS Hierarchy] -> [3. WHOIS Ownership] -> [4. Subdomains] -> [5. Probing]  |
|   (Addressing)        (Name Resolution)      (Legal & Infra)      (Attack Surface)     (Live Services)|
+-------------------------------------------------------------------------------------------------------+
```

### Step 1: IP Addresses and Domain Names (How Computers Find Each Other)
At the lowest networking layer of the Internet (Layer 3 of the OSI model), computers do not understand names like `google.com` or `github.com`. Instead, machines route packets using **IP (Internet Protocol) Addresses**:
* **IPv4 (32-bit):** e.g., `142.250.190.46` (approximately 4.3 billion possible addresses).
* **IPv6 (128-bit):** e.g., `2607:f8b0:4005:805::200e` (virtually inexhaustible address space).

Because humans struggle to memorize numeric strings, the **Domain Name System (DNS)** was created in 1983 (RFC 882/883, updated in RFC 1034/1035) as a decentralized, hierarchical phonebook translating human-friendly names (domains) into machine-routable IP addresses.

---

### Step 2: The Domain Name System (DNS) & Record Types
When you enter a domain into a browser or terminal, your system initiates a **recursive DNS resolution process**:

1. **DNS Stub Resolver (Your Machine):** Checks local DNS cache and `hosts` file. If not cached, forwards the query to a Recursive Resolver (e.g., your ISP, Cloudflare `1.1.1.1`, or Google `8.8.8.8`).
2. **Root Nameservers (`.`):** Thirteen global clusters of root servers direct the recursive resolver to the authoritative Top-Level Domain (TLD) servers.
3. **TLD Nameservers (`.com`, `.org`, `.io`):** Direct the resolver to the specific authoritative nameservers for that domain.
4. **Authoritative Nameservers (`ns1.example.com`):** Hold the official master zone records and return the final answer.

```
       +--------------------+
       |  User Application  |
       +---------+----------+
                 |
                 v
       +--------------------+
       | Recursive Resolver | <---+ (e.g. 1.1.1.1 / 8.8.8.8)
       +----+-----+-----+---+
            |     |     |
      1.    | 2.  | 3.  |
      Root  | TLD | Auth|
      (.)   |(.com| Server (ns1.example.com)
            v     v     v
```

#### Core DNS Record Types Queried by This Toolkit:
* **`A` (Address Record):** Maps a hostname to a 32-bit IPv4 address (e.g., `example.com` -> `93.184.216.34`).
* **`AAAA` (IPv6 Address Record):** Maps a hostname to a 128-bit IPv6 address (e.g., `2606:2800:220:1:248:1893:25c8:1946`).
* **`MX` (Mail Exchange Record):** Designates mail transfer agents (MTAs) responsible for receiving email on behalf of the domain, accompanied by priority preferences (lower number = higher priority).
* **`TXT` (Text Record):** Stores human and machine-readable text. Security teams inspect TXT records for:
  * **SPF (`v=spf1 ...`):** Sender Policy Framework, prevents email spoofing.
  * **DMARC (`v=DMARC1 ...`):** Defines authentication reporting and policy enforcement.
  * **Third-Party Verifications:** Google Site Verification, GitHub Domain Verification, Microsoft 365, etc.
* **`NS` (Name Server Record):** Lists authoritative nameservers with jurisdiction over the DNS zone (crucial for finding secondary DNS servers or identifying cloud DNS hosting).
* **`CNAME` (Canonical Name Record):** Alias pointing one hostname to another (e.g., `www.example.com` -> `example.com` or cloud CDN endpoints).
* **`SOA` (Start of Authority Record):** Core metadata for the zone, including primary nameserver, administrator email, serial number, and zone transfer timers.

---

### Step 3: Domain Ownership & The WHOIS Protocol
Before a domain can have DNS records, an individual or organization must purchase and register the domain with an **ICANN-accredited registrar** (e.g., GoDaddy, Namecheap, Google Domains).

* **The WHOIS Protocol (RFC 3912):** Created in the 1980s, WHOIS is a plaintext transaction-oriented query protocol operating over **TCP port 43**. It returns registry data:
  * Registrar Name and IANA ID.
  * Creation Date, Expiration Date, and Last Updated Timestamp.
  * Registrar-level Authoritative Name Servers.
  * Registrant Organization, Contact Emails, Physical Address, and Phone Number.
  * EPP Domain Status Codes (`clientTransferProhibited`, `clientHold`).
* **Modern Privacy & RDAP:** Due to privacy regulations (such as GDPR) and proxy services (WhoisGuard, Domains By Proxy), personal information is frequently redacted. The **Registration Data Access Protocol (RDAP)** (RFC 7480-7484) is ICANN's RESTful HTTPS replacement for WHOIS. *This toolkit queries traditional WHOIS over TCP port 43 and automatically fails over to RDAP over HTTPS port 443 if port 43 is firewalled.*

---

### Step 4: The External Attack Surface & Subdomains
Organizations rarely operate on a single apex domain (`example.com`). Large enterprises manage hundreds or thousands of **subdomains** (`api.example.com`, `vpn.example.com`, `dev.staging.example.com`).

* Subdomains partition infrastructure across multiple microservices, staging environments, internal administration consoles, and third-party SaaS vendors.
* **The Security Threat:** Legacy, unmonitored, or forgotten subdomains often host unpatched software, exposed database consoles, or misconfigured cloud buckets.

---

### Step 5: Subdomain Enumeration (Passive CT vs Active AsyncIO)
Subdomain discovery is split into two complementary paradigms:

#### A. Passive Enumeration (Certificate Transparency)
* **How it works:** Under RFC 6962, Certificate Authorities (CAs) like Let's Encrypt, DigiCert, and Sectigo must append every issued SSL/TLS certificate to public, append-only cryptographic audit logs called **Certificate Transparency (CT) logs**.
* **Recon Advantage:** By querying search engines like **crt.sh**, we discover historical and active hostnames that ever possessed an SSL certificate.
* **Zero Network Footprint:** Passive enumeration sends **zero packets** to the target organization's nameservers or servers.

#### B. Active Enumeration (High-Concurrency AsyncIO Engine)
* **How it works:** We take a wordlist of high-probability subdomains (`admin`, `api`, `vpn`, `test`, `git`) and attempt to resolve `[word].[domain]` via DNS.
* **The AsyncIO Upgrade:** Instead of blocking operating system threads (`threading` / `ThreadPoolExecutor`), this toolkit uses **Python AsyncIO and `aiodns`** (powered by the C-ares asynchronous resolver library).
* **Connection Throttling (`asyncio.Semaphore`):** An asynchronous semaphore guarantees that the scanner never overwhelms system sockets or exhausts operating system file descriptors (preventing `EMFILE`/`ENFILE` crashes).
* **Wildcard DNS Handling:** If an administrator creates a wildcard record (`*.example.com A 192.0.2.1`), every candidate in a wordlist will resolve, resulting in hundreds of false positives. This toolkit automatically detects wildcard DNS asynchronously by probing random strings and filters out matching records.

---

### Step 6: HTTP/HTTPS Service Probing & Subdomain Takeover Detection
Finding an IP address is only half the battle. Security engineers need to know: **Is there a web application running on this host? What is it? Is it vulnerable?**

#### A. HTTP/HTTPS Service Probing
The toolkit takes all discovered subdomains and concurrently probes them across:
* **Port 80 (HTTP):** Standard unencrypted web traffic.
* **Port 443 (HTTPS):** Encrypted TLS web traffic (with self-signed SSL tolerance).
* **Information Harvested:** HTTP response status code (e.g. `200 OK`, `301 Redirect`, `403 Forbidden`, `404 Not Found`, `500 Server Error`), response headers, and the HTML `<title>` tag.

#### B. The Mechanics of Subdomain Takeover
Subdomain Takeover is a **high-severity external vulnerability** that occurs when a DNS record points to an abandoned or deleted third-party cloud service:

```
[ DNS Record ]  sub.company.com  CNAME  company-bucket.s3.amazonaws.com
                                                |
                                                v
[ Cloud Status ] AWS S3 Bucket "company-bucket" was DELETED by developer!
                                                |
                                                v
[ Vulnerability ] Attacker creates S3 bucket named "company-bucket" and now
                  serves arbitrary phishing or malicious content on sub.company.com!
```

* **Automated Detection:** The toolkit scans HTTP response bodies against signatures of unclaimed cloud services (e.g., AWS S3 `"NoSuchBucket"`, GitHub Pages `"There isn't a GitHub Pages site here"`, Heroku `"No such app"`, Shopify, Fastly, Azure, and more). If a signature is detected, it flags the endpoint as `[!] VULNERABLE`.

---

## 2. Project Overview

The **Recon Toolkit** is a self-contained, modular Python utility designed to automate domain footprinting:
* **WHOIS / RDAP Engine:** Queries domain registration records via TCP port 43 with seamless HTTPS fallback to RDAP when firewalls block port 43.
* **DNS Harvester:** Queries `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, and `SOA` records using `dnspython` resolvers.
* **AsyncIO Subdomain Discovery:** Uses `aiodns` and `asyncio.Semaphore` for asynchronous DNS brute-forcing combined with passive Certificate Transparency (crt.sh).
* **Wildcard DNS Immunity:** Probes the target zone before brute-forcing to identify wildcard fallbacks and eliminate false positives.
* **HTTP/HTTPS Service Prober:** Concurrently probes ports 80 & 443 using `httpx`, extracts HTML `<title>` strings, and checks for dangling cloud takeover signatures.
* **Export Flexibility:** Exports structured data to terminal, formatted JSON reports, or CSV spreadsheets.

---

## 3. Quick Start

### Prerequisites
* Python 3.9 or higher
* Internet connectivity

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-org/recon-toolkit.git
cd recon-toolkit
```

### Step 2: Create and Activate a Virtual Environment
```bash
# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# On Windows (Command Prompt):
python -m venv venv
venv\Scripts\activate.bat

# On Windows (PowerShell):
python -m venv venv
venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Your First Scan
```bash
python main.py example.com --all
```

---

## 4. Usage Examples & Terminal Output

### Example 1: Full Comprehensive Reconnaissance (`--all`)
Runs WHOIS lookup, core DNS record queries, AsyncIO subdomain enumeration, and HTTP/HTTPS service probing with takeover detection.

```bash
python main.py example.com --all
```

**Terminal Output:**
```text
  ____  _____ ____ ___  _   _   _____ ___   ___  _     _  _______ _____ 
 |  _ \| ____/ ___/ _ \| \ | | |_   _/ _ \ / _ \| |   | |/ /_   _|_   _|
 | |_) |  _|| |  | | | |  \| |   | || | | | | | | |   | ' /  | |   | |  
 |  _ <| |__| |__| |_| | |\  |   | || |_| | |_| | |___| . \  | |   | |  
 |_| \_\_____\____\___/|_| \_|   |_| \___/ \___/|_____|_|\_\ |_|   |_|  
 WHOIS * DNS Records * Subdomain Enumeration Toolkit v1.0.0
 Reconnaissance & External Attack Surface Footprinting

======================================================================
[*] PHASE 1: WHOIS REGISTRATION DATA (EXAMPLE.COM)
======================================================================
[*] Initiating WHOIS query for 'example.com' (timeout=3s)...
  Domain Name:       example.com
  Registrar:         RESERVED-Internet Assigned Numbers Authority
  WHOIS Server:      whois.iana.org
  Creation Date:     1995-08-14 04:00:00 UTC
  Expiration Date:   2027-08-13 04:00:00 UTC
  Updated Date:      2026-08-14 08:01:43 UTC
  Registrant Org:    Internet Assigned Numbers Authority
  Registrant Name:   Domain Administrator
  Country:           US
  Contact Emails:    abuse@iana.org
  DNSSEC:            signed

  Authoritative Name Servers:
    - elliott.ns.cloudflare.com
    - hera.ns.cloudflare.com

  Domain Status Codes (EPP):
    - client delete prohibited
    - client transfer prohibited
    - client update prohibited

======================================================================
[*] PHASE 2: CORE DNS RECORDS (EXAMPLE.COM)
======================================================================
[*] Querying DNS records for 'example.com' (A, AAAA, MX, TXT, NS, CNAME, SOA)...

  [A] Records:
    - 104.20.23.154 (TTL: 300s)
    - 172.66.147.243 (TTL: 300s)

  [AAAA] Records:
    - 2606:4700:10::6814:179a (TTL: 300s)
    - 2606:4700:10::ac42:93f3 (TTL: 300s)

  [MX] Records:
    - Priority: 0   Host: 

  [TXT] Records:
    - v=spf1 -all
    - _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9

  [NS] Records:
    - elliott.ns.cloudflare.com
    - hera.ns.cloudflare.com

  [CNAME] Records:
    (No CNAME records published)

  [SOA] Records:
    - Primary Master: elliott.ns.cloudflare.com, Admin Email: dns@cloudflare.com, Serial: 2415949263, Refresh: 10000s, Retry: 2400s, Expire: 604800s

======================================================================
[*] PHASE 3: SUBDOMAIN ENUMERATION [AIODNS] (EXAMPLE.COM)
======================================================================
[*] Testing target domain for Wildcard DNS (*.domain) configuration (async)...
[*] Querying Certificate Transparency logs via crt.sh for 'example.com'...
[*] Running active DNS brute-force (AsyncIO aiodns, concurrency=30) using 'subdomains_common.txt'...
[+] Active brute-force identified 1 resolving subdomains.
[*] Total Unique Subdomains Discovered: 1

  SUBDOMAIN                                     RESOLVED IP(S)                 SOURCE(S)
  --------------------------------------------- ------------------------------ ---------------
  www.example.com                               104.20.23.154, 172.66.147.243  Active (Wordlist)

======================================================================
[*] PHASE 4: HTTP/HTTPS SERVICE PROBING & TAKEOVER DETECTION (EXAMPLE.COM)
======================================================================
[*] Probing 2 host(s) on ports 80 & 443 (AsyncIO httpx, concurrency=30, timeout=3.0s)...
[*] HTTP Probing Complete: 4 live web endpoints discovered across 4 probed URLs.

  STATUS   URL                                    TITLE / ERROR                    TAKEOVER RISK
  -------- -------------------------------------- -------------------------------- ---------------
  [200]    http://example.com                     Example Domain                   None
  [200]    https://example.com                    Example Domain                   None
  [200]    http://www.example.com                 Example Domain                   None
  [200]    https://www.example.com                Example Domain                   None

[*] Reconnaissance complete for 'example.com'.
```

---

### Example 2: Subdomain Enumeration & HTTP Service Probing (`--probe`)
Discover subdomains and probe web services with custom semaphore concurrency (`-t 50`):

```bash
python main.py example.com --subdomains --probe -t 50
```

---

### Example 3: WHOIS Lookup Only (`--whois`)
Extract domain ownership metadata without generating DNS or HTTP traffic:

```bash
python main.py example.com --whois
```

---

### Example 4: Core DNS Records Query (`--dns`)
Query zone records including custom nameserver specification:

```bash
python main.py example.com --dns --nameservers "1.1.1.1,8.8.8.8"
```

---

### Example 5: High-Speed Async Brute-Forcing with Custom Wordlist
Execute aiodns brute-forcing using a custom wordlist:

```bash
python main.py example.com --subdomains --sub-mode wordlist -W wordlists/subdomains_common.txt -t 50
```

---

### Example 6: Export Complete Findings to JSON or CSV
Save the entire reconnaissance assessment (including WHOIS, DNS records, subdomains, and HTTP probe findings) to a JSON file:

```bash
# Save complete JSON scan report:
python main.py example.com --all -o scan_report.json

# Export subdomains to CSV:
python main.py example.com --subdomains -o subdomains.csv
```

---

## 5. Command Reference Table

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `domain` | — | Target domain name (e.g. `example.com` or `https://example.com`) | *Required* |
| `-a` | `--all` | Execute all modules: WHOIS, DNS, Subdomains, and HTTP Prober | `True` |
| `-w` | `--whois` | Execute WHOIS registry lookup only | `False` |
| | `--dns` | Query core DNS records only | `False` |
| `-s` | `--subdomains` | Execute Subdomain discovery only | `False` |
| `-p` | `--probe` | Concurrently probe subdomains on HTTP (80) & HTTPS (443) for status, title, and takeover risks | `False` |
| | `--sub-mode` | Subdomain mode: `both`, `passive`, or `wordlist` | `both` |
| `-W` | `--wordlist` | Path to custom subdomain wordlist | Bundled wordlist |
| `-t` | `--threads` | Max concurrency limit for AsyncIO Semaphore (DNS & HTTP probe concurrency) | `25` |
| | `--timeout` | Query timeout in seconds | `3.0` |
| | `--nameservers`| Comma-separated custom resolver IPs | System / Public resolvers |
| `-o` | `--output` | Destination file for JSON / CSV export | `None` |
| | `--json` | Output raw JSON to standard output (for piping) | `False` |
| | `--no-banner` | Suppress startup ASCII banner | `False` |

---

## 6. License & Disclaimer

**Disclaimer:** This toolkit was developed strictly for authorized educational research, defensive security assessments, and authorized penetration testing. Unauthorized scanning of third-party networks without explicit consent may violate local and international cyber laws.
