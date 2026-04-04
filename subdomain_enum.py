#!/usr/bin/env python3
"""
Subdomain enumerator for a target domain.
Sources: DNS zone transfer, DNS records (NS/MX/TXT/SRV), crt.sh, HackerTarget, brute-force.
"""

import sys
import signal
import socket
import argparse
import csv
import re
import ssl
import json
import time
import threading
import subprocess
import shutil
import itertools
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from functools import lru_cache

from utils import acquire_dns_token

import requests
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import urllib3

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── shared HTTP session with connection pooling ──────────────────────────────
_http_session = requests.Session()
_http_adapter = requests.adapters.HTTPAdapter(
    pool_connections=200, pool_maxsize=200, max_retries=1,
)
_http_session.mount("http://", _http_adapter)
_http_session.mount("https://", _http_adapter)
_http_session.max_redirects = 3

# ── thread-local DNS resolver + cached lookups ───────────────────────────────
_thread_local = threading.local()


def _get_resolver() -> dns.resolver.Resolver:
    if not hasattr(_thread_local, "resolver"):
        r = dns.resolver.Resolver()
        r.timeout = 3
        r.lifetime = 3
        _thread_local.resolver = r
    return _thread_local.resolver


@lru_cache(maxsize=10000)
def fast_resolve(hostname: str) -> str | None:
    try:
        acquire_dns_token()
        answers = _get_resolver().resolve(hostname, "A")
        return str(answers[0])
    except Exception:
        return None


@lru_cache(maxsize=10000)
def fast_reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def signal_handler(sig, frame):
    print("\n[!] Scan interrupted by user.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
_QUIET = False

# ── DNS enumeration ───────────────────────────────────────────────────────────

def get_nameservers(domain: str) -> list[str]:
    """Return the authoritative nameservers for a domain."""
    try:
        answers = _get_resolver().resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


def attempt_zone_transfer(domain: str, nameservers: list[str]) -> set[str]:
    """Try AXFR zone transfer against each nameserver."""
    found = set()
    for ns in nameservers:
        try:
            ns_ip = fast_resolve(ns)
            if not ns_ip:
                continue
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            for name in z.nodes.keys():
                host = str(name)
                if host == "@":
                    continue
                full = f"{host}.{domain}".lower()
                found.add(full)
            print(f"    [!] Zone transfer succeeded on {ns} — {len(found)} records leaked!")
        except dns.exception.FormError:
            pass  # AXFR refused (expected)
        except dns.resolver.NXDOMAIN:
            pass  # Expected for non-existent domains
        except Exception as e:
            print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")
    return found


def dns_records(domain: str) -> set[str]:
    """
    Extract subdomains from DNS record types:
      NS, MX, TXT (SPF includes), SRV common services.
    """
    found = set()
    resolver = _get_resolver()

    # NS records — nameservers are often subdomains
    try:
        for r in resolver.resolve(domain, "NS"):
            host = str(r.target).rstrip(".").lower()
            if host.endswith(f".{domain}"):
                found.add(host)
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")

    # MX records
    try:
        for r in resolver.resolve(domain, "MX"):
            host = str(r.exchange).rstrip(".").lower()
            if host.endswith(f".{domain}"):
                found.add(host)
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")

    # TXT records — SPF "include:" and "a:" can point to subdomains
    try:
        for r in resolver.resolve(domain, "TXT"):
            txt = b"".join(r.strings).decode(errors="ignore")
            for part in txt.split():
                for prefix in ("include:", "a:", "mx:", "ptr:"):
                    if part.startswith(prefix):
                        host = part[len(prefix):].strip().lower()
                        if host.endswith(f".{domain}"):
                            found.add(host)
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")

    # SRV records — all prefixes queried in parallel
    srv_prefixes = [
        "_http._tcp", "_https._tcp", "_ftp._tcp", "_smtp._tcp",
        "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
        "_submission._tcp", "_caldav._tcp", "_carddav._tcp",
        "_xmpp-client._tcp", "_xmpp-server._tcp", "_sip._tcp", "_sip._udp",
        "_sipfederationtls._tcp", "_autodiscover._tcp", "_ldap._tcp",
        "_kerberos._tcp", "_vpn._tcp",
    ]

    def _query_srv(prefix: str) -> list[str]:
        results = []
        try:
            for r in resolver.resolve(f"{prefix}.{domain}", "SRV"):
                h = str(r.target).rstrip(".").lower()
                if h.endswith(f".{domain}"):
                    results.append(h)
        except dns.resolver.NXDOMAIN:
            pass  # Expected for non-existent domains
        except Exception as e:
            print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")
        return results

    with ThreadPoolExecutor(max_workers=len(srv_prefixes)) as ex:
        for hosts in ex.map(_query_srv, srv_prefixes):
            found.update(hosts)

    return found


# ── passive sources ────────────────────────────────────────────────────────────

def fetch_crtsh(domain: str, timeout: float = 12.0) -> set[str]:
    """Query crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = _http_session.get(url, timeout=timeout)
        r.raise_for_status()
        entries = r.json()
        subs = set()
        for e in entries:
            for name in e.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}"):
                    subs.add(name.lower())
        return subs
    except Exception as ex:
        print(f"[!] crt.sh error: {ex}")
        return set()


def fetch_hackertarget(domain: str, timeout: float = 12.0) -> set[str]:
    """Query HackerTarget's free subdomain API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = _http_session.get(url, timeout=timeout)
        r.raise_for_status()
        subs = set()
        for line in r.text.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host.endswith(f".{domain}"):
                    subs.add(host)
        return subs
    except Exception as ex:
        print(f"[!] HackerTarget error: {ex}")
        return set()


def fetch_wayback(domain: str, max_results: int = 50_000, delay: float = 1.0,
                   timeout: float = 30.0, user_agent: str = "SubDomainScout/2.0") -> set[str]:
    """Query the Wayback Machine CDX API for subdomains.

    Streams text output line-by-line for memory efficiency.
    Handles 429 rate-limiting with exponential back-off.
    """
    found: set[str] = set()
    params = urllib.parse.urlencode({
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(max_results),
        "filter": "statuscode:200",
    })
    url = f"https://web.archive.org/cdx/search/cdx?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})

    time.sleep(delay)  # polite pause

    retries = 0
    max_retries = 3
    while retries <= max_retries:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as rsp:
                for raw_line in rsp:
                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    try:
                        parsed = urllib.parse.urlparse(line)
                        host = parsed.hostname
                        if host and host.lower().endswith(f".{domain}"):
                            found.add(host.lower())
                    except Exception:
                        continue
            break  # success
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = (2 ** retries) * 5
                print(f"[!] Wayback rate-limited, sleeping {wait}s...")
                time.sleep(wait)
                retries += 1
                continue
            print(f"[!] Wayback HTTP error: {e.code}")
            break
        except Exception as e:
            print(f"[!] Wayback error: {e}")
            break

    return found


def fetch_whois(domain: str) -> dict:
    """Return WHOIS data for a domain as a plain dict."""
    if not WHOIS_AVAILABLE:
        return {}
    try:
        w = whois_lib.whois(domain)
        def _first(val):
            """Return first item if list, else the value itself, as a string."""
            if isinstance(val, list):
                val = val[0] if val else None
            return str(val) if val is not None else ""
        ns = w.name_servers
        if isinstance(ns, (list, set)):
            ns = sorted({str(n).lower().rstrip(".") for n in ns if n})
        else:
            ns = [str(ns).lower().rstrip(".")] if ns else []
        return {
            "registrar":     _first(w.registrar),
            "creation_date": _first(w.creation_date),
            "expiry_date":   _first(w.expiration_date),
            "updated_date":  _first(w.updated_date),
            "name_servers":  ns,
            "status":        w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
            "emails":        w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
    except Exception:
        return {}


# ── Wildcard detection & permutation engine ────────────────────────────────────

def detect_wildcard(domain: str) -> str | None:
    """Probe for DNS wildcard: resolve a random label and return the IP if it exists.

    Returns the wildcard IP string, or None if no wildcard is configured.
    """
    import random
    import string
    random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test_host = f"{random_label}.{domain}"
    try:
        acquire_dns_token()
        answers = _get_resolver().resolve(test_host, "A")
        wildcard_ip = str(answers[0])
        return wildcard_ip
    except Exception:
        return None


def _is_valid_dns_label(label: str) -> bool:
    """RFC 1035 label validation: alphanumeric + hyphens, 1-63 chars, no leading/trailing hyphen."""
    return (
        0 < len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[A-Za-z0-9-]+", label) is not None
    )


def generate_permutations(found: set[str], domain: str,
                          max_perms: int = 10_000,
                          high_suffixes: list[str] | None = None,
                          low_suffixes: list[str] | None = None,
                          separators: list[str] | None = None) -> list[str]:
    """Generate smart subdomain permutations from discovered prefixes.

    Combines known prefixes with high/low-value suffixes (dev, prod, test, etc.)
    to find related subdomains. Deduplicates against `found` set and caps output.

    Returns a list of candidate FQDNs (not yet in `found`).
    """
    if high_suffixes is None:
        high_suffixes = ["dev", "prod", "test", "staging", "internal", "api", "admin"]
    if low_suffixes is None:
        low_suffixes = ["1", "2", "3", "old", "new"]
    if separators is None:
        separators = ["-", ""]

    # Extract single-label prefixes from already-found subdomains
    prefixes: set[str] = set()
    for fqdn in found:
        if not fqdn.endswith(f".{domain}"):
            continue
        prefix = fqdn[: -(len(domain) + 1)]
        if "." in prefix or not prefix:
            continue
        prefixes.add(prefix)

    candidates: list[str] = []
    seen: set[str] = set(found)
    count = 0

    for suffix_set in (high_suffixes, low_suffixes):
        for prefix, sep, suffix in itertools.product(prefixes, separators, suffix_set):
            if count >= max_perms:
                return candidates
            label = f"{prefix}{sep}{suffix}"
            fqdn = f"{label}.{domain}"
            if fqdn not in seen and _is_valid_dns_label(label):
                candidates.append(fqdn)
                seen.add(fqdn)
                count += 1

    # Also generate suffix-prefix combinations (e.g. "dev-mail" from prefix "mail")
    for suffix_set in (high_suffixes,):
        for suffix, sep, prefix in itertools.product(suffix_set, separators, prefixes):
            if count >= max_perms:
                return candidates
            label = f"{suffix}{sep}{prefix}"
            fqdn = f"{label}.{domain}"
            if fqdn not in seen and _is_valid_dns_label(label):
                candidates.append(fqdn)
                seen.add(fqdn)
                count += 1

    return candidates


# ── active DNS brute-force ─────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    # ── Core web ──────────────────────────────────────────────────────────────
    "www", "www2", "www3", "web", "website", "site",
    "m", "mobile", "wap", "touch",

    # ── API & services ────────────────────────────────────────────────────────
    "api", "api2", "api-v1", "api-v2", "api-v3", "apiv1", "apiv2",
    "apis", "api-gateway", "gateway", "gw",
    "graphql", "grpc", "rest", "soap", "rpc",
    "services", "service", "svc", "microservice",
    "backend", "server", "edge",
    "webhook", "webhooks", "callbacks",
    "partner-api", "partners", "partner",
    "broker", "queue", "events", "stream",

    # ── Environments ──────────────────────────────────────────────────────────
    "dev", "develop", "development",
    "staging", "stage", "stg",
    "test", "testing", "tst",
    "uat", "sit", "integration",
    "qa", "qat",
    "prod", "production",
    "beta", "alpha", "preview", "sandbox", "demo",
    "canary", "release",

    # ── Applications & portals ────────────────────────────────────────────────
    "app", "apps", "application",
    "portal", "my", "account", "accounts", "dashboard",
    "admin", "administrator", "management", "manage", "console",
    "panel", "control", "controlpanel", "cp",
    "backoffice", "back-office", "bo",
    "crm", "erp", "cms", "lms",
    "extranet", "intranet", "internal", "corp", "corporate",
    "hub", "platform",
    "customer", "client", "clients", "members", "member",
    "selfservice", "self-service",
    "agent", "agents", "broker-portal",

    # ── Authentication & identity ─────────────────────────────────────────────
    "auth", "authentication", "authorize",
    "login", "signin", "signup", "register",
    "sso", "saml", "oauth", "oidc",
    "id", "identity", "idp", "adfs", "ldap",
    "mfa", "2fa", "otp",
    "password", "reset",

    # ── CDN, static & media ───────────────────────────────────────────────────
    "cdn", "cdn1", "cdn2", "edge",
    "static", "assets", "asset",
    "media", "img", "images", "image",
    "video", "videos", "stream", "streaming", "live",
    "download", "downloads", "files", "docs-cdn",
    "fonts", "js", "css",
    "upload", "uploads",

    # ── Email & messaging ─────────────────────────────────────────────────────
    "mail", "mail2", "webmail", "email",
    "smtp", "smtps", "pop", "pop3", "imap", "imaps",
    "mx", "mx1", "mx2",
    "outlook", "exchange", "owa",
    "newsletter", "mailer", "notify", "notifications",
    "chat", "messaging", "teams",

    # ── Developer & DevOps ────────────────────────────────────────────────────
    "git", "gitlab", "github", "bitbucket", "svn",
    "ci", "cd", "cicd", "jenkins", "bamboo", "circleci",
    "build", "builds", "deploy", "deployment",
    "registry", "docker", "containers", "k8s", "kubernetes",
    "helm", "terraform", "ansible",
    "nexus", "artifactory", "packages",
    "sonar", "sonarqube",

    # ── Monitoring & observability ────────────────────────────────────────────
    "monitor", "monitoring",
    "grafana", "kibana", "elastic", "elasticsearch",
    "splunk", "datadog", "newrelic",
    "logs", "logging", "log",
    "metrics", "tracing", "trace",
    "status", "statuspage", "uptime", "health",
    "alerting", "alerts", "pagerduty",
    "apm",

    # ── Databases & storage ───────────────────────────────────────────────────
    "db", "db1", "db2", "database",
    "mysql", "postgres", "postgresql", "mssql",
    "redis", "memcache", "mongo", "mongodb", "cassandra",
    "s3", "storage", "blob", "files",
    "backup", "backups", "archive",
    "datalake", "warehouse", "bigquery",

    # ── Security ──────────────────────────────────────────────────────────────
    "vpn", "vpn1", "vpn2", "remote", "remotework",
    "secure", "ssl", "tls",
    "waf", "firewall", "proxy",
    "bastion", "jump",
    "vault", "secrets",
    "siem", "sentinel",

    # ── DNS & network infra ───────────────────────────────────────────────────
    "ns", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2",
    "ftp", "sftp", "ssh",
    "ntp", "sip", "voip",

    # ── E-commerce & payments ─────────────────────────────────────────────────
    "shop", "store", "ecommerce", "cart",
    "pay", "payment", "payments", "checkout",
    "billing", "invoice", "invoices", "finance",
    "claims", "quotes", "quote",
    "insurance", "policy", "policies",

    # ── Support & communication ───────────────────────────────────────────────
    "support", "helpdesk", "help",
    "servicedesk", "service-desk", "itsm",
    "jira", "confluence", "wiki", "kb", "knowledgebase",
    "zendesk", "freshdesk", "intercom",
    "chat", "live-chat", "livechat",
    "community", "forum",

    # ── Marketing & content ───────────────────────────────────────────────────
    "blog", "news", "press", "media-room",
    "marketing", "promo", "promotions",
    "landing", "campaigns", "campaign",
    "links", "go", "click", "track", "tracking",
    "analytics", "insights",

    # ── Hosting & control panels ──────────────────────────────────────────────
    "cpanel", "whm", "plesk", "directadmin", "direct",
    "hosting", "host",
]


def resolve(subdomain: str) -> tuple[str, str] | None:
    """Try to resolve a hostname; return (hostname, ip) or None."""
    ip = fast_resolve(subdomain)
    return (subdomain, ip) if ip else None


def brute_force(domain: str, wordlist: list[str], threads: int = 100) -> dict[str, str]:
    """Resolve candidates concurrently, return {host: ip} for live hosts."""
    candidates = [f"{w}.{domain}" for w in wordlist]
    found: dict[str, str] = {}
    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, c): c for c in candidates}
        for f in as_completed(futures):
            result = f.result()
            if result:
                host, ip = result
                found[host] = ip
                if not _QUIET:
                    print(f"  [+] {host:<48} {ip}")
    elapsed = max(time.time() - start, 0.001)
    rate = len(candidates) / elapsed
    print(f"[BRUTE] Stats: tested={len(candidates)} live={len(found)} rate~{rate:.1f}/s")
    return found


# ── IP enrichment ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=5000)
def get_ip_info(ip: str) -> dict:
    """Query ipinfo.io for ASN, CIDR, org, country."""
    if not ip or ip in ("?", ""):
        return {}
    try:
        r = _http_session.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data = r.json()
        return data
    except Exception:
        return {}


@lru_cache(maxsize=5000)
def get_shodan_internetdb(ip: str, timeout: float = 3.0) -> dict:
    """Query Shodan InternetDB for ports, tags, hostnames and CVEs."""
    if not ip or ip in ("?", ""):
        return {}
    try:
        r = _http_session.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {}
        return {
            "ip": data.get("ip", ip),
            "ports": data.get("ports", []) or [],
            "cpes": data.get("cpes", []) or [],
            "hostnames": data.get("hostnames", []) or [],
            "tags": data.get("tags", []) or [],
            "vulns": data.get("vulns", []) or [],
        }
    except Exception:
        return {}


# ── Lightweight port scanning ─────────────────────────────────────────────────

def nmap_scan_ips(ips: list[str], top_ports: int = 20, timeout: int = 30) -> dict[str, list[int]]:
    """Run a single nmap TCP-connect scan against multiple IPs.

    Returns {ip: [sorted open ports]}.  Returns {} if nmap is not installed
    or the scan fails for any reason.
    """
    if not ips:
        return {}
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return {}
    cmd = [
        nmap_path,
        "-sT",                          # TCP connect (no root needed)
        "--top-ports", str(top_ports),
        "-T4",                           # aggressive timing
        "--open",                        # only open ports
        "-oX", "-",                      # XML to stdout
        "--noninteractive",
    ] + ips
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode not in (0, 1):   # 1 = some hosts down, still valid
            return {}
        return _parse_nmap_xml(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {}


def _parse_nmap_xml(xml_str: str) -> dict[str, list[int]]:
    """Parse nmap -oX output into {ip: [open_port_numbers]}."""
    result: dict[str, list[int]] = {}
    try:
        root = ET.fromstring(xml_str)
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            ports = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        try:
                            ports.append(int(port_el.get("portid", 0)))
                        except ValueError:
                            continue
            if ports:
                result[ip] = sorted(ports)
    except ET.ParseError:
        pass
    return result


_COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 27017)


def _socket_scan_ip(ip: str, ports: tuple[int, ...] = _COMMON_PORTS,
                    timeout: float = 0.5) -> list[int]:
    """Quick TCP-connect scan using raw sockets (fallback when nmap is absent)."""
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (OSError, socket.timeout):
            continue
    return sorted(open_ports)


def check_ssh(ip: str, timeout: float = 1.5) -> str:
    """Try to grab SSH banner from port 22."""
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            banner = s.recv(128).decode(errors="ignore").strip()
            return banner.split("\n")[0] if banner else "open"
    except Exception:
        return ""


def resolve_ip(hostname: str) -> str:
    return fast_resolve(hostname) or ""


def reverse_dns(ip: str) -> str:
    return fast_reverse_dns(ip)


# ── DNSDumpster-style report ───────────────────────────────────────────────────

def fmt_ip_block(ip: str, info: dict, ssh: str = "") -> str:
    """Format one IP info block like DNSDumpster."""
    org   = info.get("org", "")          # e.g. "AS8075 MICROSOFT-CORP..."
    asn   = ""
    desc  = org
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        asn  = parts[0]
        desc = parts[1] if len(parts) > 1 else ""
    cidr    = info.get("network", info.get("ip", ip))  # fall back to plain ip
    country = info.get("country", "")
    city    = info.get("city", "")
    rdns    = reverse_dns(ip)

    lines = [f"  IP:      {ip}"]
    if rdns and rdns != ip:
        lines.append(f"  rDNS:    {rdns}")
    if asn:
        lines.append(f"  ASN:     {asn}")
    if desc:
        lines.append(f"  Org:     {desc}")
    if cidr:
        lines.append(f"  Network: {cidr}")
    loc = ", ".join(filter(None, [city, country]))
    if loc:
        lines.append(f"  Loc:     {loc}")
    if ssh:
        lines.append(f"  SSH:     {ssh}")
    return "\n".join(lines)


def print_dns_report(dns_data: dict) -> None:
    """Print MX/NS/TXT/SOA from already-collected dns_data — no re-querying."""

    # ── MX Records ────────────────────────────────────────────────────────────
    print(f"\n{'═'*70}")
    print("  MX Records")
    print(f"{'═'*70}")
    for r in dns_data.get("mx", []):
        print(f"\n  {r['pref']:<5} {r['host']}")
        if r["ip"]:
            info = {"org": f"{r['asn']} {r['asn_name']}".strip(),
                    "network": r["cidr"], "country": r["country"]}
            print(fmt_ip_block(r["ip"], info))
    if not dns_data.get("mx"):
        print("  (none)")

    # ── NS Records ────────────────────────────────────────────────────────────
    print(f"\n{'═'*70}")
    print("  NS Records")
    print(f"{'═'*70}")
    for r in dns_data.get("ns", []):
        print(f"\n  {r['host']}")
        if r["ip"]:
            info = {"org": f"{r['asn']} {r['asn_name']}".strip(),
                    "network": r["cidr"], "country": r["country"]}
            print(fmt_ip_block(r["ip"], info, r.get("ssh", "")))
    if not dns_data.get("ns"):
        print("  (none)")

    # ── TXT Records ───────────────────────────────────────────────────────────
    print(f"\n{'═'*70}")
    print("  TXT Records")
    print(f"{'═'*70}")
    for txt in dns_data.get("txt", []):
        print(f'\n  "{txt}"')
    if not dns_data.get("txt"):
        print("  (none)")

    # ── SOA Record ────────────────────────────────────────────────────────────
    print(f"\n{'═'*70}")
    print("  SOA Record")
    print(f"{'═'*70}")
    soa = dns_data.get("soa")
    if soa:
        print(f"\n  Primary NS : {soa['mname']}")
        print(f"  Hostmaster : {soa['rname']}")
        print(f"  Serial     : {soa['serial']}")
        print(f"  Refresh    : {soa['refresh']}s")
        print(f"  Retry      : {soa['retry']}s")
        print(f"  Expire     : {soa['expire']}s")
    else:
        print("  (none)")

    print(f"\n{'═'*70}\n")


# ── HTTP probing & tech detection ─────────────────────────────────────────────

TECH_PATTERNS = [
    # (header_or_body, pattern, label)
    ("server",          r"cloudfront",          "Amazon CloudFront"),
    ("server",          r"cloudflare",          "Cloudflare"),
    ("server",          r"apache",              "Apache HTTP Server"),
    ("server",          r"nginx",               "nginx"),
    ("server",          r"microsoft-iis",       "Microsoft IIS"),
    ("server",          r"litespeed",           "LiteSpeed"),
    ("server",          r"openresty",           "OpenResty"),
    ("server",          r"csw",                 "Campaign Monitor (csw)"),
    ("server",          r"snow_adc",            "ServiceNow ADC"),
    ("x-powered-by",    r"php",                 "PHP"),
    ("x-powered-by",    r"asp\.net",            "ASP.NET"),
    ("x-powered-by",    r"express",             "Express.js"),
    ("via",             r"cloudfront",          "Amazon CloudFront"),
    ("cf-ray",          r".",                   "Cloudflare"),
    ("x-amz-cf-id",     r".",                   "Amazon CloudFront"),
    ("x-azure-ref",     r".",                   "Microsoft Azure"),
    ("body",            r"jquery",              "jQuery"),
    ("body",            r"react",               "React"),
    ("body",            r"angular",             "Angular"),
    ("body",            r"vue\.js",             "Vue.js"),
    ("body",            r"wp-content",          "WordPress"),
    ("body",            r"shopify",             "Shopify"),
    ("body",            r"drupal",              "Drupal"),
    ("body",            r"joomla",              "Joomla"),
    ("body",            r"bootstrap",           "Bootstrap"),
    ("body",            r"amazon web services", "Amazon Web Services"),
    ("body",            r"azurewebsites",       "Microsoft Azure"),
    ("body",            r"amazonaws\.com",      "Amazon Web Services"),
]

def _get_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,120})", html, re.I)
    return m.group(1).strip() if m else ""


def _detect_tech(headers: dict, body: str) -> list[str]:
    found = []
    body_lower = body[:50000].lower()
    seen = set()
    for source, pattern, label in TECH_PATTERNS:
        if label in seen:
            continue
        if source == "body":
            if re.search(pattern, body_lower):
                found.append(label)
                seen.add(label)
        else:
            val = headers.get(source, "").lower()
            if val and re.search(pattern, val):
                found.append(label)
                seen.add(label)
    return found


def _probe_one(session: requests.Session, scheme: str, port: int,
               host: str, timeout: float) -> tuple[str, dict | None]:
    """Probe a single scheme/port, return (label, entry) or (label, None)."""
    label = scheme if port in (80, 443) else f"{scheme}{port}"
    url   = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    hdrs  = {"User-Agent": "Mozilla/5.0"}
    try:
        r      = session.get(url, timeout=timeout, headers=hdrs, verify=False,
                             allow_redirects=True)
        server = r.headers.get("server", "unknown server")
        title  = _get_title(r.text)
        tech   = _detect_tech(dict(r.headers), r.text)
        entry: dict = {"server": server}
        if title:
            entry["title"] = title[:80]
        if tech:
            entry["tech"] = tech
        return label, entry
    except requests.exceptions.SSLError:
        return label, {"server": "ssl-error"}
    except Exception:
        return label, None


def probe_http(host: str, timeout: float = 3.0) -> dict:
    """Probe HTTP and HTTPS on a host, return service info."""
    targets = [("https", 443), ("http", 80), ("http", 8080)]
    result  = {}
    for scheme, port in targets:
        label, entry = _probe_one(_http_session, scheme, port, host, timeout)
        if entry:
            result[label] = entry
    return result


def get_ssl_cert_info(host: str, timeout: float = 3.0) -> dict:
    """Return CN, O, and expiry info from the SSL cert of a host."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # Keep default CERT_REQUIRED so getpeercert() returns a populated dict.
        # CERT_NONE causes getpeercert() to return an empty dict with no subject.
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=timeout),
            server_hostname=host,
        ) as s:
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            result = {
                "cn": subject.get("commonName", ""),
                "o":  subject.get("organizationName", ""),
            }
            not_after = cert.get("notAfter")
            if not_after:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                days_remaining = (expiry_dt - now).days
                result["expires"] = expiry_dt.strftime("%Y-%m-%d")
                result["days_remaining"] = days_remaining
                if days_remaining < 0:
                    result["expiry_alert"] = "CRITICAL"
                    result["alert_label"]  = "EXPIRED"
                elif days_remaining <= 7:
                    result["expiry_alert"] = "CRITICAL"
                    result["alert_label"]  = "EXPIRES IN 7 DAYS"
                elif days_remaining <= 30:
                    result["expiry_alert"] = "HIGH"
                    result["alert_label"]  = "EXPIRES IN 30 DAYS"
                elif days_remaining <= 90:
                    result["expiry_alert"] = "MEDIUM"
                    result["alert_label"]  = "EXPIRES IN 90 DAYS"
                elif days_remaining <= 180:
                    result["expiry_alert"] = "LOW"
                    result["alert_label"]  = "EXPIRES IN 180 DAYS"
            return result
    except Exception:
        return {}


def collect_enrichment(
    resolved: dict[str, str],
    threads: int = 100,
    http_timeout: float = 3.0,
    ssl_timeout: float = 3.0,
    shodan_timeout: float = 3.0,
    do_http: bool = True,
    do_ssl: bool = True,
    do_rdns: bool = True,
    do_shodan: bool = True,
    do_ports: bool = True,
    nmap_top_ports: int = 20,
    enrich_limit: int = 0,
) -> dict[str, dict]:
    """Enrich all resolved hosts using a single flat thread pool.

    All sub-tasks (IP info, HTTP probe, SSL cert, rDNS) for every host are
    submitted directly — no nested executors, no per-host pool spin-up.
    Port scanning (nmap or socket fallback) runs in parallel with them.
    """
    items = sorted(resolved.items())
    if enrich_limit > 0:
        items = items[:enrich_limit]
    enriched: dict[str, dict] = {}

    # Kick off nmap in a background thread so it overlaps with enrichment
    unique_ips = list({ip for _, ip in items})
    nmap_executor = ThreadPoolExecutor(max_workers=1) if do_ports else None
    nmap_future = (nmap_executor.submit(nmap_scan_ips, unique_ips, nmap_top_ports)
                   if nmap_executor else None)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        f_info = {host: ex.submit(get_ip_info,        ip)   for host, ip in items}
        f_http = ({host: ex.submit(probe_http, host, http_timeout) for host, _ in items}
                  if do_http else {})
        f_ssl  = ({host: ex.submit(get_ssl_cert_info, host, ssl_timeout) for host, _ in items}
                  if do_ssl else {})
        f_rdns = ({host: ex.submit(reverse_dns, ip) for host, ip in items}
                  if do_rdns else {})
        f_shodan = ({host: ex.submit(get_shodan_internetdb, ip, shodan_timeout) for host, ip in items}
                    if do_shodan else {})

        # Collect nmap results (blocks only if nmap is slower than enrichment)
        nmap_results: dict[str, list[int]] = {}
        if nmap_future:
            try:
                nmap_results = nmap_future.result(timeout=35)
            except Exception:
                nmap_results = {}
            nmap_executor.shutdown(wait=False)

        # Socket fallback if nmap unavailable and returned nothing
        if do_ports and not nmap_results and not shutil.which("nmap"):
            sock_futures = {ip: ex.submit(_socket_scan_ip, ip) for ip in unique_ips}
            for ip, fut in sock_futures.items():
                try:
                    ports = fut.result()
                    if ports:
                        nmap_results[ip] = ports
                except Exception:
                    continue

        # Collect results inside the context so futures are guaranteed complete
        for host, ip in items:
            shodan_data = f_shodan[host].result() if do_shodan else {}
            ports = nmap_results.get(ip, [])
            if not ports and shodan_data.get("ports"):
                ports = shodan_data["ports"]
            enriched[host] = {
                "ip":   ip,
                "info": f_info[host].result(),
                "http": f_http[host].result() if do_http else {},
                "ssl":  f_ssl[host].result() if do_ssl else {},
                "rdns": f_rdns[host].result() if do_rdns else "",
                "shodan": shodan_data,
                "ports": ports,
            }
    return enriched


def _parse_org(info: dict) -> tuple[str, str]:
    org = info.get("org", "")
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    return "", org


def print_a_records(resolved: dict[str, str], enriched: dict[str, dict]) -> None:
    """Print A records section in DNSDumpster style."""
    print(f"\n{'═'*70}")
    print("  A Records (subdomains)")
    print(f"{'═'*70}")

    for host, ip in sorted(resolved.items()):
        d    = enriched.get(host, {})
        info = d.get("info", {})
        http = d.get("http", {})
        ssl  = d.get("ssl", {})
        rdns = d.get("rdns", "")
        shodan = d.get("shodan", {})
        asn, asn_name = _parse_org(info)

        print(f"\n  {host}")
        print(f"  IP     : {ip}")
        if rdns and rdns != ip:
            print(f"  rDNS   : {rdns}")
        if asn:
            print(f"  ASN    : {asn}")
        if asn_name:
            print(f"  Org    : {asn_name}")
        if info.get("network"):
            print(f"  CIDR   : {info['network']}")
        if info.get("country"):
            print(f"  Country: {info['country']}")
        for label, svc in http.items():
            line = f"  {label:<8}: {svc.get('server','')}"
            if svc.get("title"):
                line += f" | {svc['title']}"
            print(line)
            for t in svc.get("tech", []):
                print(f"           tech: {t}")
        if ssl.get("cn"):
            print(f"  SSL CN : {ssl['cn']}")
        if ssl.get("o"):
            print(f"  SSL O  : {ssl['o']}")
        if ssl.get("expires"):
            print(f"  SSL Exp: {ssl['expires']} ({ssl['days_remaining']}d remaining)")
        if ssl.get("alert_label"):
            print(f"  *** CERT ALERT: {ssl['alert_label']} ***")
        if shodan:
            if shodan.get("ports"):
                print(f"  Shodan : ports {', '.join(str(p) for p in shodan['ports'])}")
            if shodan.get("hostnames"):
                print(f"           hostnames: {', '.join(shodan['hostnames'][:3])}")
            if shodan.get("tags"):
                print(f"           tags: {', '.join(shodan['tags'][:5])}")
            if shodan.get("vulns"):
                print(f"           vulns: {', '.join(shodan['vulns'][:5])}")

    print(f"\n{'═'*70}\n")


# ── DNS record collection ──────────────────────────────────────────────────────

def _collect_mx_records(domain: str, resolver: dns.resolver.Resolver) -> list[dict]:
    mx_data: list[dict] = []
    try:
        mx_raw = sorted(resolver.resolve(domain, "MX"), key=lambda r: r.preference)
        hosts = [(r.preference, str(r.exchange).rstrip(".")) for r in mx_raw]
        with ThreadPoolExecutor(max_workers=10) as ex:
            ips = {h: ex.submit(resolve_ip, h) for _, h in hosts}
        with ThreadPoolExecutor(max_workers=10) as ex:
            infos = {h: ex.submit(get_ip_info, ips[h].result()) for _, h in hosts if ips[h].result()}
        for pref, host in hosts:
            ip = ips[host].result()
            info = infos[host].result() if host in infos else {}
            asn, asn_name = _parse_org(info)
            mx_data.append(
                {
                    "pref": pref,
                    "host": host,
                    "ip": ip,
                    "rdns": reverse_dns(ip) if ip else "",
                    "asn": asn,
                    "asn_name": asn_name,
                    "cidr": info.get("network", ""),
                    "country": info.get("country", ""),
                }
            )
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")
    return mx_data


def _collect_ns_records(domain: str, resolver: dns.resolver.Resolver) -> list[dict]:
    ns_data: list[dict] = []
    try:
        ns_raw = resolver.resolve(domain, "NS")
        hosts = [str(r.target).rstrip(".") for r in ns_raw]
        with ThreadPoolExecutor(max_workers=10) as ex:
            ips = {h: ex.submit(resolve_ip, h) for h in hosts}
        ip_results = {h: ips[h].result() for h in hosts}
        with ThreadPoolExecutor(max_workers=20) as ex:
            sshs = {h: ex.submit(check_ssh, ip_results[h]) for h in hosts if ip_results[h]}
            infos = {h: ex.submit(get_ip_info, ip_results[h]) for h in hosts if ip_results[h]}
        for host in hosts:
            ip = ip_results[host]
            info = infos[host].result() if host in infos else {}
            asn, asn_name = _parse_org(info)
            ns_data.append(
                {
                    "host": host,
                    "ip": ip,
                    "rdns": reverse_dns(ip) if ip else "",
                    "asn": asn,
                    "asn_name": asn_name,
                    "cidr": info.get("network", ""),
                    "country": info.get("country", ""),
                    "ssh": sshs[host].result() if host in sshs else "",
                }
            )
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")
    return ns_data


def _collect_txt_soa_records(domain: str, resolver: dns.resolver.Resolver) -> tuple[list[str], dict | None]:
    txt_data: list[str] = []
    soa_data: dict | None = None

    try:
        for r in resolver.resolve(domain, "TXT"):
            txt_data.append(b"".join(r.strings).decode(errors="ignore"))
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")

    try:
        soa = resolver.resolve(domain, "SOA")[0]
        soa_data = {
            "mname": str(soa.mname).rstrip("."),
            "rname": str(soa.rname).rstrip("."),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
        }
    except dns.resolver.NXDOMAIN:
        pass  # Expected for non-existent domains
    except Exception as e:
        print(f"[DEBUG] Minor error ignored: {type(e).__name__}: {e}")

    return txt_data, soa_data


def collect_dns_records(domain: str) -> dict:
    """Collect MX, NS, TXT, SOA records and enrich with IP info."""
    resolver = _get_resolver()

    txt_data, soa_data = _collect_txt_soa_records(domain, resolver)
    return {
        "mx": _collect_mx_records(domain, resolver),
        "ns": _collect_ns_records(domain, resolver),
        "txt": txt_data,
        "soa": soa_data,
    }


# ── CSV report ─────────────────────────────────────────────────────────────────

def generate_csv(resolved: dict[str, str], enriched: dict[str, dict], path: str) -> None:
    fields = ["host","ip","rdns","asn","asn_name","cidr","country",
              "http_server","http_title","https_server","https_title",
              "http8080_server","tech","ssl_cn","ssl_o",
              "shodan_ports","shodan_hostnames","shodan_tags","shodan_vulns","shodan_cpes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for host, ip in sorted(resolved.items()):
            d    = enriched.get(host, {})
            info = d.get("info", {})
            http = d.get("http", {})
            ssl  = d.get("ssl", {})
            shodan = d.get("shodan", {})
            asn, asn_name = _parse_org(info)
            def svc(label, key):
                return http.get(label, {}).get(key, "")
            w.writerow({
                "host": host, "ip": ip, "rdns": d.get("rdns",""),
                "asn": asn, "asn_name": asn_name,
                "cidr": info.get("network",""), "country": info.get("country",""),
                "http_server":   svc("http","server"),  "http_title":   svc("http","title"),
                "https_server":  svc("https","server"), "https_title":  svc("https","title"),
                "http8080_server": svc("http8080","server"),
                "tech": " | ".join(http.get("http",{}).get("tech",[]) or
                                   http.get("https",{}).get("tech",[])),
                "ssl_cn": ssl.get("cn",""), "ssl_o": ssl.get("o",""),
                "shodan_ports": ",".join(str(p) for p in shodan.get("ports", [])),
                "shodan_hostnames": " | ".join(shodan.get("hostnames", [])),
                "shodan_tags": " | ".join(shodan.get("tags", [])),
                "shodan_vulns": " | ".join(shodan.get("vulns", [])),
                "shodan_cpes": " | ".join(shodan.get("cpes", [])),
            })
    print(f"[+] CSV saved → {path}")


def generate_json(
    domain: str,
    resolved: dict[str, str],
    enriched: dict[str, dict],
    dns_data: dict,
    path: str,
    scan_started: float | None = None,
) -> None:
    payload = {
        "target": domain,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan_started": datetime.fromtimestamp(scan_started).isoformat(timespec="seconds") if scan_started else "",
        "live_count": len(resolved),
        "subdomains": [
            {"host": host, **enriched.get(host, {"ip": ip})}
            for host, ip in sorted(resolved.items())
        ],
        "dns_records": dns_data,
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[+] JSON saved → {path}")


def generate_ndjson(resolved: dict[str, str], enriched: dict[str, dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for host, ip in sorted(resolved.items()):
            row = {"host": host, **enriched.get(host, {"ip": ip})}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[+] NDJSON saved → {path}")


# ── HTML report ────────────────────────────────────────────────────────────────

def _h(text: str) -> str:
    """HTML-escape a string."""
    return (str(text)
            .replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))


def generate_html(domain: str, resolved: dict[str, str], enriched: dict[str, dict],
                  dns_data: dict, path: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows_a = []
    for host, ip in sorted(resolved.items()):
        d    = enriched.get(host, {})
        info = d.get("info", {})
        http = d.get("http", {})
        ssl  = d.get("ssl", {})
        rdns = d.get("rdns", "")
        shodan = d.get("shodan", {})
        asn, asn_name = _parse_org(info)

        services = []
        for label, svc in http.items():
            s = f"<b>{_h(label)}</b>: {_h(svc.get('server',''))}"
            if svc.get("title"):
                s += f"<br><span class='dim'>title: {_h(svc['title'])}</span>"
            for t in svc.get("tech", []):
                s += f"<br><span class='tag'>{_h(t)}</span>"
            services.append(s)
        if ssl.get("cn"):
            services.append(f"<span class='dim'>CN: {_h(ssl['cn'])}</span>")
        if shodan.get("ports"):
            services.append(f"<span class='dim'>Shodan ports: {_h(', '.join(str(p) for p in shodan.get('ports', [])))}</span>")
        if shodan.get("vulns"):
            services.append(f"<span class='tag'>Vulns: {_h(', '.join(shodan.get('vulns', [])[:5]))}</span>")

        rows_a.append(f"""
        <tr>
          <td><a href="https://{_h(host)}" target="_blank">{_h(host)}</a></td>
          <td class="mono">{_h(ip)}</td>
          <td class="mono dim">{_h(rdns) if rdns != ip else ""}</td>
          <td><span class="asn">{_h(asn)}</span></td>
          <td>{_h(asn_name)}</td>
          <td class="mono dim">{_h(info.get("network",""))}</td>
          <td>{_h(info.get("country",""))}</td>
          <td>{"<br>".join(services)}</td>
        </tr>""")

    rows_mx = []
    for r in dns_data.get("mx", []):
        rows_mx.append(f"""
        <tr>
          <td class="mono">{_h(r['pref'])}</td>
          <td>{_h(r['host'])}</td>
          <td class="mono">{_h(r['ip'])}</td>
          <td class="mono dim">{_h(r['rdns']) if r['rdns'] != r['ip'] else ""}</td>
          <td><span class="asn">{_h(r['asn'])}</span> {_h(r['asn_name'])}</td>
          <td class="mono dim">{_h(r['cidr'])}</td>
          <td>{_h(r['country'])}</td>
        </tr>""")

    rows_ns = []
    for r in dns_data.get("ns", []):
        rows_ns.append(f"""
        <tr>
          <td>{_h(r['host'])}</td>
          <td class="mono">{_h(r['ip'])}</td>
          <td class="mono dim">{_h(r['rdns']) if r['rdns'] != r['ip'] else ""}</td>
          <td><span class="asn">{_h(r['asn'])}</span> {_h(r['asn_name'])}</td>
          <td class="mono dim">{_h(r['cidr'])}</td>
          <td>{_h(r['country'])}</td>
          <td class="mono dim">{_h(r.get('ssh',''))}</td>
        </tr>""")

    soa = dns_data.get("soa") or {}
    soa_html = ""
    if soa:
        soa_html = f"""
        <table class="soa-table">
          <tr><th>Primary NS</th><td>{_h(soa['mname'])}</td></tr>
          <tr><th>Hostmaster</th><td>{_h(soa['rname'])}</td></tr>
          <tr><th>Serial</th><td>{_h(soa['serial'])}</td></tr>
          <tr><th>Refresh</th><td>{_h(soa['refresh'])}s</td></tr>
          <tr><th>Retry</th><td>{_h(soa['retry'])}s</td></tr>
          <tr><th>Expire</th><td>{_h(soa['expire'])}s</td></tr>
        </table>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Subdomain Report – {_h(domain)}</title>
<style>
  :root {{
    --bg: #050a05;
    --surface: #0b140b;
    --border: #1a3a1a;
    --text: #a8f0a8;
    --dim: #4e8a50;
    --accent: #00ff41;
    --green: #00ff41;
    --amber: #adff2f;
    --red: #ff2040;
    --hover-row: rgba(0, 255, 65, 0.06);
    --asn-bg: #0a1f0a;
    --tag-bg: #0c2010;
    --tag-fg: #7fff8a;
    --glow: rgba(0, 255, 65, 0.35);
    --glow-sm: rgba(0, 255, 65, 0.15);
    --scrollbar-thumb: #1a3a1a;
    --scrollbar-track: #050a05;
  }}

  body.light {{
    --bg: #f4fff4;
    --surface: #ffffff;
    --border: #cce7cc;
    --text: #103010;
    --dim: #3f6b3f;
    --accent: #0f7a2a;
    --green: #0f7a2a;
    --amber: #6b8e00;
    --red: #b42318;
    --hover-row: rgba(15, 122, 42, 0.06);
    --asn-bg: #dff5df;
    --tag-bg: #e9fbe9;
    --tag-fg: #1f6f2f;
    --glow: rgba(15, 122, 42, 0.15);
    --glow-sm: rgba(15, 122, 42, 0.08);
    --scrollbar-thumb: #99cc99;
    --scrollbar-track: #e8f5e8;
  }}

  ::selection {{
    background: var(--accent);
    color: #000;
  }}

  ::-webkit-scrollbar {{
    width: 8px;
    height: 8px;
  }}
  ::-webkit-scrollbar-track {{
    background: var(--scrollbar-track);
  }}
  ::-webkit-scrollbar-thumb {{
    background: var(--scrollbar-thumb);
    border-radius: 4px;
  }}
  ::-webkit-scrollbar-thumb:hover {{
    background: var(--accent);
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', 'Fira Code', monospace;
    font-size: 14px;
    padding: 24px;
  }}

  h1 {{
    font-size: 1.5rem;
    margin-bottom: 4px;
    color: var(--accent);
    letter-spacing: .08em;
    text-transform: uppercase;
    text-shadow: 0 0 10px var(--glow), 0 0 30px var(--glow-sm);
  }}

  .meta {{
    color: var(--dim);
    font-size: 12px;
    margin-bottom: 32px;
  }}

  .header-row {{
    display: block;
    margin-bottom: 4px;
  }}

  .theme-toggle {{
    position: fixed;
    top: 14px;
    right: 14px;
    z-index: 1000;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 12px;
    font-size: 12px;
    font-family: 'Courier New', monospace;
    color: var(--dim);
    cursor: pointer;
    transition: all 0.2s ease;
  }}
  .theme-toggle:hover {{
    color: var(--accent);
    border-color: var(--accent);
    box-shadow: 0 0 12px var(--glow-sm);
  }}

  @media (max-width: 640px) {{
    .theme-toggle {{ top: 10px; right: 10px; }}
  }}

  .stat-bar {{
    display: flex;
    gap: 16px;
    margin-bottom: 32px;
    flex-wrap: wrap;
  }}
  .stat {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 20px;
    min-width: 120px;
  }}
  .stat .num {{
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent);
    text-shadow: 0 0 10px var(--glow), 0 0 40px var(--glow-sm);
  }}
  .stat .lbl {{
    color: var(--dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .05em;
  }}

  section {{ margin-bottom: 40px; }}

  h2 {{
    font-size: 1rem;
    font-weight: 600;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 16px;
    text-transform: uppercase;
    letter-spacing: .08em;
    text-shadow: 0 0 6px var(--glow-sm);
  }}

  .table-wrap {{
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid var(--border);
  }}
  table {{ width: 100%; border-collapse: collapse; }}

  thead th {{
    background: var(--surface);
    color: var(--dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .05em;
    padding: 10px 14px;
    text-align: left;
    white-space: nowrap;
  }}

  tbody tr {{
    border-top: 1px solid var(--border);
    transition: background 0.15s ease;
  }}
  tbody tr:hover {{
    background: var(--hover-row);
  }}

  td {{
    padding: 10px 14px;
    vertical-align: top;
    word-break: break-word;
    max-width: 320px;
  }}
  td a {{
    color: var(--accent);
    text-decoration: none;
    font-weight: 600;
    text-shadow: 0 0 4px var(--glow-sm);
  }}
  td a:hover {{
    text-decoration: underline;
    text-shadow: 0 0 8px var(--glow);
  }}

  .mono {{ font-family: 'Courier New', monospace; font-size: 12px; }}
  .dim  {{ color: var(--dim); }}

  .asn {{
    background: var(--asn-bg);
    color: var(--amber);
    font-family: 'Courier New', monospace;
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 4px;
    white-space: nowrap;
  }}

  .tag {{
    display: inline-block;
    background: var(--tag-bg);
    color: var(--tag-fg);
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 4px;
    margin-top: 2px;
  }}

  .txt-record {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    word-break: break-all;
    white-space: pre-wrap;
    color: var(--green);
    text-shadow: 0 0 3px var(--glow-sm);
  }}

  .soa-table th {{
    background: var(--surface);
    padding: 8px 14px;
    text-align: left;
    color: var(--dim);
    width: 140px;
    font-weight: normal;
  }}
  .soa-table td {{
    padding: 8px 14px;
    font-family: 'Courier New', monospace;
  }}
  .soa-table tr {{
    border-top: 1px solid var(--border);
  }}
</style>
<script>
  (function() {{
    if (localStorage.getItem('theme') === 'light') document.documentElement.classList.add('light-pending');
  }})();
</script>
</head>
<body>
<script>
  if (localStorage.getItem('theme') === 'light') document.body.classList.add('light');
  function updateThemeButton() {{
    var btn = document.getElementById('theme-btn');
    if (!btn) return;
    var isLight = document.body.classList.contains('light');
    btn.textContent = isLight ? '🌙 Dark mode' : '☀️ Light mode';
  }}
  function toggleTheme() {{
    var light = document.body.classList.toggle('light');
    localStorage.setItem('theme', light ? 'light' : 'dark');
    updateThemeButton();
  }}
</script>
<div class="header-row">
  <h1>Subdomain Recon Report</h1>
  <button id="theme-btn" class="theme-toggle" onclick="toggleTheme()">☀️ Light mode</button>
</div>
<script>updateThemeButton();</script>
<p class="meta">Target: <strong>{_h(domain)}</strong> &nbsp;|&nbsp; Generated: {now}</p>

<div class="stat-bar">
  <div class="stat"><div class="num">{len(resolved)}</div><div class="lbl">Live Subdomains</div></div>
  <div class="stat"><div class="num">{len(dns_data.get('mx',[]))}</div><div class="lbl">MX Records</div></div>
  <div class="stat"><div class="num">{len(dns_data.get('ns',[]))}</div><div class="lbl">NS Records</div></div>
  <div class="stat"><div class="num">{len(dns_data.get('txt',[]))}</div><div class="lbl">TXT Records</div></div>
</div>

<section>
  <h2>A Records (Subdomains)</h2>
  <div class="table-wrap">
  <table>
    <thead><tr>
      <th>Host</th><th>IP</th><th>rDNS</th><th>ASN</th>
      <th>Organisation</th><th>CIDR</th><th>Country</th><th>Open Services</th>
    </tr></thead>
    <tbody>{"".join(rows_a)}</tbody>
  </table>
  </div>
</section>

<section>
  <h2>MX Records</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Pref</th><th>Host</th><th>IP</th><th>rDNS</th><th>ASN / Org</th><th>CIDR</th><th>Country</th></tr></thead>
    <tbody>{"".join(rows_mx)}</tbody>
  </table>
  </div>
</section>

<section>
  <h2>NS Records</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>rDNS</th><th>ASN / Org</th><th>CIDR</th><th>Country</th><th>SSH</th></tr></thead>
    <tbody>{"".join(rows_ns)}</tbody>
  </table>
  </div>
</section>

<section>
  <h2>TXT Records</h2>
  {"".join(f'<div class="txt-record">{_h(t)}</div>' for t in dns_data.get("txt",[]))}
</section>

<section>
  <h2>SOA Record</h2>
  <div class="table-wrap">{soa_html}</div>
</section>

</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    print(f"[+] HTML saved → {path}")


# ── DNS resolution / validation ────────────────────────────────────────────────

def resolve_all(subdomains: set[str], threads: int = 100) -> dict[str, str]:
    """Resolve subdomains concurrently, printing each hit as it arrives."""
    resolved = {}
    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, s): s for s in subdomains}
        for f in as_completed(futures):
            result = f.result()
            if result:
                host, ip = result
                resolved[host] = ip
                if not _QUIET:
                    print(f"  [+] {host:<48} {ip}")
    elapsed = max(time.time() - start, 0.001)
    rate = len(subdomains) / elapsed if subdomains else 0.0
    print(f"[RESOLVE] Stats: checked={len(subdomains)} live={len(resolved)} rate~{rate:.1f}/s")
    return resolved


# ── scan progress & operator-style output ─────────────────────────────────────

def _progress_bar(percent: int, width: int = 36) -> str:
    pct = max(0, min(100, int(percent)))
    filled = int(width * pct / 100)
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


def _fmt_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02}:{m:02}:{sec:02}"


def _phase_progress(phase_idx: int, total_phases: int, phase_name: str, scan_start: float) -> None:
    percent = int((phase_idx / total_phases) * 100)
    elapsed = max(time.time() - scan_start, 0.001)
    eta = ((elapsed / phase_idx) * (total_phases - phase_idx)) if phase_idx > 0 else 0.0
    print(
        f"\n[PROGRESS] {_progress_bar(percent)} {percent:>3}%  | "
        f"Phase {phase_idx}/{total_phases}: {phase_name} | ETA: {_fmt_duration(eta)}"
    )


def _print_whois_summary(whois_data: dict) -> None:
    if not whois_data:
        print("[WHOIS] No WHOIS data returned.")
        return
    print("[WHOIS] Registrar     :", whois_data.get("registrar", ""))
    print("[WHOIS] Created       :", whois_data.get("creation_date", ""))
    print("[WHOIS] Updated       :", whois_data.get("updated_date", ""))
    print("[WHOIS] Expires       :", whois_data.get("expiry_date", ""))
    ns = whois_data.get("name_servers", []) or []
    print("[WHOIS] Name servers  :", ", ".join(ns) if ns else "(none)")


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator")
    parser.add_argument("domain", help="Target domain, e.g. hollard.com.au")
    parser.add_argument("--no-brute", action="store_true", help="Skip DNS brute-force")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive sources")
    parser.add_argument("--no-http-probe", action="store_true", help="Skip HTTP/HTTPS probing")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL certificate lookup")
    parser.add_argument("--no-rdns", action="store_true", help="Skip reverse DNS lookups")
    parser.add_argument("--no-shodan", action="store_true", help="Skip Shodan InternetDB enrichment")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS query")
    parser.add_argument("--quick", action="store_true", help="Faster scan with lighter enrichment defaults")
    parser.add_argument("--wordlist", help="Path to custom wordlist (one word per line)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent threads (default 100)")
    parser.add_argument("--http-timeout", type=float, default=3.0, help="HTTP probe timeout in seconds (default 3.0)")
    parser.add_argument("--ssl-timeout", type=float, default=3.0, help="SSL timeout in seconds (default 3.0)")
    parser.add_argument("--shodan-timeout", type=float, default=3.0, help="Shodan InternetDB timeout in seconds (default 3.0)")
    parser.add_argument("--passive-timeout", type=float, default=12.0, help="Passive source timeout in seconds (default 12.0)")
    parser.add_argument("--enrich-limit", type=int, default=0, help="Only enrich first N resolved hosts (0 = all)")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--json-output", help="Save structured JSON report")
    parser.add_argument("--ndjson-output", help="Save line-delimited JSON results")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-host live output")
    args = parser.parse_args()
    global _QUIET
    _QUIET = args.quiet

    domain = args.domain.lower().strip()
    total_phases = 6
    scan_start = time.time()
    print("\nStarting Subdomain Recon Engine")
    print(f"Target: {domain}")
    print(f"Threads: {args.threads}")
    print("[INIT] Initializing scan modules, DNS resolvers, and HTTP probes...")
    _phase_progress(0, total_phases, "Initialization", scan_start)

    found: set[str] = set()
    # Track hosts already resolved during brute-force to avoid re-resolving them
    pre_resolved: dict[str, str] = {}
    dns_data = {"mx": [], "ns": [], "txt": [], "soa": None}

    # WHOIS
    _phase_progress(1, total_phases, "WHOIS", scan_start)
    if args.no_whois:
        print("[WHOIS] Skipped by operator flag (--no-whois).")
    elif not WHOIS_AVAILABLE:
        print("[WHOIS] Skipped (python-whois not installed).")
    else:
        print("[WHOIS] Querying registrar and registration metadata...")
        whois_data = fetch_whois(domain)
        _print_whois_summary(whois_data)

    # DNS (enumeration + record collection)
    _phase_progress(2, total_phases, "DNS (Discovery + Records)", scan_start)
    print("[DNS] Discovering authoritative nameservers...")
    nameservers = get_nameservers(domain)
    if nameservers:
        print(f"[DNS] Nameservers: {', '.join(nameservers)}")
    else:
        print("[DNS] No nameservers found")

    print("[DNS] Attempting AXFR zone transfer checks...")
    axfr = attempt_zone_transfer(domain, nameservers)
    if axfr:
        found |= axfr
    else:
        print("[DNS] Zone transfer refused/blocked (expected).")

    print("[DNS] Extracting candidate hosts from NS/MX/TXT/SRV records...")
    dns_found = dns_records(domain)
    print(f"[DNS] Record extraction yielded {len(dns_found)} candidate subdomains.")
    found |= dns_found

    print("[DNS] Enumerating MX/NS/TXT/SOA records for reporting...")
    dns_data = collect_dns_records(domain)
    print(
        "[DNS] Record inventory: "
        f"MX={len(dns_data.get('mx', []))}, "
        f"NS={len(dns_data.get('ns', []))}, "
        f"TXT={len(dns_data.get('txt', []))}, "
        f"SOA={'yes' if dns_data.get('soa') else 'no'}"
    )
    print("[DNS] Printing unified DNS report output...")
    print_dns_report(dns_data)

    # Passive recon — run sources in parallel
    _phase_progress(3, total_phases, "Passive", scan_start)
    if not args.no_passive:
        print("[PASSIVE] Querying passive intel sources (crt.sh, HackerTarget)...")
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_crt = ex.submit(fetch_crtsh, domain, args.passive_timeout)
            f_ht  = ex.submit(fetch_hackertarget, domain, args.passive_timeout)
            crt = f_crt.result()
            ht  = f_ht.result()
        print(f"[PASSIVE] Results: crt.sh={len(crt)} | HackerTarget={len(ht)}")
        found |= crt
        found |= ht
    else:
        print("[PASSIVE] Skipped by operator flag (--no-passive).")

    # Brute-force — streams hits to screen as found, returns {host: ip}
    _phase_progress(4, total_phases, "Brute-force", scan_start)
    if not args.no_brute:
        wordlist = COMMON_SUBDOMAINS
        if args.wordlist:
            try:
                with open(args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
                print(f"[BRUTE] Using custom wordlist ({len(wordlist)} entries).")
            except FileNotFoundError:
                print(f"[!] Wordlist not found: {args.wordlist}")
        else:
            print(f"[BRUTE] Using built-in wordlist ({len(wordlist)} entries).")
        print("[BRUTE] Launching high-concurrency DNS brute-force...")
        brute = brute_force(domain, wordlist, threads=args.threads)
        print(f"[BRUTE] Live discoveries: {len(brute)}")
        pre_resolved.update(brute)
        found |= set(brute.keys())
    else:
        print("[BRUTE] Skipped by operator flag (--no-brute).")

    # Resolve remaining subdomains not already resolved by brute-force
    _phase_progress(5, total_phases, "Resolve", scan_start)
    unresolved = found - set(pre_resolved.keys())
    print(f"[RESOLVE] Pending hosts: {len(unresolved)} | Pre-resolved from brute-force: {len(pre_resolved)}")
    print("[RESOLVE] Performing DNS A/AAAA resolution for discovered hostnames...")
    resolved = {**pre_resolved, **resolve_all(unresolved, threads=args.threads)}

    live = sorted(resolved.items())
    print(f"[RESOLVE] Live hosts confirmed: {len(live)}")

    if args.output:
        with open(args.output, "w") as f:
            for host, ip in live:
                f.write(f"{host},{ip}\n")
        print(f"[+] Saved to {args.output}")

    do_http = not args.no_http_probe
    do_ssl  = not args.no_ssl
    do_rdns = not args.no_rdns
    do_shodan = not args.no_shodan
    enrich_limit = args.enrich_limit
    if args.quick:
        # Quick mode prioritizes speed over depth.
        do_http = False
        do_ssl = False
        do_rdns = False
        do_shodan = False
        enrich_limit = enrich_limit or 100

    # Enrich hosts (IP info always; optional HTTP probe + SSL + rDNS)
    _phase_progress(6, total_phases, "Enrich", scan_start)
    print("[ENRICH] Enriching hosts with IP metadata and service intelligence...")
    print(f"[ENRICH] Options: http={do_http} ssl={do_ssl} rdns={do_rdns} shodan={do_shodan} limit={enrich_limit or 'all'}")
    enriched = collect_enrichment(
        resolved,
        threads=args.threads,
        http_timeout=args.http_timeout,
        ssl_timeout=args.ssl_timeout,
        shodan_timeout=args.shodan_timeout,
        do_http=do_http,
        do_ssl=do_ssl,
        do_rdns=do_rdns,
        do_shodan=do_shodan,
        enrich_limit=enrich_limit,
    )

    # A records report (terminal)
    print_a_records(resolved, enriched)

    # Output reports
    stem = domain.replace(".", "_")
    generate_csv(resolved, enriched, f"{stem}_report.csv")
    generate_html(domain, resolved, enriched, dns_data, f"{stem}_report.html")
    if args.json_output:
        generate_json(domain, resolved, enriched, dns_data, args.json_output, scan_start)
    if args.ndjson_output:
        generate_ndjson(resolved, enriched, args.ndjson_output)
    print(f"\n[COMPLETE] {_progress_bar(100)} 100%  | Recon workflow finished for {domain}")


if __name__ == "__main__":
    main()
