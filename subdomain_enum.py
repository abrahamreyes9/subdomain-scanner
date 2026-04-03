#!/usr/bin/env python3
"""
Subdomain enumerator for a target domain.
Sources: DNS zone transfer, DNS records (NS/MX/TXT/SRV), crt.sh, HackerTarget, brute-force.
"""

import sys
import socket
import argparse
import threading
import requests
import re
import ssl
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from time import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Module-level configuration ────────────────────────────────────────────────

_verbose: bool = False
_custom_nameservers: list[str] = []
_verify_ssl: bool = True           # Default True — use --insecure to disable
MAX_WORKERS: int = 100             # Default concurrency for brute-force / resolve
_thread_local = threading.local()  # Thread-local resolver cache


def configure(nameservers: list[str] | None = None,
              verbose: bool = False,
              verify_ssl: bool = True) -> None:
    """Set module-wide DNS resolver, verbosity, and SSL verification."""
    global _verbose, _custom_nameservers, _verify_ssl
    _verbose = verbose
    _custom_nameservers = nameservers or []
    _verify_ssl = verify_ssl
    # Invalidate any cached thread-local resolvers so they pick up new nameservers
    _thread_local.__dict__.clear()


def _make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    """Create a new Resolver configured with any custom nameservers."""
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    if _custom_nameservers:
        r.nameservers = _custom_nameservers
    return r


def _get_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    """Return a thread-local Resolver, creating it on first use per thread."""
    key = f"resolver_{timeout}"
    if not hasattr(_thread_local, key):
        setattr(_thread_local, key, _make_resolver(timeout))
    return getattr(_thread_local, key)


def _vprint(*args, **kwargs) -> None:
    if _verbose:
        print(*args, **kwargs)


def rate_limited(max_per_second: float):
    """Thread-safe decorator that caps how often a function may be called."""
    min_interval = 1.0 / max_per_second
    def decorate(func):
        last_called = [0.0]
        lock = threading.Lock()
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                elapsed = time() - last_called[0]
                wait = min_interval - elapsed
                if wait > 0:
                    import time as _t; _t.sleep(wait)
                last_called[0] = time()
            return func(*args, **kwargs)
        return wrapper
    return decorate


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
            ns_ip = resolve_ip(ns)
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
        except Exception:
            pass
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
    except Exception:
        pass

    # MX records
    try:
        for r in resolver.resolve(domain, "MX"):
            host = str(r.exchange).rstrip(".").lower()
            if host.endswith(f".{domain}"):
                found.add(host)
    except Exception:
        pass

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
    except Exception:
        pass

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
        except Exception:
            pass
        return results

    with ThreadPoolExecutor(max_workers=len(srv_prefixes)) as ex:
        for hosts in ex.map(_query_srv, srv_prefixes):
            found.update(hosts)

    return found


# ── passive sources ────────────────────────────────────────────────────────────

@rate_limited(2.0)
def fetch_crtsh(domain: str) -> set[str]:
    """Query crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        entries = r.json()
        subs = set()
        for e in entries:
            for name in e.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name.lower())
        return subs
    except Exception as ex:
        print(f"[!] crt.sh error: {ex}")
        return set()


@rate_limited(2.0)
def fetch_hackertarget(domain: str) -> set[str]:
    """Query HackerTarget's free subdomain API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=20)
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


def fetch_whois(domain: str) -> dict:
    """Return WHOIS registration data for a domain."""
    try:
        import whois
        w = whois.whois(domain)
        def _str(v):
            if isinstance(v, list): v = v[0]
            return str(v).split("T")[0] if v else ""
        return {
            "registrar":     w.registrar or "",
            "creation_date": _str(w.creation_date),
            "expiry_date":   _str(w.expiration_date),
            "updated_date":  _str(w.updated_date),
            "name_servers":  sorted({ns.lower().rstrip(".") for ns in (w.name_servers or [])}),
            "status":        (w.status if isinstance(w.status, list) else [w.status]) if w.status else [],
        }
    except Exception:
        return {}


# ── active DNS brute-force ─────────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    # ── Core web ──────────────────────────────────────────────────────────────
    "www", "www2", "www3", "web", "website", "site",
    "m", "mobile", "wap", "touch",

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
    """Resolve a hostname to its A record using the configured resolver."""
    try:
        answer = _get_resolver(timeout=3.0).resolve(subdomain, "A")
        return (subdomain, str(answer[0]))
    except Exception:
        return None


def brute_force(domain: str, wordlist: list[str], threads: int = MAX_WORKERS) -> set[str]:
    """Resolve candidates concurrently, printing hits as they arrive."""
    candidates = [f"{w}.{domain}" for w in wordlist]
    found = set()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, c): c for c in candidates}
        for f in as_completed(futures):
            try:
                result = f.result()
                if result:
                    host, ip = result
                    found.add(host)
                    _vprint(f"  [+] {host:<48} {ip}")
            except Exception as e:
                _vprint("[!] thread error:", e)
    return found


# ── IP enrichment ─────────────────────────────────────────────────────────────

_ip_cache: dict[str, dict] = {}

@rate_limited(5.0)  # ipinfo.io free tier: ~50k req/mo, stay polite
def get_ip_info(ip: str) -> dict:
    """Query ipinfo.io for ASN, CIDR, org, country."""
    if ip in _ip_cache or ip in ("?", ""):
        return _ip_cache.get(ip, {})
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data = r.json()
        _ip_cache[ip] = data
        return data
    except Exception:
        return {}


def check_ssh(ip: str, timeout: float = 1.5) -> str:
    """Try to grab SSH banner from port 22."""
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as s:
            banner = s.recv(128).decode(errors="ignore").strip()
            return banner.split("\n")[0] if banner else "open"
    except Exception:
        return ""


def resolve_ip(hostname: str) -> str:
    """Resolve hostname to IPv4 using the configured resolver."""
    result = resolve(hostname)
    return result[1] if result else ""


def reverse_dns(ip: str) -> str:
    try:
        rev = dns.reversename.from_address(ip)
        return str(_get_resolver(timeout=3.0).resolve(rev, "PTR")[0]).rstrip(".")
    except Exception:
        return ""


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


# ── Subdomain takeover fingerprints ───────────────────────────────────────────
# Source: https://github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_FINGERPRINTS: dict[str, list[str]] = {
    "github.io":          ["There isn't a GitHub Pages site here", "For root URLs"],
    "amazonaws.com":      ["NoSuchBucket", "The specified bucket does not exist"],
    "s3.amazonaws.com":   ["NoSuchBucket", "The specified bucket does not exist"],
    "heroku.com":         ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "herokussl.com":      ["No such app"],
    "azurewebsites.net":  ["404 Web Site not found"],
    "cloudapp.net":       ["404 Web Site not found"],
    "trafficmanager.net": ["404 Web Site not found"],
    "fastly.net":         ["Fastly error: unknown domain"],
    "shopify.com":        ["Sorry, this shop is currently unavailable"],
    "shopifypreview.com": ["Sorry, this shop is currently unavailable"],
    "tumblr.com":         ["Whatever you were looking for doesn't currently exist"],
    "wordpress.com":      ["Do you want to register"],
    "ghost.io":           ["The thing you were looking for is no longer here"],
    "surge.sh":           ["project not found"],
    "statuspage.io":      ["Better Status Communication"],
    "readme.io":          ["Project doesnt exist"],
    "helpscout.com":      ["No settings were found for this company"],
    "intercom.io":        ["Uh oh. That page doesn't exist"],
    "uservoice.com":      ["This UserVoice subdomain is currently available"],
    "zendesk.com":        ["Help Center Closed"],
    "unbounce.com":       ["The requested URL was not found on this server"],
    "launchrock.com":     ["It looks like you may have taken a wrong turn"],
    "sendgrid.net":       ["The requested URL was not found"],
    "webflow.io":         ["The page you are looking for doesn't exist"],
    "pantheonsite.io":    ["The gods are wise"],
    "cargo.site":         ["If you're moving your domain away from Cargo"],
    "freshdesk.com":      ["There is no helpdesk here with that URL"],
    "teamwork.com":       ["Oops - We didn't find your site"],
}

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 5900, 6379,
              8080, 8443, 8888, 9200, 27017]

def check_ports(ip: str, timeout: float = 1.5) -> list[int]:
    """TCP connect scan against common ports. Returns list of open ports."""
    def _try(port: int) -> int | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=len(SCAN_PORTS)) as ex:
        return sorted(p for p in ex.map(_try, SCAN_PORTS) if p)


def check_takeover(host: str) -> dict | None:
    """Check if a subdomain CNAME points to an unclaimed service."""
    try:
        resolver = _get_resolver(timeout=3)
        try:
            answers = resolver.resolve(host, "CNAME")
            cname   = str(answers[0].target).rstrip(".").lower()
        except Exception:
            return None

        matched = next((svc for svc in TAKEOVER_FINGERPRINTS if svc in cname), None)
        if not matched:
            return None

        fingerprints = TAKEOVER_FINGERPRINTS[matched]
        for scheme in ("https", "http"):
            try:
                r    = requests.get(f"{scheme}://{host}", timeout=5, verify=_verify_ssl,
                                    allow_redirects=True)
                body = r.text[:8000].lower()
                hit  = next((fp for fp in fingerprints if fp.lower() in body), None)
                if hit:
                    return {"cname": cname, "service": matched,
                            "status": r.status_code, "fingerprint": hit}
            except Exception:
                pass
    except Exception:
        pass
    return None


def _probe_one(session: requests.Session, scheme: str, port: int,
               host: str, timeout: float) -> tuple[str, dict | None]:
    """Probe a single scheme/port — captures status code and redirect chain."""
    label = scheme if port in (80, 443) else f"{scheme}{port}"
    url   = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    hdrs  = {"User-Agent": "Mozilla/5.0"}
    try:
        r      = session.get(url, timeout=timeout, headers=hdrs, verify=_verify_ssl,
                             allow_redirects=True)
        server = r.headers.get("server", "unknown server")
        title  = _get_title(r.text)
        tech   = _detect_tech(dict(r.headers), r.text)

        # Build redirect chain from requests history
        chain = [{"url": str(step.url), "status": step.status_code}
                 for step in r.history]
        if chain:
            chain.append({"url": str(r.url), "status": r.status_code})

        entry: dict = {
            "status": r.history[0].status_code if r.history else r.status_code,
            "final_status": r.status_code,
            "server": server,
        }
        if title:              entry["title"]    = title[:80]
        if tech:               entry["tech"]     = tech
        if chain:              entry["redirects"] = chain
        return label, entry
    except requests.exceptions.SSLError:
        return label, {"status": 0, "final_status": 0, "server": "ssl-error"}
    except Exception:
        return label, None


def probe_http(host: str, timeout: float = 5.0) -> dict:
    """Probe HTTP and HTTPS on a host concurrently, return service info."""
    session = requests.Session()
    session.max_redirects = 3
    targets = [("https", 443), ("http", 80), ("http", 8080)]
    result  = {}
    with ThreadPoolExecutor(max_workers=len(targets)) as ex:
        futures = [ex.submit(_probe_one, session, s, p, host, timeout) for s, p in targets]
        for f in as_completed(futures):
            label, entry = f.result()
            if entry:
                result[label] = entry
    return result


def get_ssl_cert_info(host: str, timeout: float = 5.0) -> dict:
    """Return CN and O from the SSL cert of a host."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=timeout),
            server_hostname=host,
        ) as s:
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            return {
                "cn": subject.get("commonName", ""),
                "o":  subject.get("organizationName", ""),
            }
    except Exception:
        return {}


def _enrich_batch(batch: list[tuple[str, str]], threads: int) -> dict[str, dict]:
    """Enrich a single batch of (host, ip) pairs."""
    enriched = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        f_info     = {host: ex.submit(get_ip_info,      ip)   for host, ip in batch}
        f_http     = {host: ex.submit(probe_http,        host) for host, _ in batch}
        f_ssl      = {host: ex.submit(get_ssl_cert_info, host) for host, _ in batch}
        f_rdns     = {host: ex.submit(reverse_dns,       ip)   for host, ip in batch}
        f_ports    = {host: ex.submit(check_ports,       ip)   for host, ip in batch}
        f_takeover = {host: ex.submit(check_takeover,    host) for host, _ in batch}
    for host, ip in batch:
        try:
            enriched[host] = {
                "ip":       ip,
                "info":     f_info[host].result(),
                "http":     f_http[host].result(),
                "ssl":      f_ssl[host].result(),
                "rdns":     f_rdns[host].result(),
                "ports":    f_ports[host].result(),
                "takeover": f_takeover[host].result(),
            }
        except Exception:
            enriched[host] = {"ip": ip, "info": {}, "http": {}, "ssl": {},
                               "rdns": "", "ports": [], "takeover": None}
    return enriched


def collect_enrichment(resolved: dict[str, str], threads: int = 50,
                       batch_size: int | None = None) -> dict[str, dict]:
    """Enrich resolved hosts in batches to avoid resource exhaustion."""
    items = sorted(resolved.items())
    # Auto-tune batch size: ~10% of total hosts, clamped between 20 and 100
    if batch_size is None:
        batch_size = max(20, min(100, len(items) // 10 or 20))
    enriched: dict[str, dict] = {}
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        enriched.update(_enrich_batch(batch, threads=min(threads, len(batch) * 6)))
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

    print(f"\n{'═'*70}\n")


# ── DNS record collection ──────────────────────────────────────────────────────

def collect_dns_records(domain: str) -> dict:
    """Collect MX, NS, TXT, SOA records and enrich with IP info."""
    resolver = _get_resolver()
    data = {"mx": [], "ns": [], "txt": [], "soa": None}

    # MX
    try:
        mx_raw = sorted(resolver.resolve(domain, "MX"), key=lambda r: r.preference)
        hosts  = [(r.preference, str(r.exchange).rstrip(".")) for r in mx_raw]
        with ThreadPoolExecutor(max_workers=10) as ex:
            ips   = {h: ex.submit(resolve_ip, h)   for _, h in hosts}
        with ThreadPoolExecutor(max_workers=10) as ex:
            infos = {h: ex.submit(get_ip_info, ips[h].result()) for _, h in hosts if ips[h].result()}
        for pref, host in hosts:
            ip   = ips[host].result()
            info = infos[host].result() if host in infos else {}
            asn, asn_name = _parse_org(info)
            data["mx"].append({"pref": pref, "host": host, "ip": ip,
                               "rdns": reverse_dns(ip) if ip else "",
                               "asn": asn, "asn_name": asn_name,
                               "cidr": info.get("network",""), "country": info.get("country","")})
    except Exception:
        pass

    # NS
    try:
        ns_raw = resolver.resolve(domain, "NS")
        hosts  = [str(r.target).rstrip(".") for r in ns_raw]
        with ThreadPoolExecutor(max_workers=10) as ex:
            ips  = {h: ex.submit(resolve_ip, h) for h in hosts}
            sshs = {h: ex.submit(check_ssh, ips[h].result()) for h in hosts if ips[h].result()}
        with ThreadPoolExecutor(max_workers=10) as ex:
            infos = {h: ex.submit(get_ip_info, ips[h].result()) for h in hosts if ips[h].result()}
        for host in hosts:
            ip   = ips[host].result()
            info = infos[host].result() if host in infos else {}
            asn, asn_name = _parse_org(info)
            data["ns"].append({"host": host, "ip": ip,
                               "rdns": reverse_dns(ip) if ip else "",
                               "asn": asn, "asn_name": asn_name,
                               "cidr": info.get("network",""), "country": info.get("country",""),
                               "ssh": sshs[host].result() if host in sshs else ""})
    except Exception:
        pass

    # TXT
    try:
        for r in resolver.resolve(domain, "TXT"):
            data["txt"].append(b"".join(r.strings).decode(errors="ignore"))
    except Exception:
        pass

    # SOA
    try:
        soa = resolver.resolve(domain, "SOA")[0]
        data["soa"] = {
            "mname": str(soa.mname).rstrip("."),
            "rname": str(soa.rname).rstrip("."),
            "serial": soa.serial, "refresh": soa.refresh,
            "retry": soa.retry,   "expire": soa.expire,
        }
    except Exception:
        pass

    return data


# ── CSV report ─────────────────────────────────────────────────────────────────

import csv
from datetime import datetime
from pathlib import Path

def generate_csv(resolved: dict[str, str], enriched: dict[str, dict], path: str) -> None:
    fields = ["host","ip","rdns","asn","asn_name","cidr","country",
              "http_server","http_title","https_server","https_title",
              "http8080_server","tech","ssl_cn","ssl_o"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for host, ip in sorted(resolved.items()):
            d    = enriched.get(host, {})
            info = d.get("info", {})
            http = d.get("http", {})
            ssl  = d.get("ssl", {})
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
            })
    print(f"[+] CSV saved → {path}")


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
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3e;
    --text: #e2e8f0; --dim: #6b7280; --accent: #6366f1;
    --green: #10b981; --amber: #f59e0b; --red: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; font-size: 14px; padding: 24px; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 4px; color: var(--accent); }}
  .meta {{ color: var(--dim); font-size: 12px; margin-bottom: 32px; }}
  .stat-bar {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
           padding: 12px 20px; min-width: 120px; }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .stat .lbl {{ color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }}
  section {{ margin-bottom: 40px; }}
  h2 {{ font-size: 1rem; font-weight: 600; color: var(--accent); border-bottom: 1px solid var(--border);
        padding-bottom: 8px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: .05em; }}
  .table-wrap {{ overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{ background: var(--surface); color: var(--dim); font-size: 11px; text-transform: uppercase;
              letter-spacing: .05em; padding: 10px 14px; text-align: left; white-space: nowrap; }}
  tbody tr {{ border-top: 1px solid var(--border); }}
  tbody tr:hover {{ background: var(--surface); }}
  td {{ padding: 10px 14px; vertical-align: top; word-break: break-word; max-width: 320px; }}
  td a {{ color: var(--accent); text-decoration: none; }}
  td a:hover {{ text-decoration: underline; }}
  .mono {{ font-family: monospace; font-size: 12px; }}
  .dim {{ color: var(--dim); }}
  .asn {{ background: #1e293b; color: var(--amber); font-family: monospace; font-size: 11px;
          padding: 1px 6px; border-radius: 4px; white-space: nowrap; }}
  .tag {{ display: inline-block; background: #0d2137; color: #38bdf8; font-size: 11px;
          padding: 1px 6px; border-radius: 4px; margin-top: 2px; }}
  .txt-record {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
                 padding: 10px 14px; margin-bottom: 8px; font-family: monospace; font-size: 12px;
                 word-break: break-all; white-space: pre-wrap; color: var(--green); }}
  .soa-table th {{ background: var(--surface); padding: 8px 14px; text-align: left;
                   color: var(--dim); width: 140px; font-weight: normal; }}
  .soa-table td {{ padding: 8px 14px; font-family: monospace; }}
  .soa-table tr {{ border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<h1>Subdomain Recon Report</h1>
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

def resolve_all(subdomains: set[str], threads: int = MAX_WORKERS) -> dict[str, str]:
    """Resolve subdomains concurrently, printing each hit as it arrives."""
    resolved = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, s): s for s in subdomains}
        for f in as_completed(futures):
            try:
                result = f.result()
                if result:
                    host, ip = result
                    resolved[host] = ip
                    _vprint(f"  [+] {host:<48} {ip}")
            except Exception as e:
                _vprint("[!] thread error:", e)
    return resolved


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator")
    parser.add_argument("domain", help="Target domain, e.g. hollard.com.au")
    parser.add_argument("--no-brute", action="store_true", help="Skip DNS brute-force")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive sources")
    parser.add_argument("--wordlist", help="Path to custom wordlist (one word per line)")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads (default 50)")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--dns", metavar="NS", nargs="+",
                        help="Custom DNS resolvers, e.g. --dns 1.1.1.1 8.8.8.8")
    parser.add_argument("--verbose", action="store_true",
                        help="Print each resolved subdomain as it is found")
    parser.add_argument("--insecure", action="store_false", dest="verify_ssl",
                        help="Disable TLS certificate verification")
    parser.set_defaults(verify_ssl=True)
    args = parser.parse_args()

    configure(nameservers=args.dns, verbose=args.verbose, verify_ssl=args.verify_ssl)
    domain = args.domain.lower().strip()
    print(f"\n[*] Target: {domain}\n")

    found: set[str] = set()

    # DNS enumeration
    print("[*] Fetching nameservers ...")
    nameservers = get_nameservers(domain)
    if nameservers:
        print(f"    Nameservers: {', '.join(nameservers)}")
    else:
        print("    No nameservers found")

    print("[*] Attempting zone transfers (AXFR) ...")
    axfr = attempt_zone_transfer(domain, nameservers)
    if axfr:
        found |= axfr
    else:
        print("    Zone transfer refused (expected)")

    print("[*] Extracting subdomains from DNS records (NS/MX/TXT/SRV) ...")
    dns_found = dns_records(domain)
    print(f"    DNS records yielded {len(dns_found)} subdomains")
    found |= dns_found

    # Passive recon — run sources in parallel
    if not args.no_passive:
        print("[*] Querying passive sources in parallel (crt.sh, HackerTarget) ...")
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_crt = ex.submit(fetch_crtsh, domain)
            f_ht  = ex.submit(fetch_hackertarget, domain)
            crt = f_crt.result()
            ht  = f_ht.result()
        print(f"    crt.sh: {len(crt)}  HackerTarget: {len(ht)}")
        found |= crt
        found |= ht

    # Brute-force — streams hits to screen as found
    if not args.no_brute:
        wordlist = COMMON_SUBDOMAINS
        if args.wordlist:
            try:
                with open(args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
                print(f"[*] Brute-forcing with custom wordlist ({len(wordlist)} words) ...")
            except FileNotFoundError:
                print(f"[!] Wordlist not found: {args.wordlist}")
        else:
            print(f"[*] Brute-forcing with built-in wordlist ({len(wordlist)} words) ...")
        brute = brute_force(domain, wordlist, threads=args.threads)
        print(f"    Brute-force: {len(brute)} live")
        found |= brute

    # Resolve all found subdomains (streams hits to screen as they come in)
    print(f"\n[*] Resolving {len(found)} unique subdomains ...")
    resolved = resolve_all(found, threads=args.threads)

    live = sorted(resolved.items())
    print(f"\n[+] {len(live)} live subdomains found for {domain}")

    if args.output:
        with open(args.output, "w") as f:
            for host, ip in live:
                f.write(f"{host},{ip}\n")
        print(f"[+] Saved to {args.output}")

    # Enrich all hosts (HTTP probe + IP info + SSL + rDNS)
    print("\n[*] Enriching subdomains (HTTP/HTTPS probe, IP info, SSL, rDNS) ...")
    enriched = collect_enrichment(resolved, threads=args.threads)

    # A records report (terminal)
    print_a_records(resolved, enriched)

    # Collect DNS records (MX / NS / TXT / SOA) with enrichment
    print("[*] Collecting DNS records ...")
    dns_data = collect_dns_records(domain)

    # DNS report (terminal)
    print_dns_report(dns_data)

    # Output reports
    stem = domain.replace(".", "_")
    generate_csv(resolved, enriched, f"{stem}_report.csv")
    generate_html(domain, resolved, enriched, dns_data, f"{stem}_report.html")


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
