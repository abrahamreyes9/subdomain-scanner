# Subdomain Scanner

A passive reconnaissance tool that gives you an attacker's view of your external attack surface — without running a single scan.

## Why I Built This

Traditional attack surface tools are either expensive enterprise platforms, require active scanning (which triggers alerts and firewalls), or take days to set up. I wanted something I could point at any domain and instantly see what an attacker sees — all subdomains, what's running on them, who hosts them, and how they're configured — using only passive, publicly available data sources.

The goal: **know your attack surface before an attacker does.**

Since the initial build, the scope has grown beyond pure discovery. The tool now evaluates subdomain takeover exposure, email authentication posture, certificate expiry risk, and what adversaries already see in Shodan — turning it from a recon script into a lightweight attack surface management tool.

---

## What It Does

The scanner combines multiple passive intelligence sources and semi-active techniques to discover and enrich every subdomain associated with a target domain, then surfaces the security-relevant findings that matter.

### Discovery Sources

| Source | What it finds |
|---|---|
| **Certificate Transparency (crt.sh)** | Every subdomain that has ever had a TLS certificate issued — historical records expose decommissioned and staging assets attackers still target |
| **AlienVault OTX** | Passive DNS from a global threat-intelligence feed; surfaces subdomains seen in malware campaigns and historical lookups |
| **HackerTarget** | Passive DNS dataset aggregated from public sources |
| **Wayback Machine (CDX API)** | URLs crawled by the Internet Archive — often exposes forgotten admin panels and dev endpoints no longer linked anywhere |
| **DNS Zone Transfer (AXFR)** | Full zone dump if a nameserver is misconfigured — a critical misconfiguration finding in its own right |
| **DNSSEC NSEC Walk** | Enumerates all signed zone labels when DNSSEC is enabled but NSEC3 opt-out is not configured — turns the cryptographic infrastructure itself into a discovery vector |
| **DNS Records (NS / MX / TXT / SRV)** | 19 SRV service types (LDAP, Kerberos, SMTP, SIP, XMPP, etc.) plus NS, MX, and SPF `include:` references — each record type can point to additional in-scope infrastructure |
| **Brute-force** | 239 common subdomain prefixes across 14 categories (web, API, DevOps, databases, security appliances, monitoring, e-commerce, support) resolved against live DNS |
| **Smart Permutations** | Generates variants from already-discovered prefixes using high-value suffix combinations (dev, prod, staging, api, admin) and a Markov chain character model trained on the target's own naming patterns — finds neighbour subdomains not present in any public dataset |

### Enrichment

Once subdomains are discovered, each one is enriched across several dimensions.

**Host Intelligence**
- IP address and Reverse DNS
- ASN, Organisation, CIDR, Country via ipinfo.io (LRU-cached to minimise API calls)
- Cloudflare CDN detection against 15 Cloudflare CIDR ranges — relevant because Cloudflare-fronted hosts expose no real origin IP and sit behind a WAF

**Service & HTTP Probing**
- HTTPS:443, HTTP:80, HTTP:8080 — status code, server header, page title, redirect chain with final resolved URL
- Tech fingerprinting across 21 patterns: server headers (Apache, nginx, IIS), framework headers (X-Powered-By, CF-Ray, X-Azure-Ref), and page body signals (React, Angular, WordPress, Shopify, Drupal, jQuery, AWS SDK, Azure)

**SSL / Certificate Analysis**
- Common Name, Organisation, SANs, expiry date and days remaining
- Severity-tiered expiry alerts: CRITICAL (expired or ≤7 days), HIGH (≤30 days), MEDIUM (≤90 days), LOW (≤180 days)

Expired and near-expiry certificates are a common source of outages and a trivial impersonation vector — an attacker who knows a cert is about to expire can time a phishing campaign around the confusion it causes.

**Port Scanning**
- nmap with TCP connect mode (`-sT`, no root required), `--top-ports N`, `-T4`, full XML output parsing
- Socket-based fallback when nmap is unavailable, scanning 21 ports: FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), HTTP (80), POP3 (110), IMAP (143), HTTPS (443), SMB (445), MSSQL (1433), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379), Elasticsearch (9200), MongoDB (27017), HTTP-alt (8080/8443)

Exposed management ports are direct attack paths. RDP, MySQL, Redis, and MongoDB regularly appear on public-facing hosts because infrastructure migrates and firewall rules don't always follow. This makes the actual internet-facing perimeter visible, not just what the architecture diagram says it should be.

**Accessibility Verification**
- Multi-method: ICMP ping, HTTP/HTTPS request, TCP connect to ports 80/443/8080/8443/22, OS-level DNS cross-check
- Each host is classified as **Confirmed Online** (at least one method succeeded) or **Detected (Unverified)** (DNS resolves, no service responded)

This matters for prioritisation — a host that resolves to an IP but has no reachable service is a different risk profile than one actively serving HTTP traffic.

**Subdomain Takeover Detection**
- Resolves full CNAME chains and checks HTTP response bodies against fingerprints for 24 services: GitHub Pages, Heroku, AWS S3, Azure (3 variants), Fastly, Zendesk, Netlify, Vercel, ReadTheDocs, Surge, Bitbucket, Ghost, Tumblr, WordPress, UserVoice, Freshdesk, Unbounce, Statuspage, FeedPress, HelpScout, CampaignMonitor, Pingdom, Cargo, Strikingly

A dangling CNAME — a DNS record pointing to a cloud or SaaS resource that has since been deprovisioned — allows an attacker to register the backing service and serve arbitrary content from your domain. It is one of the highest-impact, lowest-effort attacks on external infrastructure. Detected takeover risks are surfaced as a prominent warning in the UI.

**Shodan Integration**
- **Free (no key required):** Shodan InternetDB — open ports, CPEs, hostnames, tags, and known CVE identifiers per IP
- **Shodan API (optional key):** org, OS, full historical port data

Shodan has already indexed your infrastructure. This pulls exactly what an attacker sees in Shodan before they send a single packet toward your network.

---

## DNS Intelligence

Beyond subdomain discovery, the tool performs a full DNS audit of the target zone.

- **MX Records** — mail exchange hosts with preference value, IP, rDNS, ASN, CIDR, Country
- **NS Records** — authoritative nameservers with full IP enrichment and SSH banner grab
- **SRV Records** — 19 service types including LDAP, Kerberos, SIP, XMPP, SMTP, IMAP
- **TXT Records** — SPF includes, DKIM selectors, domain verification tokens, and third-party integration identifiers (40+ recognised vendors)
- **SOA Record** — zone authority (primary NS, hostmaster), serial number, refresh/retry/expire intervals

**Email Security Analysis**

- **SPF** — policy strength (`+all`, `~all`, `-all`, `?all`), authorised IP4/IP6 ranges, and all `include:` references, risk-scored from CRITICAL to SECURE. A permissive `+all` or missing SPF record means any host on the internet can send mail as your domain.
- **DMARC** — policy mode (none / quarantine / reject), SP tag, alignment mode, RUA reporting address — risk-scored. A `p=none` DMARC record (or no DMARC at all) means phishing emails that spoof your domain pass authentication checks in most mail clients. This is one of the most common vectors for business email compromise.

---

## Outputs

| Export | Contents |
|---|---|
| **Full Report (.txt)** | Human-readable report with all enriched data, DNS records, email security posture, and service info |
| **HTML Report** | Interactive version of the full report with sortable tables viewable in any browser |
| **ASM Import (.txt)** | `IP \| Domain` list for direct import into Qualys, Tenable, or Rapid7 |

The API also exposes JSON, NDJSON, and CSV formats for downstream tooling.

---

## Interface

The SPA streams results live via SSE as each phase completes and includes:

- **Threat Dashboard** — takeover risk count, certificates expiring within 30 days, per-source discovery breakdown, confirmed vs unverified host counts
- **Live Discovery Table** — hosts appear in real time with source attribution badges (crt.sh, AlienVault, AXFR, NSEC, brute-force, permutation, DNS records)
- **Attack Surface Tables** — confirmed-online and detected hosts in separate tables; high-risk ports (RDP, MySQL, MongoDB, Redis, Elasticsearch) highlighted
- **Email Security Panel** — DMARC and SPF risk cards with full policy detail
- **Certificate Expiry Panel** — breakdown by severity tier (CRITICAL / HIGH / MEDIUM / LOW)
- **Software Detected Panel** — third-party services identified from TXT records

---

## Tech Stack

- **Backend** — Python / FastAPI, streaming via `queue.Queue` → SSE
- **Recon** — `dnspython`, `requests`, `nmap`, `shodan`
- **Intelligence Sources** — crt.sh, HackerTarget, AlienVault OTX, Wayback Machine, ipinfo.io, Shodan InternetDB
- **Frontend** — Vanilla HTML/CSS/JS (single-file SPA), Server-Sent Events
- **Deployment** — Docker / Railway (auto-deploys on push to `main`)

---

## Running Locally

```bash
# From repo root
source .venv/Scripts/activate        # Windows Git Bash
pip install -r webapp/requirements.txt

cd webapp && python main.py
# → http://localhost:8000
```

Enter a domain and click **Scan**.

Set `SHODAN_API_KEY` in a `.env` file for full Shodan enrichment. Without a key, Shodan InternetDB (free) is used automatically.

---

## Deployment

Deployed via Docker on [Railway](https://railway.app). Any push to `main` triggers an automatic redeploy. The Dockerfile installs `nmap` in the container for port scanning.

---

## Disclaimer

This tool uses only passive, publicly available data sources. It does not conduct active scanning or send traffic directly to the target. Use responsibly and only against domains you own or have explicit permission to assess.
