# Subdomain Scanner

A passive reconnaissance tool that gives you an attacker's view of your external attack surface — without running a single scan.

## Why I Built This

Traditional attack surface tools are either expensive enterprise platforms, require active scanning (which triggers alerts and firewalls), or take days to set up. I wanted something I could point at any domain and instantly see what an attacker sees — all subdomains, what's running on them, who hosts them, and how they're configured — using only passive, publicly available data sources.

The goal: **know your attack surface before an attacker does.**

---

## What It Does

The scanner combines multiple passive intelligence sources and semi-active techniques (such as DNS brute-forcing and lightweight port scanning) to discover and enrich every subdomain associated with a target domain.

### Discovery Sources

| Source | What it finds |
|---|---|
| **Certificate Transparency (crt.sh)** | Every subdomain that has ever had a TLS certificate issued |
| **HackerTarget** | Passive DNS dataset aggregated from public sources |
| **DNS Zone Transfer (AXFR)** | Full zone dump if a nameserver is misconfigured |
| **DNS Records (NS/MX/TXT/SRV)** | Subdomains referenced in mail, nameserver, SPF and service records |
| **Brute-force** | 200+ common subdomain prefixes resolved against live DNS |

### Enrichment (per subdomain)

Once subdomains are discovered, each one is enriched with:

- **IP address** and **Reverse DNS**
- **ASN, Organisation, CIDR block** and **Country** (via ipinfo.io)
- **HTTP/HTTPS service probing** — server headers, page titles, technology detection
- **SSL certificate info** — Common Name and Organisation
- **SSH banner** (nameservers only)

### DNS Intelligence

- **MX Records** — mail infrastructure with IP/ASN enrichment
- **NS Records** — nameservers with SSH banner detection
- **TXT Records** — SPF, DKIM, domain verification tokens, third-party integrations
- **SOA Record** — zone authority and serial number

---

## Outputs

| Export | Contents |
|---|---|
| **Full Report (.txt)** | Human-readable report with all enriched data, DNS records and service info |
| **HTML Report** | Interactive version of the full report viewable in any browser |
| **IP/Subdomains List (.txt)** | Clean `IP \| Domain` list for direct import into Qualys, Tenable, or Rapid7 |

---

## Tech Stack

- **Backend** — Python / FastAPI
- **Recon** — `dnspython`, `requests`, ipinfo.io, crt.sh, HackerTarget
- **Frontend** — Vanilla HTML/CSS/JS with real-time streaming via Server-Sent Events (SSE)
- **Deployment** — Docker / Railway

---

## Running Locally

```bash
pip install -r requirements.txt
python main.py
```

Open [http://localhost:8000](http://localhost:8000), enter a domain and click **Scan**.

---

## Deployment

Deployed via Docker on [Railway](https://railway.app). Any push to `main` triggers an automatic redeploy.

---

## Disclaimer

This tool uses only passive, publicly available data sources. It does not conduct active scanning or send traffic directly to the target. Use responsibly and only against domains you own or have explicit permission to assess.
