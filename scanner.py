"""
scanner.py — runs subdomain enumeration in a background thread,
emitting structured events into a queue for the SSE stream.
"""

import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from subdomain_enum import (
    fetch_crtsh,
    fetch_hackertarget,
    get_nameservers,
    attempt_zone_transfer,
    dns_records as extract_dns_subdomains,
    resolve,
    collect_enrichment,
    collect_dns_records,
    COMMON_SUBDOMAINS,
    _parse_org,
)


def run_scan(domain: str, q: queue.Queue) -> None:
    """Run a full scan and push events into q. Puts None when done."""

    def emit(data: dict) -> None:
        q.put(data)

    try:
        found: set[str] = set()
        resolved: dict[str, str] = {}

        # ── Phase 1: DNS ──────────────────────────────────────────────────────
        emit({"type": "phase", "phase": "dns", "message": "Fetching nameservers..."})

        nameservers = get_nameservers(domain)
        if nameservers:
            emit({"type": "status", "message": f"Nameservers: {', '.join(nameservers)}"})

        emit({"type": "status", "message": "Attempting zone transfer (AXFR)..."})
        axfr = attempt_zone_transfer(domain, nameservers)
        if axfr:
            found |= axfr
            emit({"type": "status", "message": f"Zone transfer succeeded — {len(axfr)} records!"})
        else:
            emit({"type": "status", "message": "Zone transfer refused (expected)"})

        emit({"type": "status", "message": "Extracting subdomains from NS/MX/TXT/SRV records..."})
        dns_sub = extract_dns_subdomains(domain)
        found |= dns_sub
        emit({"type": "status", "message": f"DNS records yielded {len(dns_sub)} subdomains"})

        # ── Phase 2: Passive sources ──────────────────────────────────────────
        emit({"type": "phase", "phase": "passive", "message": "Querying passive sources..."})

        with ThreadPoolExecutor(max_workers=2) as ex:
            f_crt = ex.submit(fetch_crtsh, domain)
            f_ht  = ex.submit(fetch_hackertarget, domain)
            crt   = f_crt.result()
            ht    = f_ht.result()

        found |= crt | ht
        emit({"type": "status",
              "message": f"crt.sh: {len(crt)}  HackerTarget: {len(ht)}"})

        # ── Phase 3: Brute-force ──────────────────────────────────────────────
        emit({"type": "phase", "phase": "brute",
              "message": f"Brute-forcing {len(COMMON_SUBDOMAINS)} common subdomains..."})

        candidates = [f"{w}.{domain}" for w in COMMON_SUBDOMAINS]
        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = {ex.submit(resolve, c): c for c in candidates}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    host, ip = result
                    found.add(host)
                    resolved[host] = ip
                    emit({"type": "subdomain", "host": host, "ip": ip, "source": "brute"})

        # ── Phase 4: Resolve passive/DNS hits not yet resolved ────────────────
        passive_only = found - set(resolved.keys())
        if passive_only:
            emit({"type": "phase", "phase": "resolve",
                  "message": f"Resolving {len(passive_only)} passive subdomains..."})
            with ThreadPoolExecutor(max_workers=100) as ex:
                futures = {ex.submit(resolve, s): s for s in passive_only}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        host, ip = result
                        resolved[host] = ip
                        emit({"type": "subdomain", "host": host, "ip": ip, "source": "passive"})

        # ── Phase 5: Enrich ───────────────────────────────────────────────────
        emit({"type": "phase", "phase": "enrich",
              "message": f"Enriching {len(resolved)} live subdomains (HTTP probe, IP info, SSL)..."})

        enriched = collect_enrichment(resolved, threads=50)

        for host, data in enriched.items():
            info      = data.get("info", {})
            asn, org  = _parse_org(info)
            emit({
                "type":     "enriched",
                "host":     host,
                "ip":       data.get("ip", ""),
                "rdns":     data.get("rdns", ""),
                "asn":      asn,
                "org":      org,
                "cidr":     info.get("network", ""),
                "country":  info.get("country", ""),
                "http":     data.get("http", {}),
                "ssl":      data.get("ssl", {}),
                "ports":    data.get("ports", []),
                "takeover": data.get("takeover"),
            })

        # ── Phase 6: DNS records ──────────────────────────────────────────────
        emit({"type": "phase", "phase": "dns_records",
              "message": "Collecting MX / NS / TXT / SOA records..."})

        dns_data = collect_dns_records(domain)
        emit({"type": "dns", "data": dns_data})

        emit({"type": "done", "total": len(resolved)})

    except Exception as exc:
        emit({"type": "error", "message": str(exc)})

    finally:
        q.put(None)  # sentinel — tells the stream to close
