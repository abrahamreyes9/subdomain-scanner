"""
scanner.py — runs subdomain enumeration in a background thread,
emitting structured events into a queue for the SSE stream.

V2: integrated Config, ScanContext, Wayback Machine, permutation engine,
    token-bucket DNS rate limiting, and cancellation support.
"""

import queue
try:
    import shodan as shodan_lib
except ImportError:
    shodan_lib = None

from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from config import Config
from context import ScanContext
from utils import init_dns_bucket

from subdomain_enum import (
    fetch_crtsh,
    fetch_hackertarget,
    fetch_wayback,
    fetch_whois,
    get_nameservers,
    attempt_zone_transfer,
    dns_records as extract_dns_subdomains,
    resolve,
    collect_enrichment,
    collect_dns_records,
    detect_wildcard,
    generate_permutations,
    COMMON_SUBDOMAINS,
    _parse_org,
)


def _safe_result(future: Future, source: str, ctx: ScanContext) -> set:
    """Return future result, emitting a warning and returning empty set on failure."""
    try:
        return future.result()
    except Exception as e:
        ctx.emit({"type": "warning", "message": f"{source} failed: {e}"})
        return set()


def run_scan(domain: str, q: queue.Queue,
             max_workers: int = 100, enrich_threads: int = 50,
             shodan_key: str = None, cfg: Config = None) -> None:
    """Run a full scan and push events into q. Puts None when done."""

    # ── Build config & context ────────────────────────────────────────────────
    if cfg is None:
        cfg = Config.load()
        cfg.max_workers = max_workers
        cfg.enrich_threads = enrich_threads
        if shodan_key:
            cfg.shodan_key = shodan_key

    ctx = ScanContext(q)
    emit = ctx.emit

    # Initialise DNS rate limiter
    init_dns_bucket(rate=cfg.dns_rate, burst=cfg.dns_burst)

    try:
        found: set[str] = set()
        resolved: dict[str, str] = {}

        # ── Phase 0: WHOIS ────────────────────────────────────────────────────
        emit({"type": "phase", "phase": "whois", "message": "Running WHOIS lookup..."})
        whois_data = fetch_whois(domain)
        if whois_data.get("registrar"):
            emit({"type": "status", "message": f"Registrar: {whois_data['registrar']}"})
        if whois_data.get("creation_date"):
            emit({"type": "status", "message": f"Created: {whois_data['creation_date']}  Expires: {whois_data.get('expiry_date', '?')}"})
        if whois_data.get("name_servers"):
            emit({"type": "status", "message": f"Name servers: {', '.join(whois_data['name_servers'][:4])}"})
        emit({"type": "whois", "data": whois_data})

        if ctx.cancelled:
            return

        # ── Phase 1: DNS ──────────────────────────────────────────────────────
        emit({"type": "phase", "phase": "dns", "message": "Fetching nameservers..."})

        nameservers = get_nameservers(domain)
        if nameservers:
            emit({"type": "status", "message": f"Nameservers: {', '.join(nameservers)}"})
        else:
            emit({"type": "status", "message": "No nameservers found"})

        emit({"type": "status", "message": f"Attempting zone transfer (AXFR) on {len(nameservers)} nameserver(s)..."})
        axfr = attempt_zone_transfer(domain, nameservers)
        if axfr:
            found |= axfr
            emit({"type": "status", "message": f"Zone transfer succeeded — {len(axfr)} records leaked!"})
        else:
            emit({"type": "status", "message": "Zone transfer refused (expected)"})

        emit({"type": "status", "message": "Querying NS / MX / TXT / SRV records..."})
        dns_sub = extract_dns_subdomains(domain)
        found |= dns_sub
        emit({"type": "status", "message": f"DNS records yielded {len(dns_sub)} subdomain(s)"})

        # Collect MX / NS / TXT / SOA records
        emit({"type": "status", "message": "Collecting MX / NS / TXT / SOA records..."})
        dns_data = collect_dns_records(domain)
        mx_count  = len(dns_data.get("mx", []))
        ns_count  = len(dns_data.get("ns", []))
        txt_count = len(dns_data.get("txt", []))
        emit({"type": "status", "message": f"MX: {mx_count}  NS: {ns_count}  TXT: {txt_count}"})
        emit({"type": "dns", "data": dns_data})

        emit({"type": "status", "message": f"Total unique so far: {len(found)}"})

        if ctx.cancelled:
            return

        # ── Phase 2: Passive sources ──────────────────────────────────────────
        passive_sources = ["crt.sh", "HackerTarget"]
        if cfg.enable_wayback:
            passive_sources.append("Wayback")
        emit({"type": "phase", "phase": "passive",
              "message": f"Querying passive sources ({', '.join(passive_sources)})..."})

        with ThreadPoolExecutor(max_workers=3) as ex:
            f_crt = ex.submit(fetch_crtsh, domain)
            f_ht  = ex.submit(fetch_hackertarget, domain)
            f_wb  = (ex.submit(fetch_wayback, domain, cfg.max_wayback,
                               cfg.wayback_delay, 30.0, cfg.user_agent)
                     if cfg.enable_wayback else None)

            crt = _safe_result(f_crt, "crt.sh", ctx)
            ht  = _safe_result(f_ht,  "HackerTarget", ctx)
            wb  = _safe_result(f_wb,  "Wayback Machine", ctx) if f_wb else set()

        found |= crt | ht | wb
        emit({"type": "status", "message": f"crt.sh: {len(crt)} subdomains"})
        emit({"type": "status", "message": f"HackerTarget: {len(ht)} subdomains"})
        if cfg.enable_wayback:
            emit({"type": "status", "message": f"Wayback Machine: {len(wb)} subdomains"})
        emit({"type": "status", "message": f"Total unique so far: {len(found)}"})

        if ctx.cancelled:
            return

        # ── Phase 3: Brute-force ──────────────────────────────────────────────
        # Detect wildcard DNS before brute-forcing
        wildcard_ip = detect_wildcard(domain)
        if wildcard_ip:
            emit({"type": "status",
                  "message": f"Wildcard DNS detected ({wildcard_ip}) — filtering false positives"})

        emit({"type": "phase", "phase": "brute",
              "message": f"Brute-forcing {len(COMMON_SUBDOMAINS)} common subdomains..."})

        candidates = [f"{w}.{domain}" for w in COMMON_SUBDOMAINS]
        total_brute = len(candidates)
        completed_brute = 0

        with ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
            futures = {ex.submit(resolve, c): c for c in candidates}
            for f in as_completed(futures):
                if ctx.cancelled:
                    ex.shutdown(wait=False, cancel_futures=True)
                    return
                result = f.result()
                completed_brute += 1
                if result:
                    host, ip = result
                    # Filter wildcard matches
                    if wildcard_ip and ip == wildcard_ip:
                        continue
                    found.add(host)
                    resolved[host] = ip
                    emit({"type": "subdomain", "host": host, "ip": ip, "source": "brute"})
                if completed_brute % 50 == 0 or completed_brute == total_brute:
                    emit({"type": "progress", "phase": "brute",
                          "done": completed_brute, "total": total_brute,
                          "found": len(resolved)})

        emit({"type": "status", "message": f"Brute-force complete — {len(resolved)} live"})

        # ── Phase 3.5: Smart permutations ─────────────────────────────────────
        if cfg.enable_permutations and found:
            perm_candidates = generate_permutations(
                found, domain,
                max_perms=cfg.max_permutations,
                high_suffixes=cfg.high_value_suffixes,
                low_suffixes=cfg.low_value_suffixes,
                separators=cfg.permutation_separators,
            )

            if perm_candidates:
                emit({"type": "status",
                      "message": f"Resolving {len(perm_candidates)} smart permutations..."})

                total_perm = len(perm_candidates)
                completed_perm = 0

                with ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
                    futures = {ex.submit(resolve, c): c for c in perm_candidates}
                    for f in as_completed(futures):
                        if ctx.cancelled:
                            ex.shutdown(wait=False, cancel_futures=True)
                            return
                        result = f.result()
                        completed_perm += 1
                        if result:
                            host, ip = result
                            if wildcard_ip and ip == wildcard_ip:
                                continue
                            found.add(host)
                            resolved[host] = ip
                            emit({"type": "subdomain", "host": host, "ip": ip,
                                  "source": "permutation"})
                        if completed_perm % 50 == 0 or completed_perm == total_perm:
                            emit({"type": "progress", "phase": "brute",
                                  "done": total_brute + completed_perm,
                                  "total": total_brute + total_perm,
                                  "found": len(resolved)})

                emit({"type": "status",
                      "message": f"Permutations complete — {len(resolved)} live total"})

        emit({"type": "status", "message": f"Total unique so far: {len(found)}"})

        if ctx.cancelled:
            return

        # ── Phase 4: Resolve passive/DNS hits not yet resolved ────────────────
        passive_only = found - set(resolved.keys())
        if passive_only:
            emit({"type": "phase", "phase": "resolve",
                  "message": f"Resolving {len(passive_only)} passive/DNS subdomains..."})
            total_resolve = len(passive_only)
            completed_resolve = 0

            with ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
                futures = {ex.submit(resolve, s): s for s in passive_only}
                for f in as_completed(futures):
                    if ctx.cancelled:
                        ex.shutdown(wait=False, cancel_futures=True)
                        return
                    result = f.result()
                    completed_resolve += 1
                    if result:
                        host, ip = result
                        if wildcard_ip and ip == wildcard_ip:
                            continue
                        resolved[host] = ip
                        emit({"type": "subdomain", "host": host, "ip": ip, "source": "passive"})
                    if completed_resolve % 50 == 0 or completed_resolve == total_resolve:
                        emit({"type": "progress", "phase": "resolve",
                              "done": completed_resolve, "total": total_resolve,
                              "found": len(resolved)})

            emit({"type": "status", "message": f"Resolve complete — {len(resolved)} live subdomains total"})

        if ctx.cancelled:
            return

        # ── Phase 5: Enrich ───────────────────────────────────────────────────
        emit({"type": "phase", "phase": "enrich",
              "message": f"Enriching {len(resolved)} live subdomains..."})
        emit({"type": "status", "message": "Running HTTP probe, IP info, SSL cert, rDNS, nmap port scan, takeover check..."})

        # Using optimized enrichment with shared connection pool
        enriched = collect_enrichment(
            resolved, threads=cfg.enrich_threads,
            do_ports=cfg.enable_nmap, nmap_top_ports=cfg.nmap_top_ports,
        )

        # ── Phase 5.5: Shodan Enrichment (Optional) ──────────────────────────
        if cfg.shodan_key and shodan_lib:
            emit({"type": "status", "message": "Enriching results with Shodan data..."})
            api = shodan_lib.Shodan(cfg.shodan_key)
            for host, ip in resolved.items():
                try:
                    s_info = api.host(ip)
                    enriched[host]["shodan"] = {
                        "org":   s_info.get("org", ""),
                        "os":    s_info.get("os", ""),
                        "ports": s_info.get("ports", []),
                    }
                except Exception:
                    continue

        emit({"type": "status", "message": f"Enrichment complete — {len(enriched)} hosts processed"})

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
                "shodan":   data.get("shodan", {}),
                "takeover": data.get("takeover"),
            })

        emit({"type": "done", "total": len(resolved)})

    except Exception as exc:
        emit({"type": "error", "message": str(exc)})

    finally:
        q.put(None)  # sentinel — tells the stream to close
