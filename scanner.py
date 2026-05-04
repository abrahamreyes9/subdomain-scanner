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
    fetch_alienvault,
    fetch_wayback,
    fetch_whois,
    get_nameservers,
    attempt_zone_transfer,
    attempt_nsec_walk,
    dns_records as extract_dns_subdomains,
    resolve,
    collect_enrichment,
    collect_dns_records,
    detect_wildcard,
    generate_permutations,
    check_takeover,
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

        # ── Phase 0+1+2: Discovery (WHOIS, DNS, AXFR, passive) in parallel ───
        passive_sources = ["crt.sh", "HackerTarget"]
        if cfg.enable_wayback:
            passive_sources.append("Wayback")
        emit({"type": "phase", "phase": "whois",
              "message": f"Running WHOIS, DNS, and passive sources ({', '.join(passive_sources)}) in parallel..."})

        with ThreadPoolExecutor(max_workers=10) as ex:
            f_whois     = ex.submit(fetch_whois, domain)
            f_ns        = ex.submit(get_nameservers, domain)
            f_dns_sub   = ex.submit(extract_dns_subdomains, domain)
            f_dns_data  = ex.submit(collect_dns_records, domain)
            f_crt       = ex.submit(fetch_crtsh, domain)
            f_ht        = ex.submit(fetch_hackertarget, domain)
            f_otx       = ex.submit(fetch_alienvault, domain)
            f_wb        = (ex.submit(fetch_wayback, domain, cfg.max_wayback,
                                      cfg.wayback_delay, 30.0, cfg.user_agent)
                           if cfg.enable_wayback else None)
            f_wildcard  = ex.submit(detect_wildcard, domain)

            # WHOIS
            whois_data = _safe_result(f_whois, "WHOIS", ctx) or {}
            if isinstance(whois_data, set):  # _safe_result returns set on failure
                whois_data = {}
            if whois_data.get("registrar"):
                emit({"type": "status", "message": f"Registrar: {whois_data['registrar']}"})
            if whois_data.get("creation_date"):
                emit({"type": "status", "message": f"Created: {whois_data['creation_date']}  Expires: {whois_data.get('expiry_date', '?')}"})
            if whois_data.get("name_servers"):
                emit({"type": "status", "message": f"Name servers: {', '.join(whois_data['name_servers'][:4])}"})
            emit({"type": "whois", "data": whois_data})

            # DNS phase highlight
            emit({"type": "phase", "phase": "dns", "message": "Resolving DNS records..."})

            # Nameservers → AXFR (depends on f_ns; chained inside the same pool)
            try:
                nameservers = f_ns.result() or []
            except Exception:
                nameservers = []
            if nameservers:
                emit({"type": "status", "message": f"Nameservers: {', '.join(nameservers)}"})
            else:
                emit({"type": "status", "message": "No nameservers found"})

            f_axfr = ex.submit(attempt_zone_transfer, domain, nameservers) if nameservers else None
            f_nsec = (ex.submit(attempt_nsec_walk, domain, nameservers)
                      if nameservers and cfg.enable_nsec_walk else None)
            if f_axfr:
                emit({"type": "status",
                      "message": f"Attempting zone transfer (AXFR) on {len(nameservers)} nameserver(s)..."})
            if f_nsec:
                emit({"type": "status",
                      "message": f"Attempting DNSSEC NSEC zone walk..."})

            # DNS records (NS/MX/TXT/SRV)
            dns_sub = _safe_result(f_dns_sub, "DNS records", ctx)
            found |= dns_sub
            emit({"type": "status", "message": f"DNS records yielded {len(dns_sub)} subdomain(s)"})

            # MX / NS / TXT / SOA detail
            try:
                dns_data = f_dns_data.result()
            except Exception as e:
                ctx.emit({"type": "warning", "message": f"DNS detail failed: {e}"})
                dns_data = {}
            mx_count  = len(dns_data.get("mx", []))
            ns_count  = len(dns_data.get("ns", []))
            txt_count = len(dns_data.get("txt", []))
            emit({"type": "status", "message": f"MX: {mx_count}  NS: {ns_count}  TXT: {txt_count}"})
            emit({"type": "dns", "data": dns_data})

            # AXFR result
            if f_axfr:
                axfr = _safe_result(f_axfr, "AXFR", ctx)
                if axfr:
                    found |= axfr
                    emit({"type": "status", "message": f"Zone transfer succeeded — {len(axfr)} records leaked!"})
                else:
                    emit({"type": "status", "message": "Zone transfer refused (expected)"})

            # Passive sources
            emit({"type": "phase", "phase": "passive",
                  "message": "Collecting passive source results..."})
            crt = _safe_result(f_crt, "crt.sh", ctx)
            ht  = _safe_result(f_ht,  "HackerTarget", ctx)
            otx = _safe_result(f_otx, "AlienVault OTX", ctx)
            wb  = _safe_result(f_wb,  "Wayback Machine", ctx) if f_wb else set()
            found |= crt | ht | otx | wb
            emit({"type": "status", "message": f"crt.sh: {len(crt)} subdomains"})
            emit({"type": "status", "message": f"HackerTarget: {len(ht)} subdomains"})
            emit({"type": "status", "message": f"AlienVault OTX: {len(otx)} subdomains"})
            if cfg.enable_wayback:
                emit({"type": "status", "message": f"Wayback Machine: {len(wb)} subdomains"})

            # NSEC zone walk
            nsec = _safe_result(f_nsec, "NSEC walk", ctx) if f_nsec else set()
            if nsec:
                found |= nsec
                emit({"type": "status", "message": f"NSEC zone walk: {len(nsec)} names enumerated"})
            elif f_nsec:
                emit({"type": "status", "message": "NSEC walk: zone not signed with walkable NSEC"})

            # Wildcard detection
            try:
                wildcard_ips = f_wildcard.result() or set()
            except Exception:
                wildcard_ips = set()

        # Build per-source tracking: host → list of sources that found it
        host_sources: dict[str, list[str]] = {}
        for host in axfr or []:
            host_sources.setdefault(host, []).append("axfr")
        for host in dns_sub or []:
            host_sources.setdefault(host, []).append("dns")
        for host in crt or []:
            host_sources.setdefault(host, []).append("crtsh")
        for host in ht or []:
            host_sources.setdefault(host, []).append("hackertarget")
        for host in wb or []:
            host_sources.setdefault(host, []).append("wayback")
        for host in otx or []:
            host_sources.setdefault(host, []).append("alienvault")
        for host in nsec or []:
            host_sources.setdefault(host, []).append("nsec")

        emit({"type": "status", "message": f"Total unique so far: {len(found)}"})

        if ctx.cancelled:
            return

        # ── Phase 3+3.5+4: Unified resolution pool ────────────────────────────
        # All resolution work (brute-force, permutations, passive/DNS) shares
        # one ThreadPoolExecutor and one as_completed loop.  Permutations are
        # seeded from passive results immediately rather than waiting for
        # brute-force to finish.
        if wildcard_ips:
            emit({"type": "status",
                  "message": f"Wildcard DNS detected ({', '.join(wildcard_ips)}) — filtering false positives"})

        emit({"type": "phase", "phase": "brute",
              "message": "Resolving brute-force, permutations, and passive sources..."})

        brute_set = {f"{w}.{domain}" for w in COMMON_SUBDOMAINS}
        passive_set = set(found)  # found currently holds passive + DNS + AXFR results

        perm_set: set[str] = set()
        if cfg.enable_permutations and passive_set:
            perm_set = set(generate_permutations(
                passive_set, domain,
                max_perms=cfg.max_permutations,
                high_suffixes=cfg.high_value_suffixes,
                low_suffixes=cfg.low_value_suffixes,
                separators=cfg.permutation_separators,
            ))

        # Source tag per candidate (brute > permutation > passive priority for labelling).
        candidate_source: dict[str, str] = {}
        for c in passive_set:
            srcs = host_sources.get(c, ["passive"])
            candidate_source[c] = srcs[0]
        for c in perm_set:
            candidate_source.setdefault(c, "permutation")
        for c in brute_set:
            candidate_source[c] = "brute"

        total = len(candidate_source)
        completed = 0
        emit({"type": "status",
              "message": f"Resolving {total} candidates "
                         f"({len(brute_set)} brute, {len(perm_set)} permutations, "
                         f"{len(passive_set)} passive)..."})

        with ThreadPoolExecutor(max_workers=cfg.max_workers) as ex:
            futures = {ex.submit(resolve, c): c for c in candidate_source}
            for f in as_completed(futures):
                if ctx.cancelled:
                    ex.shutdown(wait=False, cancel_futures=True)
                    return
                completed += 1
                cand = futures[f]
                try:
                    result = f.result()
                except Exception:
                    result = None
                if result:
                    host, ip = result
                    if wildcard_ips and ip in wildcard_ips:
                        pass
                    elif host not in resolved:
                        resolved[host] = ip
                        found.add(host)
                        primary_source = candidate_source.get(cand, "passive")
                        # Get sources — either already tracked or use primary source
                        sources = host_sources.get(host)
                        if not sources:
                            sources = [primary_source] if primary_source else ["passive"]
                            # Track brute/permutation sources
                            if cand in brute_set:
                                host_sources[host] = ["brute"]
                                sources = ["brute"]
                            elif cand in perm_set:
                                host_sources[host] = ["permutation"]
                                sources = ["permutation"]
                            else:
                                host_sources[host] = sources
                        emit({"type": "subdomain", "host": host, "ip": ip,
                              "source": sources[0], "sources": sources})
                if completed % 50 == 0 or completed == total:
                    emit({"type": "progress", "phase": "brute",
                          "done": completed, "total": total,
                          "found": len(resolved)})

        emit({"type": "status",
              "message": f"Resolution complete — {len(resolved)} live subdomains total"})

        if ctx.cancelled:
            return

        # ── Phase 5: Enrich (streaming) ───────────────────────────────────────
        emit({"type": "phase", "phase": "enrich",
              "message": f"Enriching {len(resolved)} live subdomains..."})
        emit({"type": "status", "message": "Running HTTP probe, IP info, SSL cert, rDNS, nmap port scan, takeover check..."})

        def _emit_enriched(host: str, data: dict) -> None:
            info     = data.get("info", {})
            asn, org = _parse_org(info)
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
                "shodan":        data.get("shodan", {}),
                "takeover":      data.get("takeover"),
                "accessibility": data.get("accessibility", {}),
            })

        # Streams via on_host_complete: each host emits as soon as it's enriched.
        enriched = collect_enrichment(
            resolved, threads=cfg.enrich_threads,
            do_ports=cfg.enable_nmap, nmap_top_ports=cfg.nmap_top_ports,
            on_host_complete=(None if (cfg.shodan_key and shodan_lib) else _emit_enriched),
        )

        # ── Phase 5.5: Shodan Enrichment (Optional) — parallelised ───────────
        if cfg.shodan_key and shodan_lib:
            emit({"type": "status", "message": "Enriching results with Shodan data..."})
            api = shodan_lib.Shodan(cfg.shodan_key)

            def _fetch_shodan(item):
                host, ip = item
                try:
                    s_info = api.host(ip)
                    return host, {
                        "org":   s_info.get("org", ""),
                        "os":    s_info.get("os", ""),
                        "ports": s_info.get("ports", []),
                    }
                except Exception:
                    return host, None

            with ThreadPoolExecutor(max_workers=10) as ex:
                for host, s_data in ex.map(_fetch_shodan, list(resolved.items())):
                    if s_data is not None and host in enriched:
                        enriched[host]["shodan"] = s_data

            # Emit enriched events now that Shodan has been merged.
            for host, data in enriched.items():
                _emit_enriched(host, data)

        emit({"type": "status", "message": f"Enrichment complete — {len(enriched)} hosts processed"})
        emit({"type": "done", "total": len(resolved)})

    except Exception as exc:
        emit({"type": "error", "message": str(exc)})

    finally:
        q.put(None)  # sentinel — tells the stream to close
