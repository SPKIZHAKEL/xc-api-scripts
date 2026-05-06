#!/usr/bin/env python3
"""
F5 XC Tenant-Wide CNAME Checker
---------------------------------
1. Fetches all namespaces in the tenant
2. For each namespace, fetches all HTTP load balancers
3. Extracts all configured domains from each LB
4. Performs DNS CNAME lookups on every domain
5. Counts domains whose CNAME ends in *.ves.io  (actively on F5 XC)
6. Prints per-namespace breakdown + tenant-wide total

Usage:
    python f5xc_cname_check.py --tenant <tenant> --token <api_token>

    Or set env vars:
        F5XC_TENANT, F5XC_TOKEN
"""

import argparse
import os
import sys
import json
import subprocess
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Matches any CNAME ending in *.ves.io (with optional trailing dot)
VES_IO_PATTERN = re.compile(r"\.ves\.io\.?$", re.IGNORECASE)

# System namespaces to skip (internal F5 XC namespaces)
SKIP_NAMESPACES = {"system", "shared", "default"}


# ── API helpers ───────────────────────────────────────────────────────────────

def _get(session: requests.Session, url: str) -> dict:
    log.debug("GET %s", url)
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_namespaces(session: requests.Session, tenant: str) -> list[str]:
    """Return list of namespace names for the tenant."""
    url = f"https://{tenant}.console.ves.volterra.io/api/web/namespaces"
    data = _get(session, url)
    names = [item["name"] for item in data.get("items", []) if item.get("name")]
    filtered = [n for n in names if n not in SKIP_NAMESPACES]
    log.info("Found %d namespace(s) (skipped system ones): %s", len(filtered), filtered)
    return filtered


def get_load_balancers(session: requests.Session, tenant: str, namespace: str) -> list[dict]:
    """Return all HTTP LB items in a namespace."""
    url = f"https://{tenant}.console.ves.volterra.io/api/config/namespaces/{namespace}/http_loadbalancers?report_fields"
    try:
        data = _get(session, url)
        items = data.get("items", [])
        log.debug("  Namespace '%s': %d LB(s)", namespace, len(items))
        return items
    except requests.HTTPError as e:
        log.warning("  Namespace '%s': API error %s — skipping", namespace, e)
        return []


def extract_domains(items: list[dict]) -> dict[str, list[str]]:
    """Return mapping lb_name -> [domain, ...] from LB items."""
    result: dict[str, list[str]] = {}
    for item in items:
        name = item.get("name", "<unknown>")
        domains = item.get("get_spec", {}).get("domains", [])
        if domains:
            result[name] = domains
    return result


# ── DNS ───────────────────────────────────────────────────────────────────────

def dig_cname(domain: str) -> str | None:
    """Run dig +short CNAME <domain> and return the CNAME, or None."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines[-1] if lines else None
    except FileNotFoundError:
        return _fallback_cname(domain)
    except subprocess.TimeoutExpired:
        log.warning("dig timed out for %s", domain)
        return None


def _fallback_cname(domain: str) -> str | None:
    """Fallback: dnspython -> Cloudflare DoH."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target)
    except Exception:
        pass
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=CNAME"
        resp = requests.get(url, headers={"Accept": "application/dns-json"}, timeout=10)
        answers = resp.json().get("Answer", [])
        cnames = [a["data"] for a in answers if a.get("type") == 5]
        return cnames[-1] if cnames else None
    except Exception:
        return None


def is_on_xc(cname: str | None) -> bool:
    """Return True if the CNAME ends with *.ves.io"""
    return bool(cname and VES_IO_PATTERN.search(cname))


# ── Core logic ────────────────────────────────────────────────────────────────

def check_domain(namespace: str, lb: str, domain: str) -> dict:
    cname = dig_cname(domain)
    return {
        "namespace": namespace,
        "lb": lb,
        "domain": domain,
        "cname": cname or "N/A",
        "on_xc": is_on_xc(cname),
    }


# ── Formatting ────────────────────────────────────────────────────────────────

COL = {"ns": 22, "lb": 28, "domain": 36, "cname": 46}
DIVIDER = "─" * (sum(COL.values()) + 12)

def print_header():
    print("\n" + DIVIDER)
    print(
        f"{'NAMESPACE':<{COL['ns']}} {'LOAD BALANCER':<{COL['lb']}} "
        f"{'DOMAIN':<{COL['domain']}} {'CNAME':<{COL['cname']}} ON XC?"
    )
    print(DIVIDER)

def print_row(r: dict):
    flag = "YES" if r["on_xc"] else " no"
    print(
        f"{r['namespace'][:COL['ns']-1]:<{COL['ns']}} "
        f"{r['lb'][:COL['lb']-1]:<{COL['lb']}} "
        f"{r['domain'][:COL['domain']-1]:<{COL['domain']}} "
        f"{r['cname'][:COL['cname']-1]:<{COL['cname']}} {flag}"
    )

def print_ns_subtotal(namespace: str, ns_res: list[dict]):
    on_xc = sum(1 for r in ns_res if r["on_xc"])
    print(f"  >> [{namespace}]  {on_xc} / {len(ns_res)} domain(s) on F5 XC")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Tenant-wide F5 XC domain CNAME checker"
    )
    p.add_argument("--tenant",         default=os.getenv("F5XC_TENANT"), help="F5 XC tenant name")
    p.add_argument("--token",          default=os.getenv("F5XC_TOKEN"),  help="F5 XC API token")
    p.add_argument("--workers",        type=int, default=20,             help="Parallel DNS workers (default: 20)")
    p.add_argument("--output",         default=None,                     help="Optional JSON output file")
    p.add_argument("--include-system", action="store_true",              help="Include system/shared/default namespaces")
    p.add_argument("--verbose",        action="store_true",              help="Debug logging")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.tenant or not args.token:
        log.error("--tenant and --token are required (or set F5XC_TENANT / F5XC_TOKEN)")
        sys.exit(1)

    if args.include_system:
        SKIP_NAMESPACES.clear()

    # Session with auth header
    session = requests.Session()
    session.headers.update({
        "Authorization": f"APIToken {args.token}",
        "Accept": "application/json",
    })

    # ── 1. Get all namespaces ─────────────────────────────────────────────────
    try:
        namespaces = get_namespaces(session, args.tenant)
    except requests.HTTPError as e:
        log.error("Failed to fetch namespaces: %s", e)
        sys.exit(1)

    if not namespaces:
        log.warning("No namespaces found for tenant '%s'", args.tenant)
        sys.exit(0)

    # ── 2. Collect all (namespace, lb, domain) tuples ─────────────────────────
    all_tasks: list[tuple[str, str, str]] = []
    ns_lb_map: dict[str, dict[str, list[str]]] = {}

    log.info("Scanning %d namespace(s) for load balancers...", len(namespaces))
    for ns in namespaces:
        items = get_load_balancers(session, args.tenant, ns)
        lb_domains = extract_domains(items)
        ns_lb_map[ns] = lb_domains
        for lb_name, domains in lb_domains.items():
            for domain in domains:
                all_tasks.append((ns, lb_name, domain))

    total_domains = len(all_tasks)
    log.info("Total domains to DNS-check: %d", total_domains)

    if total_domains == 0:
        print("\nNo domains configured on any load balancer across all namespaces.")
        sys.exit(0)

    # ── 3. Parallel DNS lookups ────────────────────────────────────────────────
    print_header()

    all_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check_domain, ns, lb, domain): (ns, lb, domain)
            for ns, lb, domain in all_tasks
        }
        completed = [f.result() for f in as_completed(futures)]

    # Sort by namespace -> lb -> domain for clean grouped output
    completed.sort(key=lambda r: (r["namespace"], r["lb"], r["domain"]))

    ns_results_map: dict[str, list[dict]] = {ns: [] for ns in namespaces}
    prev_ns = None

    for r in completed:
        if r["namespace"] != prev_ns:
            if prev_ns is not None:
                print()
                print_ns_subtotal(prev_ns, ns_results_map[prev_ns])
                print()
            prev_ns = r["namespace"]
        print_row(r)
        ns_results_map[r["namespace"]].append(r)
        all_results.append(r)

    if prev_ns:
        print()
        print_ns_subtotal(prev_ns, ns_results_map[prev_ns])

    # ── 4. Grand summary ───────────────────────────────────────────────────────
    total_on_xc = sum(1 for r in all_results if r["on_xc"])
    total_lbs   = sum(len(lbs) for lbs in ns_lb_map.values())

    print("\n" + "=" * 60)
    print(f"  TENANT-WIDE SUMMARY  |  {args.tenant}")
    print("=" * 60)
    print(f"  Namespaces scanned     : {len(namespaces)}")
    print(f"  Load balancers found   : {total_lbs}")
    print(f"  Total domains checked  : {total_domains}")
    print(f"  Domains ON F5 XC       : {total_on_xc}   (CNAME -> *.ves.io)")
    print(f"  Domains NOT on F5 XC   : {total_domains - total_on_xc}")
    if total_domains:
        print(f"  Coverage               : {total_on_xc / total_domains * 100:.1f}%")
    print("=" * 60)

    print("\n  Per-namespace breakdown:")
    print(f"  {'Namespace':<30} {'On XC':>6}  {'Total':>6}")
    print(f"  {'-'*30}  {'-'*6}  {'-'*6}")
    for ns in namespaces:
        ns_res = ns_results_map.get(ns, [])
        if not ns_res:
            continue
        on_xc = sum(1 for r in ns_res if r["on_xc"])
        print(f"  {ns:<30} {on_xc:>6}  {len(ns_res):>6}")
    print()

    # ── 5. Optional JSON output ────────────────────────────────────────────────
    if args.output:
        payload = {
            "tenant": args.tenant,
            "summary": {
                "namespaces_scanned": len(namespaces),
                "load_balancers": total_lbs,
                "total_domains": total_domains,
                "domains_on_xc": total_on_xc,
                "domains_not_on_xc": total_domains - total_on_xc,
                "coverage_pct": round(total_on_xc / total_domains * 100, 1) if total_domains else 0,
            },
            "per_namespace": {
                ns: {
                    "total": len(ns_results_map.get(ns, [])),
                    "on_xc": sum(1 for r in ns_results_map.get(ns, []) if r["on_xc"]),
                }
                for ns in namespaces if ns_results_map.get(ns)
            },
            "results": all_results,
        }
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2)
        log.info("Full results written to %s", args.output)


if __name__ == "__main__":
    main()
