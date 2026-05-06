import requests
import json
import csv
import argparse
import os
import sys
import json
import subprocess
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed



#!/usr/bin/env python3
"""
F5 XC Load Balancer CNAME Checker
-----------------------------------
Fetches all HTTP load balancers in a given namespace, extracts their domains,
performs DNS CNAME lookups, and counts how many resolve to a ves.io CNAME
(indicating the domain is actively routed through F5 XC).

Usage:
    python f5xc_cname_check.py --tenant <tenant> --namespace <namespace> --token

    Or set env vars:
        F5XC_TENANT, F5XC_NAMESPACE, F5XC_TOKEN
"""


try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

VES_IO_PATTERN = re.compile(r"\.ves\.io\.?$", re.IGNORECASE)


# ── API ───────────────────────────────────────────────────────────────────────

def get_load_balancers(tenant: str, namespace: str, token: str) -> list[dict]:
    """Return all HTTP LB items from the F5 XC API."""
    url = f"https://{tenant}.console.ves.volterra.io/api/config/namespaces/{namespace}/http_loadbalancers?report_fields"
    headers = {
        "Authorization": f"APIToken {token}",
        "Accept": "application/json",
    }
    log.info("GET %s", url)
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("items", [])
    log.info("Fetched %d load balancer(s)", len(items))
    return items


def extract_domains(items: list[dict]) -> dict[str, list[str]]:
    """
    Return a mapping of  lb_name -> [domain, ...].
    Domains live at  item.get_spec.domains  (list of strings).
    """
    result: dict[str, list[str]] = {}
    for item in items:
        name = item.get("name", "<unknown>")
        spec = item.get("get_spec", {})
        domains = spec.get("domains", [])
        if domains:
            result[name] = domains
        else:
            log.debug("LB '%s' has no domains configured", name)
    return result


# ── DNS ───────────────────────────────────────────────────────────────────────

def dig_cname(domain: str) -> str | None:
    """
    Run  dig +short CNAME <domain>  and return the CNAME value, or None.
    Falls back to a simple check if dig is unavailable.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip()
        # dig may return multiple lines; take the last non-empty one
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        return lines[-1] if lines else None
    except FileNotFoundError:
        # dig not available – try socket/dnspython fallback
        return _fallback_cname(domain)
    except subprocess.TimeoutExpired:
        log.warning("dig timed out for %s", domain)
        return None


def _fallback_cname(domain: str) -> str | None:
    """Fallback using dnspython if available, otherwise None."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target)
    except Exception:
        try:
            # Last resort: use the system resolver via DoH (Cloudflare)
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=CNAME"
            resp = requests.get(url, headers={"Accept": "application/dns-json"}, timeout=10)
            data = resp.json()
            answers = data.get("Answer", [])
            cnames = [a["data"] for a in answers if a.get("type") == 5]
            return cnames[-1] if cnames else None
        except Exception:
            return None


def is_ves_io_cname(cname: str | None) -> bool:
    """Return True if the CNAME matches *.ves.io (with optional trailing dot)."""
    if not cname:
        return False
    return bool(VES_IO_PATTERN.search(cname))


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check which F5 XC LB domains resolve to a ves.io CNAME"
    )
    p.add_argument("--tenant",    default=os.getenv("F5XC_TENANT"),    help="F5 XC tenant name (subdomain)")
    p.add_argument("--namespace", default=os.getenv("F5XC_NAMESPACE"), help="F5 XC namespace")
    p.add_argument("--token",     default=os.getenv("F5XC_TOKEN"),     help="F5 XC API token")
    p.add_argument("--workers",   type=int, default=10,                 help="Parallel DNS workers (default: 10)")
    p.add_argument("--output",    default=None,                         help="Optional JSON output file path")
    p.add_argument("--verbose",   action="store_true",                  help="Show DEBUG logs")
    return p.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate required args
    missing = [f for f, v in [("--tenant", args.tenant), ("--namespace", args.namespace), ("--token", args.token)] if not v]
    if missing:
        log.error("Missing required argument(s): %s", ", ".join(missing))
        log.error("Set them via CLI flags or env vars: F5XC_TENANT, F5XC_NAMESPACE, F5XC_TOKEN")
        sys.exit(1)

    # ── 1. Fetch LBs ──────────────────────────────────────────────────────────
    try:
        items = get_load_balancers(args.tenant, args.namespace, args.token)
    except requests.HTTPError as e:
        log.error("API request failed: %s", e)
        sys.exit(1)

    lb_domains = extract_domains(items)

    if not lb_domains:
        log.warning("No load balancers with domains found in namespace '%s'", args.namespace)
        sys.exit(0)

    # Flatten all domains with their LB name for lookup
    all_domains: list[tuple[str, str]] = [
        (lb_name, domain)
        for lb_name, domains in lb_domains.items()
        for domain in domains
    ]

    total_domains = len(all_domains)
    log.info("Total domains to check: %d across %d load balancer(s)", total_domains, len(lb_domains))

    # ── 2. DNS CNAME lookups (parallel) ───────────────────────────────────────
    print("\n" + "─" * 70)
    print(f"{'LOAD BALANCER':<30} {'DOMAIN':<35} {'CNAME':<40} {'VES.IO?'}")
    print("─" * 70)

    results: list[dict] = []
    ves_io_count = 0

    def check(lb_name: str, domain: str) -> dict:
        cname = dig_cname(domain)
        on_xc = is_ves_io_cname(cname)
        return {"lb": lb_name, "domain": domain, "cname": cname, "on_xc": on_xc}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check, lb_name, domain): (lb_name, domain)
            for lb_name, domain in all_domains
        }
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            flag = "✅ YES" if r["on_xc"] else "❌  no"
            if r["on_xc"]:
                ves_io_count += 1
            print(
                f"{r['lb'][:29]:<30} {r['domain'][:34]:<35} "
                f"{(r['cname'] or 'N/A')[:39]:<40} {flag}"
            )

    # ── 3. Summary ────────────────────────────────────────────────────────────
    print("─" * 70)
    print(f"\n📊  SUMMARY  —  Namespace: {args.namespace}  |  Tenant: {args.tenant}")
    print(f"   Load balancers checked : {len(lb_domains)}")
    print(f"   Total domains checked  : {total_domains}")
    print(f"   Domains on F5 XC       : {ves_io_count}  (CNAME → ves.io)")
    print(f"   Domains NOT on F5 XC   : {total_domains - ves_io_count}")
    print(f"   Coverage               : {ves_io_count/total_domains*100:.1f}%" if total_domains else "")
    print()

    # ── 4. Optional JSON output ───────────────────────────────────────────────
    if args.output:
        payload = {
            "tenant": args.tenant,
            "namespace": args.namespace,
            "summary": {
                "load_balancers": len(lb_domains),
                "total_domains": total_domains,
                "domains_on_xc": ves_io_count,
                "domains_not_on_xc": total_domains - ves_io_count,
            },
            "results": sorted(results, key=lambda x: (x["lb"], x["domain"])),
        }
        with open(args.output, "w") as f:
            json.dump(payload, f, indent=2)
        log.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()
