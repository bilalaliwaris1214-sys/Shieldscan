#!/usr/bin/env python3
"""ShieldScan - external attack surface checker for domains YOU OWN or have written permission to test."""
import argparse
import json
import sys

from checks.email_dns import check_email_dns
from checks.headers import check_headers
from checks.ports import check_ports
from checks.ssl_check import check_ssl

WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
ORDER = ["critical", "high", "medium", "low", "info"]


def run(domain):
    findings = []
    for fn in (check_ssl, check_headers, check_email_dns, check_ports):
        findings += fn(domain)
    findings.sort(key=lambda f: ORDER.index(f["severity"]))
    score = max(0, 100 - sum(WEIGHTS[f["severity"]] for f in findings))
    return {"domain": domain, "score": score, "findings": findings}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("domain")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you own this domain or have written permission to scan it")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    if not args.authorized:
        sys.exit("Refusing to scan: pass --authorized only for domains you own or have written permission to test.")

    report = run(args.domain)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(f"\nShieldScan report for {report['domain']}  |  Security score: {report['score']}/100\n")
    for f in report["findings"]:
        print(f"[{f['severity'].upper():8}] {f['title']}\n           Fix: {f['fix']}\n")
    if not report["findings"]:
        print("No issues found.")


if __name__ == "__main__":
    main()
