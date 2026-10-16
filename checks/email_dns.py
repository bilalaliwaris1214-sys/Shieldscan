"""Email spoofing protection: SPF and DMARC."""
import dns.resolver


def _txt(name):
    try:
        return [b"".join(r.strings).decode() for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []


def check_email_dns(domain):
    findings = []
    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        findings.append({"check": "email", "severity": "high",
                         "title": "No SPF record found",
                         "fix": "Publish an SPF TXT record listing your authorized mail servers."})
    elif spf[0].rstrip().endswith("+all"):
        findings.append({"check": "email", "severity": "critical",
                         "title": "SPF allows any server to send mail (+all)",
                         "fix": "Change the ending to '-all' or '~all'."})

    dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append({"check": "email", "severity": "high",
                         "title": "No DMARC record found",
                         "fix": "Add a _dmarc TXT record, start with p=none and move to quarantine/reject."})
    elif "p=none" in dmarc[0].replace(" ", "").lower():
        findings.append({"check": "email", "severity": "medium",
                         "title": "DMARC policy is p=none (monitoring only)",
                         "fix": "After reviewing reports, move to p=quarantine or p=reject."})
    return findings
