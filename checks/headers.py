"""HTTP security header check."""
import urllib.request

EXPECTED = {
    "strict-transport-security": ("medium", "Add HSTS so browsers always use HTTPS."),
    "content-security-policy": ("medium", "Add a Content-Security-Policy to reduce XSS impact."),
    "x-frame-options": ("low", "Add X-Frame-Options (or CSP frame-ancestors) to stop clickjacking."),
    "x-content-type-options": ("low", "Add 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": ("low", "Add a Referrer-Policy to limit data leakage."),
}


def check_headers(host, timeout=6):
    url = f"https://{host}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ShieldScan/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
    except Exception as e:
        return [{"check": "headers", "severity": "info",
                 "title": "Could not fetch site over HTTPS",
                 "fix": f"Skipped header check. Detail: {e}"}]

    findings = []
    for name, (sev, fix) in EXPECTED.items():
        if name not in headers:
            findings.append({"check": "headers", "severity": sev,
                             "title": f"Missing header: {name}", "fix": fix})
    if "server" in headers and any(c.isdigit() for c in headers["server"]):
        findings.append({"check": "headers", "severity": "low",
                         "title": f"Server header reveals version: {headers['server']}",
                         "fix": "Hide server version info to slow down fingerprinting."})
    return findings
