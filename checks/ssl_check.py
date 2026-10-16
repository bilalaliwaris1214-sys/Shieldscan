"""TLS certificate expiry and protocol check."""
import socket
import ssl
from datetime import datetime, timezone


def check_ssl(host, port=443, timeout=5):
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        return [{"check": "ssl", "severity": "critical",
                 "title": "TLS certificate failed verification",
                 "fix": f"Install a valid certificate (e.g. Let's Encrypt). Detail: {e.verify_message}"}]
    except OSError as e:
        return [{"check": "ssl", "severity": "medium",
                 "title": "Could not establish TLS connection on port 443",
                 "fix": f"Enable HTTPS on the site. Detail: {e}"}]

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    if days < 0:
        findings.append({"check": "ssl", "severity": "critical",
                         "title": "TLS certificate has expired",
                         "fix": "Renew the certificate immediately."})
    elif days < 30:
        findings.append({"check": "ssl", "severity": "medium",
                         "title": f"TLS certificate expires in {days} days",
                         "fix": "Renew soon and enable auto-renewal."})
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append({"check": "ssl", "severity": "high",
                         "title": f"Outdated protocol negotiated: {version}",
                         "fix": "Disable TLS 1.0/1.1 and allow only TLS 1.2+."})
    return findings
