"""TCP port check for common risky services."""
import socket
from concurrent.futures import ThreadPoolExecutor

# port -> (service, why it matters)
RISKY = {
    21: ("FTP", "Unencrypted file transfer"),
    22: ("SSH", "Brute-force target if exposed"),
    23: ("Telnet", "Unencrypted remote login"),
    445: ("SMB", "Common ransomware entry point"),
    3306: ("MySQL", "Database should not be public"),
    3389: ("RDP", "Common ransomware entry point"),
    5432: ("PostgreSQL", "Database should not be public"),
    6379: ("Redis", "Often exposed without auth"),
    27017: ("MongoDB", "Often exposed without auth"),
}
COMMON = {80: "HTTP", 443: "HTTPS", **{p: v[0] for p, v in RISKY.items()}}


def _probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def check_ports(host, timeout=1.5):
    findings = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = pool.map(lambda p: _probe(host, p, timeout), COMMON)
    for port in filter(None, results):
        if port in RISKY:
            name, why = RISKY[port]
            findings.append({
                "check": "ports", "severity": "high",
                "title": f"Port {port} ({name}) is open to the internet",
                "fix": f"{why}. Close it or restrict access with a firewall/VPN.",
            })
    return findings
