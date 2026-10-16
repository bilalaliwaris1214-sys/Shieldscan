# ShieldScan

External attack surface checker for small businesses. Give it a domain and it reports:

- TLS certificate problems (expired, invalid, outdated protocol)
- Missing HTTP security headers (HSTS, CSP, X-Frame-Options, ...)
- Email spoofing protection gaps (SPF, DMARC)
- Risky exposed ports (RDP, SMB, databases, Telnet, FTP)

Each finding comes with a severity and a plain-language fix, plus an overall 0-100 security score.

> **Legal use only.** Scan domains you own or have written permission to test. The tool refuses to run without the `--authorized` flag.

## Install

```bash
git clone https://github.com/bilalaliwaris1214-sys/shieldscan
cd shieldscan
pip install -r requirements.txt
```

## Usage

```bash
python3 shieldscan.py example.com --authorized
python3 shieldscan.py example.com --authorized --json > report.json
```

## Project layout

```
shieldscan.py        CLI + scoring
checks/ports.py      risky open ports
checks/ssl_check.py  certificate + protocol
checks/headers.py    HTTP security headers
checks/email_dns.py  SPF / DMARC
```

## Roadmap

- [ ] Subdomain discovery
- [ ] Exposed admin panels / sensitive files check
- [ ] HTML/PDF report export
- [ ] DNS TXT ownership verification
- [ ] FastAPI web dashboard
- [ ] Scheduled scans + alerts
- [ ] Cloud misconfiguration checks (public storage buckets)

## Disclaimer

For educational and defensive security purposes only.
