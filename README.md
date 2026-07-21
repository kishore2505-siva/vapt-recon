# vapt-recon

Automated recon + report generation for VAPT (Vulnerability Assessment & Penetration
Testing) work, built for Kali Linux. Wraps standard, industry-recognized tools
(Nmap, Nikto, WhatWeb, subfinder, optionally sqlmap) and compiles their output
into a structured Markdown report — Executive Summary, Scope, Methodology,
Findings by severity, Remediation Plan, and Conclusion.

## ⚠️ Authorization required

**Only run this against systems you own, or have explicit written permission
to test** (a signed scope document / rules of engagement, or your own lab/CTF
environment). Unauthorized scanning — even "just" port scanning or a header
check — can violate computer misuse laws, including the IT Act 2000 (India),
the CFAA (US), and the Computer Misuse Act (UK). `recon.sh` includes a
confirmation prompt for this reason; don't work around it.

sqlmap testing in particular is **opt-in only** (`-u` flag) because it
actively sends injection payloads to the target.

## What it does

| Phase | Tool | What it checks |
|---|---|---|
| Subdomain enumeration | subfinder | Additional attack surface |
| Port/service scan | Nmap (`-A`) | Open ports, running services, versions |
| Web misconfig scan | Nikto | Missing security headers, cookie flags, known paths |
| Tech fingerprinting | WhatWeb | Frameworks/libraries in use, versions |
| SQL injection (opt-in) | sqlmap | Whether a specific parameter is injectable |

`report_generator.py` then parses the raw tool output, auto-flags findings
with severity (Critical/High/Medium/Low/Info), computes an OWASP-style risk
score (Likelihood × Impact), and writes a Markdown report.

**Important:** auto-detected findings are a draft, not a verified report.
Nikto and pattern-matching produce false positives. Manually confirm every
finding — especially anything marked Critical or High — before it goes in
front of a client or gets submitted anywhere.

## Requirements (Kali Linux)

```bash
sudo apt update
sudo apt install -y nmap nikto whatweb sqlmap
# subfinder isn't in apt by default — install via Go or the ProjectDiscovery release:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Python 3.8+ (Kali ships this by default) — no extra pip packages needed,
`report_generator.py` only uses the standard library.

## Usage

```bash
git clone <your-repo-url>
cd vapt-recon
chmod +x scripts/recon.sh

# 1. Run recon (requires -a to confirm authorization, plus a typed confirmation)
./scripts/recon.sh -t example.com -a

# 2. (Optional) Include a SQLi test against a specific parameter you've been
#    authorized to test — this is active and will send injection payloads:
./scripts/recon.sh -t example.com -a -u "https://example.com/page.php?id=5"

# 3. Generate the report from the results
python3 scripts/report_generator.py \
    --input results/example.com_<timestamp> \
    --target example.com \
    --tester "Your Name" \
    --output vapt_report_example_com.md
```

Raw tool output stays in `results/<target>_<timestamp>/` so you can dig into
anything the report summarized, or attach it as an appendix.

## Project structure

```
vapt-recon/
├── README.md
├── scripts/
│   ├── recon.sh              # orchestrates the scans
│   └── report_generator.py   # parses output → Markdown report
├── templates/
│   └── report_template.md    # structure reference / manual-writing template
└── sample_output/            # example run + generated report for reference
```

## Extending it

Ideas if you want to build this out further for your portfolio:
- Add a `--html` output mode to `report_generator.py` (wrap the Markdown in a
  styled HTML template) for client-ready PDFs.
- Pull CVE data automatically for versions WhatWeb detects (NVD API) instead
  of just flagging "verify manually."
- Add DIRB/Gobuster for directory brute-forcing as another optional phase.
- Add a `--severity-min` flag to only report findings at or above a threshold.

## License

MIT — use freely, no warranty. See LICENSE.
