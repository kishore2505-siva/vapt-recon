#!/usr/bin/env python3
"""
report_generator.py — turns raw recon.sh output into a structured VAPT report.

Report layout mirrors a standard VAPT deliverable:
  1. Executive Summary
  2. Scope of Testing
  3. Methodology
  4. Detailed Vulnerability Analysis (auto-flagged findings, severity-ranked)
  5. Remediation Plan
  6. Conclusion & Recommendations
  7. Appendices (raw tool output references)

Findings are pattern-matched from tool output (Nikto flags, missing headers,
Nmap open ports, outdated JS/CSS libs from WhatWeb, sqlmap results if present).
This is a starting draft, not a substitute for manual verification — a human
tester should confirm every finding before it goes in a report a client sees.

USAGE:
    python3 report_generator.py --input results/example.com_20260721_120000 \
        --target example.com --tester "Your Name" --output report.md
"""
import argparse
import json
import os
import re
from datetime import date

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def read_file(path):
    if os.path.exists(path):
        with open(path, "r", errors="ignore") as f:
            return f.read()
    return ""


def parse_nmap(outdir):
    findings = []
    raw = read_file(os.path.join(outdir, "nmap_raw.txt"))
    open_ports = re.findall(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", raw, re.MULTILINE)
    risky_services = {"ftp", "telnet", "mysql", "ms-sql-s", "mongodb", "redis", "rdp", "vnc"}
    for port, proto, service in open_ports:
        sev = "Medium" if service.lower() in risky_services else "Low"
        findings.append({
            "title": f"Open Port: {port}/{proto} ({service})",
            "severity": sev,
            "category": "Network / Security Misconfiguration",
            "owasp": "A05:2021 - Security Misconfiguration",
            "detail": f"Port {port}/{proto} is open and running '{service}'. "
                      f"If this service is not required to be publicly reachable, "
                      f"it unnecessarily widens the attack surface.",
            "evidence": f"nmap: {port}/{proto} open {service}",
            "remediation": "Close the port at the firewall or host level if the "
                           "service does not need to be internet-facing. If it must "
                           "remain open, restrict access via IP allow-listing and "
                           "ensure the service is patched and uses strong authentication.",
        })
    return findings


def parse_nikto(outdir):
    findings = []
    raw = read_file(os.path.join(outdir, "nikto_output.txt"))
    if not raw:
        return findings

    header_checks = {
        "X-Content-Type-Options": "MIME-type sniffing attacks (browsers may misinterpret file types).",
        "Strict-Transport-Security": "downgrade / protocol-stripping attacks against HTTPS.",
        "Content-Security-Policy": "cross-site scripting (XSS) and data-injection attacks.",
        "X-Frame-Options": "clickjacking attacks via iframe embedding.",
    }
    for header, risk in header_checks.items():
        if re.search(rf"{re.escape(header)}.*not (present|defined)", raw, re.IGNORECASE):
            findings.append({
                "title": f"Missing Security Header: {header}",
                "severity": "Medium",
                "category": "Security Misconfiguration",
                "owasp": "A05:2021 - Security Misconfiguration",
                "detail": f"The '{header}' header is not set, which increases exposure to {risk}",
                "evidence": f"nikto: {header} header not present",
                "remediation": f"Configure the web server / application to send the "
                               f"'{header}' header on all responses.",
            })

    if re.search(r"httponly", raw, re.IGNORECASE) and re.search(
        r"cookie.*without.*httponly|created without the httponly", raw, re.IGNORECASE
    ):
        findings.append({
            "title": "Insecure Cookie Configuration (Missing HttpOnly/Secure)",
            "severity": "Medium",
            "category": "Session Management",
            "owasp": "A05:2021 - Security Misconfiguration",
            "detail": "One or more cookies are set without the HttpOnly and/or Secure "
                      "flags, making them readable by client-side scripts and "
                      "transmittable over unencrypted channels.",
            "evidence": "nikto: cookie created without the httponly flag",
            "remediation": "Set Secure, HttpOnly, and SameSite attributes on all "
                           "session cookies.",
        })

    admin_matches = re.findall(r"(/[\w\-/]*admin[\w\-/]*)", raw, re.IGNORECASE)
    if admin_matches:
        findings.append({
            "title": "Potentially Exposed Admin Path",
            "severity": "High",
            "category": "Access Control",
            "owasp": "A01:2021 - Broken Access Control",
            "detail": "Nikto identified one or more admin-related paths that "
                      "responded without requiring prior authentication context. "
                      "Manual verification is required to confirm whether this is "
                      "genuinely unauthenticated or just a login page.",
            "evidence": f"nikto: {admin_matches[0]}",
            "remediation": "Confirm the admin panel enforces authentication and "
                           "authorization on every request. Restrict access further "
                           "via IP allow-listing, VPN, or MFA.",
        })

    return findings


def parse_whatweb(outdir):
    findings = []
    raw = read_file(os.path.join(outdir, "whatweb.json"))
    if not raw:
        return findings
    try:
        # whatweb --log-json emits one JSON object per line
        entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except json.JSONDecodeError:
        entries = []

    outdated_hint_libs = ["bootstrap", "jquery", "wordpress", "joomla", "drupal"]
    for entry in entries:
        plugins = entry.get("plugins", {})
        for lib in outdated_hint_libs:
            for key in plugins:
                if lib in key.lower():
                    version_info = plugins[key]
                    version = None
                    if isinstance(version_info, dict):
                        v = version_info.get("version")
                        if isinstance(v, list):
                            version = v[0] if v else None
                        else:
                            version = v
                    findings.append({
                        "title": f"Third-Party Component Detected: {key}"
                                 + (f" ({version})" if version else ""),
                        "severity": "Info",
                        "category": "Vulnerable and Outdated Components",
                        "owasp": "A06:2021 - Vulnerable and Outdated Components",
                        "detail": f"WhatWeb fingerprinted '{key}'"
                                  + (f" version {version}" if version else "")
                                  + ". Cross-reference this against the CVE database "
                                    "(nvd.nist.gov) to confirm whether this version has "
                                    "known vulnerabilities before including it as a "
                                    "confirmed finding.",
                        "evidence": f"whatweb: {key} {version or ''}".strip(),
                        "remediation": "Update to the latest stable release and "
                                       "subscribe to security advisories for this "
                                       "component.",
                    })
    return findings


def parse_sqlmap(outdir):
    findings = []
    raw = read_file(os.path.join(outdir, "sqlmap_raw.txt"))
    if not raw:
        return findings
    if re.search(r"is vulnerable", raw, re.IGNORECASE):
        param_match = re.search(r"Parameter:\s*(\S+)", raw)
        param = param_match.group(1) if param_match else "unknown parameter"
        findings.append({
            "title": f"SQL Injection Confirmed ({param})",
            "severity": "Critical",
            "category": "Injection",
            "owasp": "A03:2021 - Injection",
            "detail": f"sqlmap confirmed the '{param}' parameter is injectable. "
                      f"This can allow an attacker to read, modify, or exfiltrate "
                      f"database contents, and in some configurations escalate to "
                      f"full system compromise.",
            "evidence": "sqlmap: injection point confirmed, see sqlmap_raw.txt for full technique details",
            "remediation": "Replace dynamic SQL with parameterized queries / "
                           "prepared statements everywhere user input reaches the "
                           "database. Apply least-privilege to the DB account used "
                           "by the app. Deploy a WAF as a compensating control.",
        })
    else:
        findings.append({
            "title": "SQL Injection Test — No Injection Confirmed",
            "severity": "Info",
            "category": "Injection",
            "owasp": "A03:2021 - Injection",
            "detail": "sqlmap did not confirm an injectable parameter at the tested "
                      "endpoint with the tuning used (--level=2 --risk=1). This does "
                      "not rule out SQLi elsewhere in the application or at higher "
                      "test intensity.",
            "evidence": "sqlmap: no injection point identified",
            "remediation": "N/A — consider testing additional parameters/endpoints "
                           "manually or with authenticated sessions.",
        })
    return findings


def risk_score(severity):
    mapping = {"Critical": (4, 4), "High": (3, 3), "Medium": (2, 2), "Low": (2, 1), "Info": (1, 1)}
    likelihood, impact = mapping.get(severity, (1, 1))
    return likelihood, impact, likelihood * impact


def build_report(target, tester, findings, outdir):
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)

    today = date.today().strftime("%B %d, %Y")
    lines = []
    lines.append(f"# VAPT REPORT\n")
    lines.append(f"## {target}\n")
    lines.append(f"**Tester:** {tester}  \n**Date:** {today}\n")
    lines.append("---\n")

    # 1. Executive Summary
    lines.append("## 1. Executive Summary\n")
    lines.append(f"This report presents the findings of an automated reconnaissance "
                 f"and vulnerability scan conducted against **{target}**. Findings "
                 f"below are auto-detected from tool output and require manual "
                 f"verification before being reported to a client or considered final.\n")
    lines.append(f"**Total findings:** {len(findings)}\n")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in by_sev:
            lines.append(f"- **{sev}:** {len(by_sev[sev])}")
    lines.append("")

    # Risk score table
    lines.append("### Risk Score (OWASP Risk Rating: Risk = Likelihood x Impact)\n")
    lines.append("| Finding | Likelihood | Impact | Risk Score | Level |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        l, i, s = risk_score(f["severity"])
        lines.append(f"| {f['title']} | {l} | {i} | {s} | {f['severity']} |")
    lines.append("")

    # 2. Scope
    lines.append("## 2. Scope of Testing\n")
    lines.append(f"- **Primary Target:** {target}")
    subdomains = read_file(os.path.join(outdir, "subdomains.txt")).strip()
    if subdomains:
        lines.append(f"- **Subdomains Discovered:**\n```\n{subdomains}\n```")
    else:
        lines.append("- **Subdomains Discovered:** None found / not scanned")
    lines.append("- **Methodology:** Black-box testing, no credentials provided\n")

    # 3. Methodology
    lines.append("## 3. Methodology\n")
    lines.append("| Phase | Tool | Purpose |")
    lines.append("|---|---|---|")
    lines.append("| Subdomain Enumeration | subfinder | Discover additional attack surface |")
    lines.append("| Port/Service Scan | Nmap | Identify open ports and running services |")
    lines.append("| Web Misconfiguration Scan | Nikto | Detect header/cookie issues, known files |")
    lines.append("| Technology Fingerprinting | WhatWeb | Identify frameworks/libraries and versions |")
    lines.append("| SQL Injection Testing | sqlmap | Test a specified parameter for injectability (opt-in) |")
    lines.append("")

    # 4. Findings
    lines.append("## 4. Detailed Vulnerability Analysis\n")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev not in by_sev:
            continue
        for idx, f in enumerate(by_sev[sev], 1):
            lines.append(f"### {sev}: {f['title']}\n")
            lines.append(f"**Category:** {f['category']}  ")
            lines.append(f"**OWASP Reference:** {f['owasp']}\n")
            lines.append(f"**Impact:**  \n{f['detail']}\n")
            lines.append(f"**Evidence:**\n```\n{f['evidence']}\n```\n")
            lines.append(f"**Remediation:**  \n{f['remediation']}\n")
    if not findings:
        lines.append("No findings were auto-detected from the scan output. This does "
                     "not mean the target is secure — it means these particular tools, "
                     "at this tuning, did not flag anything. Manual testing is still "
                     "recommended.\n")

    # 5. Remediation plan grouped by priority
    lines.append("## 5. Remediation Plan\n")
    priority_map = {"Critical": "Immediate", "High": "High Priority", "Medium": "Medium Priority",
                     "Low": "Low Priority", "Info": "Informational"}
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev not in by_sev:
            continue
        lines.append(f"**{priority_map[sev]}:**")
        for f in by_sev[sev]:
            lines.append(f"- {f['remediation']}")
        lines.append("")

    # 6. Conclusion
    lines.append("## 6. Conclusion & Recommendations\n")
    lines.append("- Verify every auto-detected finding manually before delivering this report to a client.")
    lines.append("- Re-run scans periodically (e.g. quarterly) as part of an ongoing security program.")
    lines.append("- Consider deeper authenticated testing, business-logic testing, and manual code review — automated tools only catch a subset of real-world vulnerabilities.")
    lines.append("")

    # 7. Appendix
    lines.append("## 7. Appendix — Raw Tool Output\n")
    lines.append(f"Raw scan artifacts are stored in: `{outdir}`")
    lines.append("- `nmap_raw.txt`, `nmap_scan.*`")
    lines.append("- `nikto_output.txt`")
    lines.append("- `whatweb.json`, `whatweb_raw.txt`")
    lines.append("- `sqlmap/` (if sqlmap was run)")
    lines.append("- `subdomains.txt`")
    lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Generate a VAPT report from recon.sh output")
    ap.add_argument("--input", required=True, help="Directory produced by recon.sh")
    ap.add_argument("--target", required=True, help="Target domain/IP tested")
    ap.add_argument("--tester", default="Unnamed Tester", help="Name to put on the report")
    ap.add_argument("--output", default="vapt_report.md", help="Output markdown file path")
    args = ap.parse_args()

    findings = []
    findings += parse_nmap(args.input)
    findings += parse_nikto(args.input)
    findings += parse_whatweb(args.input)
    findings += parse_sqlmap(args.input)

    report = build_report(args.target, args.tester, findings, args.input)
    with open(args.output, "w") as f:
        f.write(report)
    print(f"[*] Report written to: {args.output}")
    print(f"[*] {len(findings)} findings auto-detected — review each before sharing.")


if __name__ == "__main__":
    main()
