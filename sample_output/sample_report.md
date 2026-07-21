# VAPT REPORT

## example.com

**Tester:** Siva  
**Date:** July 21, 2026

---

## 1. Executive Summary

This report presents the findings of an automated reconnaissance and vulnerability scan conducted against **example.com**. Findings below are auto-detected from tool output and require manual verification before being reported to a client or considered final.

**Total findings:** 13

- **Critical:** 1
- **High:** 1
- **Medium:** 6
- **Low:** 3
- **Info:** 2

### Risk Score (OWASP Risk Rating: Risk = Likelihood x Impact)

| Finding | Likelihood | Impact | Risk Score | Level |
|---|---|---|---|---|
| SQL Injection Confirmed (id) | 4 | 4 | 16 | Critical |
| Potentially Exposed Admin Path | 3 | 3 | 9 | High |
| Open Port: 21/tcp (ftp) | 2 | 2 | 4 | Medium |
| Open Port: 3306/tcp (mysql) | 2 | 2 | 4 | Medium |
| Missing Security Header: X-Content-Type-Options | 2 | 2 | 4 | Medium |
| Missing Security Header: Strict-Transport-Security | 2 | 2 | 4 | Medium |
| Missing Security Header: Content-Security-Policy | 2 | 2 | 4 | Medium |
| Insecure Cookie Configuration (Missing HttpOnly/Secure) | 2 | 2 | 4 | Medium |
| Open Port: 80/tcp (http) | 2 | 1 | 2 | Low |
| Open Port: 443/tcp (https) | 2 | 1 | 2 | Low |
| Open Port: 8080/tcp (http-proxy) | 2 | 1 | 2 | Low |
| Third-Party Component Detected: Bootstrap (3.3.1) | 1 | 1 | 1 | Info |
| Third-Party Component Detected: jQuery (1.11.0) | 1 | 1 | 1 | Info |

## 2. Scope of Testing

- **Primary Target:** example.com
- **Subdomains Discovered:** None found / not scanned
- **Methodology:** Black-box testing, no credentials provided

## 3. Methodology

| Phase | Tool | Purpose |
|---|---|---|
| Subdomain Enumeration | subfinder | Discover additional attack surface |
| Port/Service Scan | Nmap | Identify open ports and running services |
| Web Misconfiguration Scan | Nikto | Detect header/cookie issues, known files |
| Technology Fingerprinting | WhatWeb | Identify frameworks/libraries and versions |
| SQL Injection Testing | sqlmap | Test a specified parameter for injectability (opt-in) |

## 4. Detailed Vulnerability Analysis

### Critical: SQL Injection Confirmed (id)

**Category:** Injection  
**OWASP Reference:** A03:2021 - Injection

**Impact:**  
sqlmap confirmed the 'id' parameter is injectable. This can allow an attacker to read, modify, or exfiltrate database contents, and in some configurations escalate to full system compromise.

**Evidence:**
```
sqlmap: injection point confirmed, see sqlmap_raw.txt for full technique details
```

**Remediation:**  
Replace dynamic SQL with parameterized queries / prepared statements everywhere user input reaches the database. Apply least-privilege to the DB account used by the app. Deploy a WAF as a compensating control.

### High: Potentially Exposed Admin Path

**Category:** Access Control  
**OWASP Reference:** A01:2021 - Broken Access Control

**Impact:**  
Nikto identified one or more admin-related paths that responded without requiring prior authentication context. Manual verification is required to confirm whether this is genuinely unauthenticated or just a login page.

**Evidence:**
```
nikto: /admin/
```

**Remediation:**  
Confirm the admin panel enforces authentication and authorization on every request. Restrict access further via IP allow-listing, VPN, or MFA.

### Medium: Open Port: 21/tcp (ftp)

**Category:** Network / Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
Port 21/tcp is open and running 'ftp'. If this service is not required to be publicly reachable, it unnecessarily widens the attack surface.

**Evidence:**
```
nmap: 21/tcp open ftp
```

**Remediation:**  
Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

### Medium: Open Port: 3306/tcp (mysql)

**Category:** Network / Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
Port 3306/tcp is open and running 'mysql'. If this service is not required to be publicly reachable, it unnecessarily widens the attack surface.

**Evidence:**
```
nmap: 3306/tcp open mysql
```

**Remediation:**  
Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

### Medium: Missing Security Header: X-Content-Type-Options

**Category:** Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
The 'X-Content-Type-Options' header is not set, which increases exposure to MIME-type sniffing attacks (browsers may misinterpret file types).

**Evidence:**
```
nikto: X-Content-Type-Options header not present
```

**Remediation:**  
Configure the web server / application to send the 'X-Content-Type-Options' header on all responses.

### Medium: Missing Security Header: Strict-Transport-Security

**Category:** Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
The 'Strict-Transport-Security' header is not set, which increases exposure to downgrade / protocol-stripping attacks against HTTPS.

**Evidence:**
```
nikto: Strict-Transport-Security header not present
```

**Remediation:**  
Configure the web server / application to send the 'Strict-Transport-Security' header on all responses.

### Medium: Missing Security Header: Content-Security-Policy

**Category:** Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
The 'Content-Security-Policy' header is not set, which increases exposure to cross-site scripting (XSS) and data-injection attacks.

**Evidence:**
```
nikto: Content-Security-Policy header not present
```

**Remediation:**  
Configure the web server / application to send the 'Content-Security-Policy' header on all responses.

### Medium: Insecure Cookie Configuration (Missing HttpOnly/Secure)

**Category:** Session Management  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
One or more cookies are set without the HttpOnly and/or Secure flags, making them readable by client-side scripts and transmittable over unencrypted channels.

**Evidence:**
```
nikto: cookie created without the httponly flag
```

**Remediation:**  
Set Secure, HttpOnly, and SameSite attributes on all session cookies.

### Low: Open Port: 80/tcp (http)

**Category:** Network / Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
Port 80/tcp is open and running 'http'. If this service is not required to be publicly reachable, it unnecessarily widens the attack surface.

**Evidence:**
```
nmap: 80/tcp open http
```

**Remediation:**  
Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

### Low: Open Port: 443/tcp (https)

**Category:** Network / Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
Port 443/tcp is open and running 'https'. If this service is not required to be publicly reachable, it unnecessarily widens the attack surface.

**Evidence:**
```
nmap: 443/tcp open https
```

**Remediation:**  
Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

### Low: Open Port: 8080/tcp (http-proxy)

**Category:** Network / Security Misconfiguration  
**OWASP Reference:** A05:2021 - Security Misconfiguration

**Impact:**  
Port 8080/tcp is open and running 'http-proxy'. If this service is not required to be publicly reachable, it unnecessarily widens the attack surface.

**Evidence:**
```
nmap: 8080/tcp open http-proxy
```

**Remediation:**  
Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

### Info: Third-Party Component Detected: Bootstrap (3.3.1)

**Category:** Vulnerable and Outdated Components  
**OWASP Reference:** A06:2021 - Vulnerable and Outdated Components

**Impact:**  
WhatWeb fingerprinted 'Bootstrap' version 3.3.1. Cross-reference this against the CVE database (nvd.nist.gov) to confirm whether this version has known vulnerabilities before including it as a confirmed finding.

**Evidence:**
```
whatweb: Bootstrap 3.3.1
```

**Remediation:**  
Update to the latest stable release and subscribe to security advisories for this component.

### Info: Third-Party Component Detected: jQuery (1.11.0)

**Category:** Vulnerable and Outdated Components  
**OWASP Reference:** A06:2021 - Vulnerable and Outdated Components

**Impact:**  
WhatWeb fingerprinted 'jQuery' version 1.11.0. Cross-reference this against the CVE database (nvd.nist.gov) to confirm whether this version has known vulnerabilities before including it as a confirmed finding.

**Evidence:**
```
whatweb: jQuery 1.11.0
```

**Remediation:**  
Update to the latest stable release and subscribe to security advisories for this component.

## 5. Remediation Plan

**Immediate:**
- Replace dynamic SQL with parameterized queries / prepared statements everywhere user input reaches the database. Apply least-privilege to the DB account used by the app. Deploy a WAF as a compensating control.

**High Priority:**
- Confirm the admin panel enforces authentication and authorization on every request. Restrict access further via IP allow-listing, VPN, or MFA.

**Medium Priority:**
- Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.
- Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.
- Configure the web server / application to send the 'X-Content-Type-Options' header on all responses.
- Configure the web server / application to send the 'Strict-Transport-Security' header on all responses.
- Configure the web server / application to send the 'Content-Security-Policy' header on all responses.
- Set Secure, HttpOnly, and SameSite attributes on all session cookies.

**Low Priority:**
- Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.
- Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.
- Close the port at the firewall or host level if the service does not need to be internet-facing. If it must remain open, restrict access via IP allow-listing and ensure the service is patched and uses strong authentication.

**Informational:**
- Update to the latest stable release and subscribe to security advisories for this component.
- Update to the latest stable release and subscribe to security advisories for this component.

## 6. Conclusion & Recommendations

- Verify every auto-detected finding manually before delivering this report to a client.
- Re-run scans periodically (e.g. quarterly) as part of an ongoing security program.
- Consider deeper authenticated testing, business-logic testing, and manual code review — automated tools only catch a subset of real-world vulnerabilities.

## 7. Appendix — Raw Tool Output

Raw scan artifacts are stored in: `sample_output/test_run`
- `nmap_raw.txt`, `nmap_scan.*`
- `nikto_output.txt`
- `whatweb.json`, `whatweb_raw.txt`
- `sqlmap/` (if sqlmap was run)
- `subdomains.txt`
