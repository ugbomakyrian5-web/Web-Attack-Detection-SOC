# 🔍 SOC Investigation: Detecting Web Attacks – Log Triage, PCAP Analysis & WAF Hardening

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-Web%20Attack%20Detection-007ACC?style=flat)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()
[![Tools](https://img.shields.io/badge/Tools-Wireshark%20%7C%20CyberChef%20%7C%20Access%20Logs-blue?style=flat)]()

Post-breach SOC investigation into a web application compromise at **TryBankMe**, an online banking platform. Attackers exfiltrated sensitive customer data and posted it to a darknet forum. Tasked with determining the initial access vector and reconstructing the full attack chain using server access logs and network traffic captures.

**Attack chain confirmed:**
> Directory Fuzzing → Credential Brute-Force → Authenticated Access → SQL Injection → Data Exfiltration

---

## 📌 Investigation Summary

| Field | Detail |
|-------|--------|
| **Incident** | Web application breach — customer data exfiltrated |
| **Target** | TryBankMe public-facing web application |
| **Attacker IP** | 192.168.1.10 |
| **Evidence Sources** | Web server access logs + network traffic PCAP |
| **Tools Used** | Wireshark, CyberChef, Access Log Analysis |
| **Outcome** | Full attack chain reconstructed — IOCs extracted, WAF rules produced |

---

## 🎯 Key Findings

| # | Finding | Evidence Source |
|---|---------|----------------|
| 1 | Directory fuzz using **FFUF v2.1.0** identified valid endpoints including `/login.php` | Access logs |
| 2 | Hydra brute-force against `/login.php` — **302 redirect confirms successful login** | Access logs |
| 3 | SQLi payload `%' OR '1'='1` submitted to `/changeusername.php` via sqlmap | Access logs + CyberChef |
| 4 | Credentials exposed: **admin / astrongpassword123** | Wireshark PCAP |
| 5 | Database dumped — users table exposed, flag `THM{dumped_the_db}` recovered in HTTP stream | Wireshark PCAP |

---

## 🔎 Investigation Walkthrough

### Phase 1 — Reconnaissance: Directory Fuzzing

**Attacker Tool**: FFUF v2.1.0
**Timestamp**: 20/Aug/2025 07:37:38 UTC
**Source IP**: 192.168.1.10

Access logs showed a burst of GET requests across multiple paths within a single second — a pattern consistent with automated directory enumeration. The `FFUF v2.1.0` User-Agent string confirmed the tooling. HTTP `200` responses revealed valid endpoints; `404` responses indicated dead ends.

**Valid endpoints discovered by attacker:**
`/login.php` `/home` `/catalog` `/products`

The attacker now had a clear map of the application's attack surface. `/login.php` became the next target.

#### 📸 Screenshot 1 — FFUF v2.1.0 User-Agent Confirmed in Access Logs
<img width="1366" height="728" alt="FFUF Directory Fuzz Detection" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/1_directory_fuzz_ffuf_useragent.png" />

*Burst of GET requests from 192.168.1.10 with FFUF v2.1.0 User-Agent — 200 responses mark valid endpoints*

---

### Phase 2 — Initial Access: Credential Brute-Force

**Target**: `/login.php`
**Tool**: Hydra (`Mozilla/5.0 (Hydra)` User-Agent)
**Indicator**: Single `302 Found` response among repeated `403` failures

The access logs recorded a high-volume flood of POST requests to `/login.php` from the same IP, all returning `403` — failed login attempts. One request returned `302 Found`, redirecting to `/account`. In HTTP authentication flows, a `302` redirect following repeated `403` failures is the definitive indicator of a successful brute-force.

The attacker was now inside the application.

#### 📸 Screenshot 2 — 302 Redirect Confirms Successful Brute-Force
<img width="1366" height="728" alt="Brute Force 302 Redirect" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/2_brute_force_login_302_redirect.png" />

*High-volume POST requests to /login.php — single 302 response among hundreds of 403 failures confirms credential compromise*

---

### Phase 3 — Exploitation: SQL Injection

**Target**: `/changeusername.php`
**Tool**: sqlmap/stable
**Raw Payload**: `%25%27+OR+%271%27%3D%271`
**Decoded Payload**: `%' OR '1'='1`

Post-authentication, the attacker targeted the `/changeusername.php` form using sqlmap. The GET request query string contained a URL-encoded SQLi payload. CyberChef's URL Decode recipe was applied to safely extract the plaintext injection string.

`%' OR '1'='1` is a classic boolean-based SQLi payload — by injecting a condition that always evaluates as true, the attacker forced the backend SQL query to return all records, effectively dumping the users table and exposing every account in the database.

#### 📸 Screenshot 3a — sqlmap User-Agent and Encoded SQLi Payload in Access Log
<img width="1366" height="728" alt="SQLi Payload in Access Log" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/3_sqli_encoded_payload_access_log.png" />

*GET /changeusername.php — URL-encoded SQLi payload and sqlmap/stable User-Agent confirm automated injection attempt*

#### 📸 Screenshot 3b — CyberChef URL Decode Reveals Plaintext SQLi Payload
<img width="1366" height="728" alt="CyberChef URL Decode" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/3b_cyberchef_url_decode_sqli_payload.png" />

*CyberChef URL Decode — %25%27+OR+%271%27%3D%271 decodes to %' OR '1'='1*

---

### Phase 4 — PCAP Corroboration: Credentials & Exfiltration Confirmed

**Evidence**: `traffic.pcap`
**Filter**: `http`
**Critical Packet**: 316 (brute-force) | 442 (SQLi response)

Access logs confirmed the attack sequence but could not expose POST body content — credentials and exfiltrated data are invisible in log-only analysis. Wireshark closed this gap.

Packet 316 — the successful POST to `/login.php` — exposed the exact credentials submitted:

- **Username**: `admin`
- **Password**: `astrongpassword123`

Following the authenticated SQLi attack, the HTTP stream for packet 442 revealed the full server response to the injection. The backend executed the malicious query directly:

```sql
SELECT id, username, email FROM users WHERE username LIKE '%' OR '1'='1%'
```

The response returned the complete users table in plaintext:

| ID | Username | Email |
|----|----------|-------|
| 1 | alice | alice@example.com |
| 2 | bob | bob@example.com |
| 3 | admin | admin@example.com |
| 4 | flag | THM{dumped_the_db} |

The flag `THM{dumped_the_db}` embedded in the database confirms successful exfiltration of the entire users table — the breach is fully corroborated.

#### 📸 Screenshot 4 — Wireshark Exposes Credentials in POST Body
<img width="1366" height="728" alt="Wireshark POST Body Credentials" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/4_wireshark_brute_force_credentials.png" />

*Packet 316 — HTTP POST body reveals username=admin, password=astrongpassword123 — credentials invisible in access logs alone*

#### 📸 Screenshot 5 — HTTP Stream Confirms Database Dump and Flag Recovery
<img width="1366" height="728" alt="SQLi Database Dump and Flag" src="https://github.com/ugbomakyrian5-web/detecting-web-attacks/blob/main/screenshots/5_wireshark_sqli_database_dump_flag.png" />

*Wireshark Follow HTTP Stream (tcp.stream eq 44) — SQLi response exposes full users table and confirms THM{dumped_the_db} flag — direct evidence of data exfiltration*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|----|----------|
| Reconnaissance | Active Scanning | T1595 | FFUF v2.1.0 directory enumeration |
| Credential Access | Brute Force | T1110 | Hydra credential stuffing against /login.php |
| Initial Access | Valid Accounts | T1078 | Authenticated session established post-brute-force |
| Defense Evasion | Masquerading | T1036 | Hydra spoofing Mozilla/5.0 User-Agent |
| Credential Access | Exploitation for Credential Access | T1212 | Boolean SQLi on /changeusername.php |
| Exfiltration | Exfiltration Over Web Service | T1041 | Full users table dumped via SQLi — confirmed in HTTP stream |

---

## 🛡 Containment & Hardening Recommendations

### Immediate WAF Rules
Block confirmed attacker tooling at the perimeter:
IF User-Agent CONTAINS "FFUF" THEN BLOCK
IF User-Agent CONTAINS "sqlmap" THEN BLOCK
IF User-Agent CONTAINS "Hydra" THEN BLOCK
IF Query-String CONTAINS "%27" OR "' OR" OR "%3D%27" THEN BLOCK

---

### Rate Limiting & Lockout
- Enforce maximum **5 login attempts per IP per minute** — trigger lockout and alert on breach
- Flag and investigate any `302` response on `/login.php` following 10+ `403` responses from the same IP

### Application Fixes
- Replace all dynamic SQL queries with **parameterised statements / prepared queries** — eliminates SQLi at source
- Sanitise and validate all user-supplied input server-side before processing
- Deploy **CAPTCHA** on authentication forms to defeat automated brute-force tooling

### SIEM Detection Rules
- Alert on `FFUF`, `sqlmap`, `Hydra`, `wpscan`, `nikto` in any User-Agent field
- Alert on 50+ requests to the same endpoint from a single IP within 60 seconds
- Flag URL-encoded SQLi patterns in GET query strings: `%27`, `%3D%271`, `+OR+`
- Correlate `302` login responses with preceding high-volume `403` sequences — automatic escalation trigger

---

## 📌 Investigator Notes

> Access logs and network captures answer different questions — neither is sufficient alone.
> Logs reveal *what happened and when*. PCAPs reveal *what was actually sent*.
> In this investigation, the credentials and the full database dump were only recoverable from the PCAP.
> Effective web attack detection requires both sources working together.

---

## 📌 Skills Demonstrated

- Web server access log triage and malicious pattern recognition
- Network traffic analysis with Wireshark — HTTP filter, Follow HTTP Stream, packet body extraction
- IOC extraction and URL-encoded payload decoding with CyberChef
- Full attack chain reconstruction across multiple evidence sources
- WAF rule creation and SIEM detection rule development
- MITRE ATT&CK mapping for web-based attack scenarios
- Structured, SOC-grade incident documentation

---

**Completed**: April 2026

Full portfolio of SOC investigations available at [github.com/ugbomakyrian5-web](https://github.com/ugbomakyrian5-web)

Feel free to fork, star, or reach out. Open to feedback and collaboration!

MIT License – see the [LICENSE](LICENSE) file for details.
