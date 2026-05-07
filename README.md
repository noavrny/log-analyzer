# log-analyzer

A Python CLI tool that parses Apache/Nginx access logs, detects common web attack patterns, and generates an HTML security report.

## Project structure

```
log-analyzer/
├── log-analyzer/
│   ├── main.py          # Entry point
│   ├── parser.py        # Log parser (Combined Log Format)
│   ├── detector.py      # Detection engine (4 detectors)
│   └── reporter.py      # HTML report generator
├── templates/
│   └── report.html      # Jinja2 report template
├── samples/             # Sample log files for testing
└── reports/             # Generated reports output
```

---

## Getting started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone <repo-url>
cd log-analyzer
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install jinja2
```

### Usage

Run the analyzer from inside the `log-analyzer/` subfolder, passing the path to a log file:

```bash
cd log-analyzer
python main.py ../samples/test.log
```

The report is written to `reports/report.html`. Open it in any browser:

```bash
open ../reports/report.html     # macOS
xdg-open ../reports/report.html # Linux
```

### Sample log files

Two files are included in `samples/` to exercise every detection scenario:

- `test.log` — brute force, directory scan, SQL injection, suspicious user-agents
- `test2.log` — additional edge cases

---

## Log format

The parser expects the **Apache/Nginx Combined Log Format**:

```
<ip> <rfc> <user> [<timestamp>] "<request>" <status> <size> "<referrer>" "<user-agent>"
```

Examples:

```
45.33.32.156 - - [01/May/2025:08:00:01 +0000] "POST /login HTTP/1.1" 401 194
192.168.1.1 - alice [01/May/2025:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

Lines that do not match this format are silently skipped.

---

## Detection capabilities

| Attack type | Detection method | Severity scale |
|---|---|---|
| **Brute force** | 5+ HTTP 401/403 from the same IP within a 15-second window | LOW / MEDIUM / HIGH |
| **Directory scan** | 5+ HTTP 404 with distinct paths from the same IP within 15 seconds | LOW / MEDIUM / HIGH |
| **SQL injection** | Regex matching on known SQLi patterns in the request URI | LOW / HIGH |
| **Suspicious user-agent** | Keyword match against known security scanner signatures | LOW / MEDIUM / HIGH |

**Severity thresholds** (volume-based detectors):

| Threshold | Severity |
|---|---|
| 20+ matching requests | HIGH |
| 10–19 matching requests | MEDIUM |
| 5–9 matching requests | LOW |

**SQL injection patterns** detected: `UNION SELECT`, boolean-based blind (`OR 1=1`), time-based blind (`SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`), stacked queries (`;DROP`, `;INSERT`, `;UPDATE`, `;DELETE`), comment sequences (`--`, `#`, `/*`), `xp_cmdshell`.

**Recognized scanning tools**: `sqlmap`, `nikto`, `masscan`, `nmap`, `burpsuite`, `zgrab`, `nuclei`, `dirbuster`.

---

## Report output

The generated HTML report provides:

- A summary strip with total, HIGH, MEDIUM, and LOW alert counts
- Priority alert cards highlighting the two most critical detections
- A full table of all alerts with type, severity, source IP, description, and number of associated log lines

---

## Professional context — cybersecurity utility

This tool addresses a real operational need in **SOC (Security Operations Center)** workflows: automated first-level triage of web server access logs.

In a professional setting, a tier-1 analyst spends significant time manually reviewing access logs to identify attack patterns before escalation. A log analyzer automates this first pass, enabling:

- **Faster incident response** — suspicious IPs and attack types are surfaced immediately, without manual `grep`/`awk` pipelines.
- **Attack correlation** — grouping alerts by source IP allows analysts to assess whether an actor is running a multi-stage attack (reconnaissance → brute force → exploitation).
- **Audit trail** — the HTML report is a self-contained artifact that can be attached to an incident ticket, delivered to a client, or archived for compliance purposes.
- **Threat hunting** — running the analyzer over historical log archives can surface intrusion attempts that went undetected at the time.

The project demonstrates practical understanding of core detection concepts: time-windowed heuristics, signature-based matching, and user-agent fingerprinting — all implemented without any external security framework dependency.

---

## Limitations and areas for further development

This tool is a functional proof of concept. Below is an honest assessment of what is not yet production-grade.

### What is not covered

**Log sources**
- Only parses Apache/Nginx Combined Log Format. Does not support syslog, Windows Event Log, JSON-structured logs (Elastic Common Schema), AWS CloudFront/ALB logs, or application-level logs.
- No support for live log streaming (`tail -f`). Analysis is batch-only.
- No multi-file ingestion or log rotation awareness.

**Detection**
- No detection of XSS, path traversal / LFI / RFI, SSRF, XXE, or command injection.
- No anomaly-based detection (behavioral baselines, statistical deviation). All rules are purely signature- or threshold-based.
- Distributed attacks spread across many IPs (botnets, credential stuffing rings) bypass IP-based grouping entirely.
- Low-and-slow attacks that stay below the 15-second time window are invisible to the brute force and directory scan detectors.
- No detection of successful credential stuffing: an attacker who succeeds after many 401s appears as a brute force alert but the follow-up 200 response is not correlated.
- The user-agent signature list is static and hardcoded — adding new tools requires editing source code.

**False positive control**
- No IP allowlist or denylist.
- No whitelisting of internal ranges, CDN egress IPs, or monitoring probes.
- No alert deduplication: the same source IP can generate multiple alerts of different types in the same run.

**Operational**
- Thresholds, time windows, and the output path are hardcoded in `detector.py` and `main.py`. There is no configuration file.
- No SIEM integration: no CEF/LEEF output, no Elastic or Splunk forwarder.
- No alerting on detection (email, Slack, webhook).
- All log entries are loaded into memory at once — not suitable for very large files (> 1 M lines).
- The tool has no execution log of its own (no audit trail for the analyzer itself).

### What should be built next

1. **Configuration file** (`config.yaml`): externalize thresholds, time windows, output path, allowlists, and UA signatures so the tool can be deployed without code changes.
2. **Broader attack coverage**: add XSS, path traversal, SSRF, and command injection detectors to cover the OWASP Top 10 more completely.
3. **Anomaly-based detection**: establish a traffic baseline per IP and endpoint, then flag statistical deviations to catch low-and-slow attacks that evade fixed thresholds.
4. **Multi-source ingestion**: support JSON logs (ECS), syslog, and piped stdin for integration with log shippers such as Filebeat or Fluentd.
5. **Alert deduplication and correlation**: merge overlapping alerts for the same actor and group different attack types from the same source IP into a single incident object.
6. **SIEM / webhook output**: emit alerts in CEF or JSON format for ingestion by Splunk, Elastic SIEM, or a Slack/PagerDuty webhook.
7. **IP enrichment**: query threat intelligence APIs (AbuseIPDB, VirusTotal, Shodan) to auto-enrich source IPs with reputation scores and geolocation.
8. **Streaming mode**: support real-time analysis via `tail -f` or a Unix domain socket for use in live production environments.
9. **Test suite**: unit tests for each detector with known-good and known-bad inputs to prevent regressions and validate threshold edge cases.
10. **Memory-efficient processing**: switch to line-by-line streaming for large log files instead of loading all entries into memory upfront.
