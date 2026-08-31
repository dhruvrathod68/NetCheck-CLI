# NetCheck-CLI (netcheck-osint)

[![PyPI Version](https://img.shields.io/pypi/v/netcheck-osint.svg)](https://pypi.org/project/netcheck-osint/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Concurrency: AsyncIO](https://img.shields.io/badge/concurrency-asyncio%20%7C%20aiohttp-brightgreen.svg)](https://docs.python.org/3/library/asyncio.html)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/dhruvrathod68/NetCheck-CLI)

**NetCheck-CLI** is a high-performance, asynchronous digital identity validation and network endpoint auditing utility engineered in Python. It enables security researchers, penetration testers, and OSINT analysts to correlate digital handles across technical and developer platforms concurrently within seconds.

---

## 🎯 Primary Use Cases

* **Threat Intelligence & OSINT Reconnaissance:** Rapidly enumerate public developer handles, repository owners, and technical contributors across package registries and version control platforms.
* **Red Team External Footprinting:** Discover exposed external accounts, secondary developer aliases, or unclaimed namespaces during the reconnaissance phase of an engagement.
* **Defensive Asset Auditing:** Verify whether decommissioned or sensitive corporate usernames remain exposed or unclaimed across third-party developer ecosystems.
* **Deterministic Baseline Auditing:** Provides reliable HTTP status-code verification without the false positives caused by JavaScript-rendered login walls and single-page apps.

---

## 🏛️ Architectural Overview

Traditional footprinting tools query platforms sequentially, wasting CPU cycles while waiting on remote socket I/O. **NetCheck-CLI** eliminates this bottleneck through a cooperative, non-blocking single-threaded event loop.

```text
[CLI Entrypoint: netcheck <target>]
               │
               ▼
 [Endpoint Configuration Parser]  <── (Embedded Defaults or Custom JSON)
               │
               ▼
  [Async Event Loop Initiated]
               │
 ┌─────────────┼─────────────┐
 ▼             ▼             ▼
[Worker Task] [Worker Task] [Worker Task]  <── Managed concurrently via aiohttp session
 │             │             │
 └─────────────┼─────────────┘
               ▼
   [Telemetry Aggregator]
         │           │
         ▼           ▼
 [Colorama ANSI UI] [RFC JSON Report]
```

### Key Technical Advantages

* **Persistent Connection Pooling:** Reuses an underlying `aiohttp.ClientSession` pool, eliminating repeated TCP three-way handshakes and TLS negotiation overhead.
* **Separation of Concerns (SoC):** Decouples platform signature definitions from the core execution engine, allowing new targets to be added via JSON configurations without touching source code.
* **Resilient Worker Isolation:** Catches timeouts and DNS/connection errors locally per task, preventing single network drops from aborting the global audit queue.

---

## 🚀 Installation & Setup

### Option A: Global System Installation via PyPI (Recommended)

Install `netcheck-osint` directly from PyPI into an isolated global environment:

```bash
# Using pipx (Recommended for isolated CLI binaries)
pipx install netcheck-osint

# Or using standard pip
pip install netcheck-osint
```

### Option B: Local Virtual Environment from Source

```bash
# 1. Clone the repository
git clone https://github.com/dhruvrathod68/NetCheck-CLI.git
cd NetCheck-CLI

# 2. Create and activate a virtual environment
# On Linux / macOS / Kali:
python3 -m venv venv
source venv/bin/activate

# On Windows PowerShell:
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install in editable mode
pip install -e .
```

---

## 🔄 Updating NetCheck-CLI

To update your globally installed version to the latest release:

```bash
# If installed via pipx
pipx upgrade netcheck-osint

# If installed via pip
pip install --upgrade netcheck-osint

# If cloned from Git source
git pull origin main
pip install -e .
```

---

## 💻 Usage & Command Reference

```text
usage: netcheck [-h] [-u USERNAME_FLAG] [-t TARGET_FLAG] [-c CONFIG_PATH] [-o OUTPUT] [username]

NetCheck-OSINT: Asynchronous Digital Identity & Endpoint Auditor

positional arguments:
  username              Target username or identifier to audit across online services.

options:
  -h, --help            Show this help message and exit.
  -u, --username        Target username or identifier (flag format).
  -t, --target          Alias for target username/identifier.
  -c, --config          Custom file path to endpoints.json configuration.
  -o, --output          File path to export structured JSON telemetry report.
```

### Example Commands

```bash
# 1. Basic Handle Audit (Positional Syntax)
netcheck johndoe

# 2. Audit with Telemetry JSON Export
netcheck -u torvalds -o audit_report.json

# 3. Run Audit with a Custom Endpoint Registry
netcheck -t octocat -c custom_endpoints.json
```

---

## 🛠️ Customizing & Extending Target Endpoints

You can customize the platform registry without modifying any Python code. By default, `NetCheck-CLI` ships with built-in signatures for major technical platforms (GitHub, GitLab, DockerHub, PyPI, NPM, Hashnode, Dev.to, Reddit, Vimeo, Pinterest, BuyMeACoffee, Bitbucket).

### Adding Custom Endpoints

Create a JSON file (e.g., `custom_targets.json`) following this schema:

```json
{
  "endpoints": [
    {
      "name": "Custom_Platform",
      "url": "https://api.example.com/users/{}",
      "validation_type": "status_code",
      "expected_value": 200
    },
    {
      "name": "Internal_Service",
      "url": "https://git.internal.corp/{}",
      "validation_type": "status_code",
      "expected_value": 200
    }
  ]
}
```

* **`name`**: Display name for terminal logs and telemetry reports.
* **`url`**: Target URL with `{}` marking where the username will be injected dynamically.
* **`expected_value`**: Expected HTTP status code (typically `200`) indicating account presence.

Execute your scan using your custom file:

```bash
netcheck johndoe -c custom_targets.json
```

---

## 📊 Telemetry Output Schema

When `-o` or `--output` is supplied, `NetCheck-CLI` generates a structured JSON report for SIEM and automation pipelines:

```json
{
  "target": "torvalds",
  "timestamp_utc": "2026-08-31T12:00:00Z",
  "duration_seconds": 1.245,
  "summary": {
    "total_audited": 12,
    "found": 7,
    "not_found": 4,
    "blocked_or_error": 1
  },
  "results": [
    {
      "service_name": "GitHub",
      "target_url": "https://github.com/torvalds",
      "status_code": 200,
      "state": "FOUND",
      "match_status": true,
      "latency_ms": 124.5
    }
  ]
}
```

### Telemetry Field Definitions

| Field | Type | Description |
| --- | --- | --- |
| `target` | `string` | Target username or handle queried. |
| `timestamp_utc` | `string (ISO-8601)` | Execution start timestamp in UTC. |
| `duration_seconds` | `float` | Cumulative clock time consumed by the audit loop. |
| `summary` | `object` | Aggregate counts (`total_audited`, `found`, `not_found`, `blocked_or_error`). |
| `results[].service_name` | `string` | Display name of the platform service. |
| `results[].target_url` | `string` | Full interpolated URL queried by the transport pool. |
| `results[].status_code` | `integer / null` | HTTP status code returned by the remote host. |
| `results[].state` | `string` | Classification (`FOUND`, `NOT_FOUND`, `BLOCKED`, `TIMEOUT`, `ERROR`). |
| `results[].match_status` | `boolean` | True if the returned status matches `expected_value`. |
| `results[].latency_ms` | `float` | Round-trip request latency in milliseconds. |

---

## 📂 Project Directory Structure

```text
NetCheck-CLI/
├── config/
│   └── endpoints.json       # Decoupled Target Data Layer
├── venv/                    # Python virtual environment (git-ignored)
├── .gitignore               # Repository file exclusion rules
├── LICENSE                  # MIT License (2026 Dhruv Rathod)
├── main.py                  # Core Asynchronous Engine & CLI Entrypoint
├── requirements.txt         # Pinned Package Metadata Dependencies
├── setup.py                 # Setuptools packaging manifest & console scripts
└── README.md                # Enterprise Open-Source Documentation
```

---

## 🗺️ Roadmap & Upcoming Features

* **Response Body Regex Matching:** Support content-absence assertions to audit Single-Page Applications (SPAs) and dynamic login redirects.
* **User-Agent Header Pools:** Randomized browser fingerprint rotation to minimize edge WAF blocks (`HTTP 403`).
* **Proxy & Tor Routing:** Built-in SOCKS5 / HTTP proxy chaining for operational security during red team assessments.
* **Multi-Format Reporting:** Native export to CSV, Markdown summary tables, and SARIF formats.

---

## 🤝 Contributing & Issue Reporting

Contributions, bug reports, and target registry additions are welcome!

### Reporting Issues

If you encounter false positives, broken endpoint patterns, or socket exceptions, please open an issue on the [GitHub Issue Tracker](https://github.com/dhruvrathod68/NetCheck-CLI/issues).

### Submitting Pull Requests

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AddPlatformSignatures`).
3. Commit your changes with clear messages (`git commit -m 'feat: add 5 new cloud platform signatures'`).
4. Push to your branch (`git push origin feature/AddPlatformSignatures`).
5. Open a Pull Request detailing your changes.

---

## ⚖️ License & Attribution

Distributed under the MIT License. See `LICENSE` for full details.

**Author:** Dhruv Rathod

**Year:** 2026
