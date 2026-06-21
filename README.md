# NetCheck-CLI

A high-performance, asynchronous digital identity validation and network endpoint auditing tool engineered in Python. 

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/architecture-AsyncIO--EventLoop-orange.svg)](https://docs.python.org/3/library/asyncio.html)

## 📋 Description

**NetCheck-CLI** is a modular command-line utility designed for Security Engineers, Penetration Testers, and Site Reliability Engineers (SREs). It optimizes the discovery and auditing of digital footprints across enterprise systems, developer registries, and cloud infrastructure. 

Traditional footprinting and status-checking tools execute requests sequentially, spending significant CPU idle time waiting for network I/O operations to resolve. **NetCheck-CLI** solves this bottleneck by utilizing Python's `asyncio` framework and `aiohttp` client engine to achieve non-blocking concurrency over a single-threaded architecture. This cuts execution windows down from minutes to seconds under scale.

---

## 🛠️ Core Features

* **Asynchronous Concurrency:** Leverages a single-threaded Event Loop to manage hundreds of parallel network requests efficiently, eliminating thread context-switching overhead.
* **Persistent Connection Pooling:** Instantiates a unified `aiohttp.ClientSession` connection pool, preserving TCP sockets and mitigating the overhead of repeated TCP 3-way handshakes and TLS negotiations.
* **Strict Separation of Concerns (SoC):** Decouples target signature definitions entirely from execution logic using an external JSON configuration layer for seamless, zero-code target expanding.
* **Resilient Fault Isolation:** Encapsulates network exception handlers directly within individual execution workers, preventing localized connection drops or timeouts from halting the global queue.
* **Structured Telemetry Logs:** Generates highly deterministic, machine-readable JSON reports mapping aggregate performance statistics alongside detailed response criteria for downstream SIEM integration.
* **Cross-Platform UX:** Styled with cross-platform terminal auto-reset escape codes using `colorama` for unified formatting on both Windows PowerShell and Linux terminals.

---

## 📐 Architectural Design

```
[CLI Flags: --target / --output]
               │
               ▼
 [Parse JSON Target Registry]
               │
               ▼
  [Async Event Loop Initiated]
               │
 ┌─────────────┼─────────────┐
 ▼             ▼             ▼
[Worker Task] [Worker Task] [Worker Task]  <-- Managed concurrently by Event Loop
│             │             │
└─────────────┼─────────────┘
▼
[Data Aggregator Module]
│
┌─────────┴─────────┐
▼                   ▼
[Terminal UI Log]   [Structured JSON Export]
```

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.8 or higher
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/NetCheck-CLI.git
cd NetCheck-CLI
```

### 2. Environment Isolation Setup

#### On Windows (PowerShell):
```powershell
# Initialize virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install pinned production dependencies
pip install -r requirements.txt
```

#### On Linux / Kali Linux (Bash):
```bash
# Initialize virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install pinned production dependencies
pip install -r requirements.txt
```

---

## 💻 Usage & Examples

The tool evaluates targets by reading signatures from `config/endpoints.json` and injecting runtime target values into string placeholder paths dynamically.

### Basic Application Execution
Run a validation check against the default endpoint registry and export logs to the default `results.json` matrix:

```bash
python main.py --target "developer_handle"
```

### Custom Document Report Redirection
Target a specific system identifier and route the production JSON telemetry matrix directly to a custom file path:

```bash
python main.py --target "audit-target-handle" --output telemetry_report.json
```

### Extending Target Databases
To add target networks without altering the source code, append entries directly to the database file at `config/endpoints.json`:

```json
{
  "name": "Custom_Platform_Service",
  "url": "https://api.example.com/users/{}",
  "validation_type": "status_code",
  "expected_value": 200
}
```

---

## 📂 Project Directory Structure

```plaintext
NetCheck-CLI/
│
├── config/
│   └── endpoints.json       # Decoupled Target Data Layer
├── main.py                  # Core Asynchronous Execution Loop
├── requirements.txt         # Pinned Package Metadata Dependency List
└── README.md                # Enterprise Documentation Module
```

---

## 🤝 Contributing

Contributions are highly valued for optimizing throughput and expansion. For sweeping architecture updates, please open an execution issue first to discuss structural modifications.

1. Fork the Repository
2. Instantiate a Feature Branch (`git checkout -b feature/Optimization`)
3. Commit Changes (`git commit -m 'Optimized event loop chunk management'`)
4. Push to the Branch (`git push origin feature/Optimization`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for further operational legal documentation.
