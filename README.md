# NetSentinel - Network Intrusion Detection System

A high-performance, real-time Network Intrusion Detection System (NIDS) built in Python. NetSentinel captures live network traffic, processes packets asynchronously using a multi-threaded queue, runs rule-based threat signatures, logs anomalies securely to SQLite (using WAL concurrency), and visualizes security intelligence on a beautiful, glassmorphic web control center.

Built as a final year B.Tech Cybersecurity capstone project.

---

## Features

- **Asynchronous Packet Sniffing:** Implements a producer-consumer thread queue model. Decouples the live Scapy sniffer from rule parsing and database writes to prevent packet drops under heavy network loads.
- **Rule-Based Attack Detection:**
  - **ICMP Flood:** Alerts when an IP sends more than 50 ICMP packets/sec.
  - **SYN Flood:** Alerts when an IP sends more than 100 SYN packets/sec (ECN/CWR compatible).
  - **Port Scan:** Tracks scans across more than 15 unique ports in a 10-second window.
  - **ARP Spoofing Mitigation:** Identifies MAC address reassignment conflicts for known IPs and implements cache-poisoning prevention.
  - **DNS Amplification:** Alerts on large DNS responses (> 512 bytes) pointing to reflection attacks.
- **SQLite WAL Storage:** Employs Write-Ahead Logging (WAL) for concurrency support and deduplicates duplicate alerts within a 5-second window.
- **Secured FastAPI REST API:** All statistics and alert endpoints require a token key verification header (`X-API-Key`).
- **Glassmorphic Web Control Center:**
  - Dark radial void aesthetic with backdrop-blur card panels.
  - Category distribution doughnut chart mapping threat vectors dynamically.
  - Glowing timeline frequency area chart mapping security alerts over time.
  - Real-time HUD stats updates and session key reset buttons.
- **Offline PCAP Analysis:** Support for parsing and running signatures on captured offline PCAP network files.
- **CLI Management:** Command-line options for running live capture, launching the API server, or outputting local databases.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Packet Capture** | Scapy 2.5 + Asynchronous Queueing |
| **Detection Engine** | Pure Python (State-decay Rules) |
| **Alert Storage** | SQLite 3 (WAL Mode Concurrency) |
| **API Backend** | FastAPI + Uvicorn + Token Authentication |
| **Frontend HUD** | HTML5 + CSS Glassmorphism + Chart.js |
| **CLI Management** | Python argparse |

---

## Project Structure

```text
netsentinel/
├── capture/         # Packet sniffing engine (Asynchronous Producer-Consumer queue)
├── detection/       # Attack detection rules & state analysis engines
├── logger/          # SQLite alert logger with cache deduplication and WAL mode
├── api/             # FastAPI backend with API Key header verification
├── dashboard/       # HTML control center dashboard
├── data/            # Local SQLite database
├── reports/         # Generated reports
├── config.py        # Settings, thresholds, and secret tokens
└── main.py          # Application entry point CLI
```

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- **Npcap (Windows):** Required for live packet capture. Download from [Npcap.com](https://npcap.com/#download).
- **Administrative Privileges:** Required to bind raw sockets for live capture on Windows/Linux.

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/zeeshanahmed30/netsentinel.git
   cd netsentinel
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # Linux/macOS
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide

### 1. Live Sniffing Mode (Run as Administrator/Sudo)
Start capture on a network interface (e.g. Wi-Fi):
```bash
python main.py --mode live --interface "Wi-Fi"
```

### 2. Launch Dashboard API
Start the backend web dashboard on localhost:
```bash
python main.py --mode api
```
Access the interface at [http://127.0.0.1:8002](http://127.0.0.1:8002).

*Note: You will be prompted to enter the API token configured in `config.py` (Default: `netsentinel_secure_token_123`).*

### 3. Display Local Text Reports
Print out saved alerts and attack vectors directly in your console:
```bash
python main.py --mode report
```

### 4. Analyze PCAP Files
Parse offline network capture files to scan for historic anomalies:
```bash
python main.py --pcap path/to/capture.pcap
```

---

## API Endpoints

| Endpoint | Method | Headers | Description |
|---|---|---|---|
| `GET /` | GET | None | Serves the web control center dashboard |
| `GET /api/alerts` | GET | `X-API-Key` | Returns the last 100 alerts (JSON) |
| `GET /api/stats` | GET | `X-API-Key` | Returns aggregated threat breakdown statistics |
| `GET /api/summary` | GET | `X-API-Key` | Returns overview metrics and the latest warning |

---

## Known Limitations

- **Throughput Limits:** Being python-based, Scapy packet capturing is capped at approximately ~50 Mbps. High-bandwidth networks will trigger dropped packets under extreme load.
- **Rule-Based Engine:** Employs static thresholds rather than dynamic anomaly models or deep-packet rule grammars (like Snort rules).
- **Loopback Capture:** Localhost traffic cannot be parsed by default on standard adapters (Npcap/loopback configuration required).

---

## Author

**Zeeshan Ahmed**
*B.Tech Cybersecurity - Techno India University, Kolkata*
- **GitHub:** [github.com/zeeshanahmed30](https://github.com/zeeshanahmed30)
- **LinkedIn:** [linkedin.com/in/zeeshanahmed30](https://linkedin.com/in/zeeshanahmed30)
