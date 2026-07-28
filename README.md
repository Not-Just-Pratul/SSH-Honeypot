<div align="center">

# 🛡️ SSH Honeypot + Live SOC Dashboard

**Defensive security tool that simulates an SSH server to capture attack metadata in real-time, with a live SOC-style dashboard, REST API, GeoIP enrichment, brute-force detection, and multi-channel alerts.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-111%20passed-success)](https://github.com/Not-Just-Pratul/SSH-Honeypot/actions)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)](https://hub.docker.com/r/not-just-pratul/ssh-honeypot)
[![Code style](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![Security](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Dashboard](#-dashboard)
- [REST API](#-rest-api)
- [Docker Deployment](#-docker-deployment)
- [Configuration](#-configuration)
- [Development](#-development)
- [Project Structure](#-project-structure)
- [Security Considerations](#-security-considerations)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Core Honeypot
- **SSH Server Simulation** — Accepts connections on a configurable port using Paramiko
- **Multi-Method Auth Capture** — Logs `password`, `publickey`, `keyboard-interactive`, and `none` auth attempts
- **Always Reject** — Never grants shell access or executes attacker commands
- **Session Tracking** — Unique IDs, connection duration, client version fingerprinting
- **Cached Host Key** — RSA key loaded once and reused across connections

### Threat Detection
- **Brute-Force Detection** — Configurable threshold and time window per IP
- **fail2Ban Integration** — Optional automated attacker blocking via fail2ban-client
- **GeoIP Enrichment** — MaxMind GeoLite2 (city + ASN) for attacker geolocation
- **Threat Intelligence** — Optional AbuseIPDB, VirusTotal, GreyNoise, and Shodan lookups
- **Combined Threat Scoring** — Aggregate multiple intelligence sources into a single risk score

### SOC Dashboard (Streamlit)
- **Overview** — Summary stats + attack timeline area chart
- **Charts** — Hourly bar, top usernames, daily scatter, country pie, auth vector breakdown, IP bar, ASN bar, heatmap, hourly trend
- **Interactive Map** — Folium-based world map with attacker geolocations and popups
- **Live Feed** — Real-time scrolling feed of the latest attacks
- **Filters & Search** — Multi-select filters by country, username, status, IP; free-text search
- **Statistics** — Top attackers, peak hours, unique counts, most targeted usernames
- **Export** — CSV, JSON, Excel (.xlsx), or PDF report generation
- **Dark/Light Theme** — Toggleable professional SOC styling

### REST API
- **Endpoints** — `/api/attacks`, `/api/attacks/latest`, `/api/stats`, `/api/health`
- **JWT Authentication** — Optional token-based auth for API endpoints
- **CORS Enabled** — All origins allowed for integration flexibility
- **Threaded Server** — Concurrent request handling

### Alert Channels
- **Telegram** — Formatted messages via bot API
- **Discord** — Rich embed notifications
- **Slack** — Block Kit structured messages
- **Email** — SMTP-based alerts
- **All async** — Non-blocking background delivery

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SSH Honeypot                      │
│                                                      │
│  ┌──────────┐    ┌──────────┐    ┌────────────────┐ │
│  │ Paramiko  │    │ Streamlit│    │   HTTP Server   │ │
│  │  Server   │    │Dashboard │    │   REST API     │ │
│  │ (Port 2222)│    │(Port 8501)│    │ (Port 8502)   │ │
│  └─────┬────┘    └────┬─────┘    └───────┬────────┘ │
│        │              │                  │          │
│  ┌─────▼──────────────▼──────────────────▼──────┐   │
│  │            SQLite Database                    │   │
│  │         + CSV Logging                         │   │
│  └─────────────────┬───────────────────────────┘   │
│                    │                                │
│  ┌─────────────────▼───────────────────────────┐   │
│  │         GeoIP + Threat Intel                 │   │
│  │   MaxMind | AbuseIPDB | VirusTotal | Shodan  │   │
│  └─────────────────┬───────────────────────────┘   │
│                    │                                │
│  ┌─────────────────▼───────────────────────────┐   │
│  │     Alerts: Telegram | Discord | Slack      │   │
│  │                   | Email                    │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### One-Line Docker (Recommended)

```bash
docker run -p 2222:2222 -p 8501:8501 ghcr.io/not-just-pratul/ssh-honeypot
```

### Manual Setup

```bash
# 1. Clone and install
git clone https://github.com/Not-Just-Pratul/SSH-Honeypot.git
cd SSH-Honeypot
pip install -e .

# 2. Generate SSH host key
mkdir keys
openssl genrsa -out keys/ssh_host_rsa_key 2048

# 3. Configure environment
cp .env.example .env
# Edit .env with your settings (GeoIP, alerts, etc.)

# 4. Run
ssh-honeypot all

# 5. Open the SOC Dashboard
# http://localhost:8501
```

### Via pip (when published)

```bash
pip install ssh-honeypot
ssh-honeypot all
```

### Quick Test

Once the honeypot is running, test it by sending SSH connections:

```bash
# Single test connection
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@localhost

# Try multiple common usernames
for user in root admin test ubuntu oracle postgres; do
    ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 -o BatchMode=yes ${user}@localhost 2>/dev/null
done
```

### Attack Simulator

A built-in attack simulator is available for testing and populating the dashboard:

```bash
# Send 20 attacks at 0.2s intervals (default)
python scripts/attack_simulator.py

# Send 100 attacks with 0.5s delay between each
python scripts/attack_simulator.py 100 --delay 0.5
```

### Verify Data

Check that attacks are being captured:

```bash
# Via REST API
curl http://localhost:8502/api/stats
curl http://localhost:8502/api/attacks/latest

# Direct database query
python -c "
from ssh_honeypot.database import get_total_count, get_username_stats
print(f'Total attacks: {get_total_count()}')
for row in get_username_stats()[:5]:
    print(f'  {row[\"username\"]}: {row[\"count\"]} hits')
"
```

---

## 📖 Usage

```bash
ssh-honeypot [mode] [options]
```

### Modes

| Mode | Description |
|------|-------------|
| `honeypot` | Start only the SSH honeypot (port 2222) |
| `dashboard` | Start only the Streamlit dashboard (port 8501) |
| `api` | Start only the REST API (port 8502) |
| `all` (default) | Start honeypot + dashboard + API |

### Options

| Option | Description |
|--------|-------------|
| `--host <ip>` | Override honeypot bind host |
| `--port <port>` | Override honeypot bind port |
| `--dashboard-port <port>` | Override dashboard port |
| `--log-level <LEVEL>` | Set verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## 📊 Dashboard

The SOC dashboard provides real-time monitoring of all captured attack data:

| Page | Description |
|------|-------------|
| **Overview** | Summary stats + attack timeline chart |
| **Charts** | Hourly bar, top usernames, daily scatter, country pie, auth vector pie, top IPs, ASN bar, heatmap, hourly trend |
| **Interactive Map** | Folium world map with attacker geolocations and details |
| **Live Feed** | Real-time scrolling feed of latest 50 attacks |
| **Filters & Search** | Multi-select filters + free-text search |
| **Statistics** | Unique counts, most targeted usernames, peak attack hour, top countries |
| **Export** | CSV, JSON, Excel (.xlsx), or PDF report |

> 🎨 Toggle between **dark** and **light** themes in the sidebar.

---

## 🔌 REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/attacks` | All attack logs (newest first) |
| `GET` | `/api/attacks/latest?limit=N` | Latest N attack logs |
| `GET` | `/api/stats` | Aggregate statistics |
| `GET` | `/api/health` | Health check |
| `POST` | `/api/auth/token` | Obtain JWT token (when enabled) |

### Authentication

Enable JWT auth in `.env`:
```ini
API_JWT_ENABLED=true
API_JWT_SECRET=your-secret-key
```

Get a token:
```bash
curl -X POST http://localhost:8502/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'
```

Use the token:
```bash
curl http://localhost:8502/api/attacks \
  -H "Authorization: Bearer <token>"
```

---

## 🐳 Docker Deployment

### Build and Run

```bash
# Build and run with Docker Compose
docker compose up -d

# Or build and run manually
docker build -t ssh-honeypot .
docker run -d \
  -p 2222:2222 -p 8501:8501 -p 8502:8502 \
  --name ssh-honeypot \
  ssh-honeypot
```

### Docker Compose Profiles

```bash
# Development (all-in-one)
docker compose up -d

# Production (honeypot-only worker)
docker compose --profile production up -d honeypot-worker
```

### Container Security

- Runs as **non-root user** (`honeypot`)
- Uses **no-new-privileges** security option
- **Health checks** configured for automatic restart
- **Memory limits** (512 MB default)
- **Read-only GeoIP mounts** for sensitive data

---

## ⚙️ Configuration

All configuration is via environment variables (see [`.env.example`](.env.example) for a complete reference).

### Key Configuration Groups

| Group | Key Variables | Description |
|-------|--------------|-------------|
| **Honeypot** | `HONEYPOT_PORT`, `HONEYPOT_BANNER`, `HONEYPOT_MAX_CONNECTIONS` | SSH server behavior |
| **Database** | `DATABASE_PATH`, `CSV_PATH` | Storage configuration |
| **GeoIP** | `GEOIP_CITY_DB`, `GEOIP_ASN_DB` | MaxMind database paths |
| **Threat Intel** | `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY` | Threat lookup APIs |
| **Alerts** | `TELEGRAM_BOT_TOKEN`, `DISCORD_WEBHOOK_URL`, `SLACK_WEBHOOK_URL` | Alert channels |
| **Dashboard** | `DASHBOARD_PORT`, `DASHBOARD_THEME`, `DASHBOARD_AUTH_ENABLED` | SOC dashboard |
| **API** | `API_PORT`, `API_JWT_ENABLED`, `API_JWT_SECRET` | REST API configuration |

---

## 🛠 Development

### Setup

```bash
git clone https://github.com/Not-Just-Pratul/SSH-Honeypot.git
cd SSH-Honeypot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=ssh_honeypot --cov-report=term-missing

# Run specific test module
pytest tests/test_config.py -v
```

### Linting

```bash
# Ruff linting
ruff check src/ tests/

# Ruff formatting check
ruff format --check src/ tests/

# Type checking
mypy src/

# Security scan
bandit -c pyproject.toml -r src/
```

### Pre-commit Hooks

```bash
pre-commit install
pre-commit run --all-files
```

---

## 📁 Project Structure

```
SSH-Honeypot/
├── src/
│   └── ssh_honeypot/       # Package source
│       ├── __init__.py      # Version and metadata
│       ├── __main__.py      # `python -m ssh_honeypot` entry
│       ├── app.py           # CLI entry point and orchestration
│       ├── config.py        # Environment configuration
│       ├── database.py      # SQLite and CSV storage
│       ├── geo.py           # GeoIP enrichment engine
│       ├── honeypot.py      # SSH honeypot + brute-force detection
│       ├── logger.py        # Logging, alerts, sanitization
│       ├── api_server.py    # REST API with JWT auth
│       └── dashboard.py     # Streamlit SOC dashboard
├── tests/                   # Test suite (111 tests)
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_database.py
│   ├── test_geo.py
│   ├── test_honeypot.py
│   ├── test_logger.py
│   └── test_api.py
├── .github/
│   └── workflows/           # CI/CD pipelines
│       ├── test.yml
│       ├── docker.yml
│       └── security.yml
├── app.py                   # Backward-compatible entry point
├── pyproject.toml           # Project config + dependencies
├── Dockerfile               # Multi-stage production build
├── docker-compose.yml       # Docker orchestration
├── .pre-commit-config.yaml  # Pre-commit hooks
├── .env.example             # Environment template
├── LICENSE                  # MIT License
├── CHANGELOG.md             # Version history
├── CONTRIBUTING.md          # Contribution guide
├── SECURITY.md              # Security policy
└── CODE_OF_CONDUCT.md       # Community guidelines
```

---

## 🔒 Security Considerations

- **Educational Use Only** — This tool is for defensive security research and education.
- **No Shell Access** — The honeypot never grants shell access or executes attacker commands.
- **Network Isolation** — Never expose the honeypot port to the public internet without fail2ban/firewall rules.
- **Secrets Management** — Keep `.env` and `keys/` out of version control (`.gitignore` handles this).
- **API Authentication** — Enable JWT auth for the REST API in production.
- **Non-Root Container** — Docker image runs as an unprivileged user.
- **Input Sanitization** — All attacker-supplied data is sanitized before storage and escaped before HTML rendering.
- **SQL Injection Protection** — All database operations use parameterized queries.

---

## 🗺 Roadmap

- [x] Package restructure with `src/` layout
- [x] Comprehensive test suite (111 tests)
- [x] Docker multi-stage build
- [x] GitHub Actions CI/CD
- [x] JWT authentication for API
- [x] Discord and Slack alert formatting
- [ ] TLS wrapper for REST API
- [ ] Grafana / Prometheus metrics exporter
- [ ] Multi-honeypot support (HTTP, Telnet, RDP)
- [ ] Attack replay / PCAP export
- [ ] Web UI for configuration management
- [ ] Real-time WebSocket attack feed
- [ ] Automated threat scoring and correlation
- [ ] Kubernetes Helm chart
- [ ] Integration with SIEM platforms (ELK, Splunk)

---

## 🤝 Contributing

Contributions are welcome! Please read the [contributing guide](CONTRIBUTING.md) to get started.

This project follows [Conventional Commits](https://www.conventionalcommits.org/) and [Semantic Versioning](https://semver.org/).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
Built with ❤️ for the cybersecurity community
</div>