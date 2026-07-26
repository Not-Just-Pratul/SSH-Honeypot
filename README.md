# SSH Honeypot + Live Alert Dashboard

Defensive security tool that simulates an SSH server to capture attack metadata in real-time, with a live SOC-style dashboard and REST API.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-Educational-green)

## Features

- **SSR Honeypot** — Accepts connections on a configurable port, logs every auth attempt (password, publickey, keyboard-interactive), and rejects all of them
- **Brute-Force Detection** — Tracks failed attempts per IP, triggers optional fail2ban integration when threshold is exceeded
- **GeoIP Enrichment** — Enriches attacker IPs with country, city, ASN, and org data using MaxMind GeoLite2
- **Threat Intelligence** — Optional AbuseIPDB / VirusTotal / GreyNoise / Shodan lookups
- **Live Dashboard** — Streamlit-based SOC dashboard with dark/light theme, real-time stats, charts, map, live feed, filters, and exports
- **REST API** — Threaded HTTP endpoints for `/api/attacks`, `/api/stats`, `/api/health`
- **Alerts** — Async Telegram, Discord, Slack, and email notifications

## Quick Start

### 1. Install Dependencies

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Generate SSH Host Key

The honeypot needs an RSA host key to complete the SSH handshake.

```powershell
mkdir keys
openssl genrsa -out keys\ssh_host_rsa_key 2048
```

### 3. Configure Environment

```powershell
copy .env.example .env
notepad .env
```

### 4. Run the App

```powershell
python app.py
```

This starts the honeypot, dashboard, and REST API together. Press `Ctrl+C` to stop.

### 5. Open the Dashboard

```
http://localhost:8501
```

## Testing SSH Connections

### From Windows (built-in OpenSSH)

```powershell
ssh -p 2222 -o StrictHostKeyChecking=no admin@localhost
```

Try different usernames and passwords. Every attempt is logged. The honeypot never grants access and will reject all auth methods.

### From Linux / macOS

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@<your-ip>
```

### From Python (automated)

```python
import paramiko, socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 2222))
transport = paramiko.Transport(sock)
transport.add_server_key(paramiko.RSAKey(filename="keys/ssh_host_rsa_key"))

class FakeServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"[LOGIN] {username}:{password}")
        return paramiko.AUTH_FAILED

transport.start_server(server=FakeServer())
```

### From nmap / ncat

```bash
ncat -v 127.0.0.1 2222
```

## Command-Line Options

```powershell
python app.py [mode] [options]
```

| Mode | Description |
|---|---|
| `honeypot` | Start only the SSH honeypot (port 2222) |
| `dashboard` | Start only the Streamlit dashboard (port 8501) |
| `api` | Start only the REST API (port 8502) |
| `all` (default) | Start honeypot + dashboard + API |

| Option | Description |
|---|---|
| `--host <ip>` | Override honeypot bind host |
| `--port <port>` | Override honeypot bind port |
| `--dashboard-port <port>` | Override dashboard port |
| `--log-level <LEVEL>` | Set verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## Environment Variables

Copy `.env.example` to `.env` and fill in the values you need.

### Honeypot

| Variable | Default | Description |
|---|---|---|
| `HONEYPOT_HOST` | `0.0.0.0` | Bind address |
| `HONEYPOT_PORT` | `2222` | Bind port |
| `HONEYPOT_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4` | SSH banner string |
| `HONEYPOT_SERVER_VERSION` | `SSH-2.0-OpenSSH_8.9p1` | Reported server version |
| `HONEYPOT_MAX_CONNECTIONS` | `100` | Backlog queue size |
| `HONEYPOT_CONNECTION_TIMEOUT` | `30` | Seconds before idle disconnect |
| `HONEYPOT_MAX_AUTH_TRIES` | `3` | (Reserved) Max auth attempts per session |
| `HONEYPOT_HOST_KEY_PATH` | `keys/ssh_host_rsa_key` | RSA private key path |
| `HONEYPOT_REJECT_PASSWORD` | `true` | Reject password auth |
| `HONEYPOT_REJECT_PUBLIC_KEY` | `true` | Reject public key auth |
| `HONEYPOT_REJECT_KEYBOARD_INTERACTIVE` | `true` | Reject keyboard-interactive |

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `logs/attack_logs.db` | SQLite database path |
| `CSV_PATH` | `logs/attack_logs.csv` | CSV export path |
| `CSV_ROTATION_SIZE_MB` | `10` | Rotate CSV after this size |
| `CSV_MAX_BACKUPS` | `5` | Keep this many rotated CSVs |

### GeoIP

| Variable | Default | Description |
|---|---|---|
| `GEOIP_CITY_DB` | _(empty)_ | Path to GeoLite2-City.mmdb |
| `GEOIP_ASN_DB` | _(empty)_ | Path to GeoLite2-ASN.mmdb |
| `GEOIP_DEFAULT_COUNTRY` | `Unknown` | Fallback country |
| `GEOIP_DEFAULT_CITY` | `Unknown` | Fallback city |
| `GEOIP_DEFAULT_LAT` | `0.0` | Fallback latitude |
| `GEOIP_DEFAULT_LON` | `0.0` | Fallback longitude |
| `GEOIP_DEFAULT_ASN` | `Unknown` | Fallback ASN |
| `GEOIP_DEFAULT_ORG` | `Unknown` | Fallback org |

Download GeoLite2 databases from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-gupdated-databases) (free account required).

### Threat Intelligence

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key |
| `ABUSEIPDB_BASE_URL` | `https://api.abuseipdb.com/api/v2` | AbuseIPDB endpoint |
| `VIRUSTOTAL_API_KEY` | _(empty)_ | VirusTotal API key |
| `GREYNOISE_API_KEY` | _(empty)_ | GreyNoise API key |
| `SHODAN_API_KEY` | _(empty)_ | Shodan API key |
| `ENABLE_THREAT_SCORE` | `false` | Enable combined threat scoring |
| `THREAT_SCORE_CACHE_TTL` | `3600` | Cache TTL in seconds |

### Alerts

| Variable | Default | Description |
|---|---|---|
| `EMAIL_ENABLED` | `false` | Enable email alerts |
| `EMAIL_SMTP_SERVER` | `smtp.gmail.com` | SMTP server |
| `EMAIL_SMTP_PORT` | `587` | SMTP port |
| `EMAIL_SENDER` | _(empty)_ | From address |
| `EMAIL_USERNAME` | _(empty)_ | SMTP username |
| `EMAIL_PASSWORD` | _(empty)_ | SMTP password / app password |
| `EMAIL_RECIPIENTS` | _(empty)_ | Comma-separated recipient list |
| `DISCORD_WEBHOOK_URL` | _(empty)_ | Discord webhook URL |
| `SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook URL |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | Telegram bot token |
| `TELEGRAM_CHAT_ID` | _(empty)_ | Telegram chat ID |

### Dashboard

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_PORT` | `8501` | Dashboard port |
| `DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind address |
| `DASHBOARD_REFRESH_INTERVAL` | `5` | Auto-refresh seconds |
| `DASHBOARD_THEME` | `dark` | Default theme (`dark` or `light`) |
| `DASHBOARD_AUTH_ENABLED` | `false` | Enable basic auth |
| `DASHBOARD_USER` | `admin` | Dashboard username |
| `DASHBOARD_PASS` | _(empty)_ | Dashboard password |

### REST API

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8502` | API port |
| `API_ENABLED` | `true` | Enable/disable API server |

## Dashboard Pages

| Page | Description |
|---|---|
| **Overview** | Summary stats + attack timeline chart |
| **Charts** | Hourly bar, top usernames, daily scatter, country pie, auth vector pie, top IPs, ASN bar, heatmap (day x hour), hourly trend line |
| **Interactive Map** | Folium-based world map of attacker geolocations |
| **Live Feed** | Real-time scrolling feed of the latest 50 attacks |
| **Filters & Search** | Multi-select filters by country, username, status, IP; free-text search across all fields |
| **Statistics** | Unique counts, most targeted usernames, peak attack hour, top countries |
| **Export** | Export data as CSV, JSON, Excel (.xlsx), or PDF report |

## REST API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/attacks` | All attack logs (newest first) |
| `GET` | `/api/attacks/latest?limit=50` | Latest N attack logs |
| `GET` | `/api/stats` | Aggregate stats (total, today, unique IPs, countries) |
| `GET` | `/api/health` | Health check |

All responses are JSON. CORS is enabled for all origins (`Access-Control-Allow-Origin: *`).

## Database Schema

```sql
CREATE TABLE attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    country TEXT DEFAULT 'Unknown',
    city TEXT DEFAULT 'Unknown',
    username TEXT NOT NULL,
    auth_method TEXT DEFAULT 'password',
    client_version TEXT DEFAULT '',
    attempts INTEGER DEFAULT 1,
    status TEXT DEFAULT 'failure',
    latitude REAL DEFAULT 0.0,
    longitude REAL DEFAULT 0.0,
    asn TEXT DEFAULT 'Unknown',
    org TEXT DEFAULT 'Unknown',
    session_id TEXT DEFAULT '',
    connection_duration REAL DEFAULT 0.0,
    protocol_version TEXT DEFAULT '',
    parsed BOOLEAN DEFAULT 0
);
```

## What Gets Logged

For every connection, the honeypot records:

- **timestamp** — ISO-8601 UTC time
- **ip** — Source IP address
- **country / city** — GeoIP enrichment (if configured)
- **username** — Attacker-supplied username
- **auth_method** — `password`, `publickey`, `keyboard-interactive`, or `none`
- **client_version** — Remote SSH client version string
- **protocol_version** — SSH protocol version
- **attempts** — Number of auth attempts in this session
- **status** — Always `failure` (honeypot rejects everything)
- **session_id** — Unique session identifier
- **connection_duration** — Seconds the connection was open
- **latitude / longitude** — GeoIP coordinates
- **asn / org** — ASN and organization from GeoIP

**The password itself is never stored.**

## Troubleshooting

### `Host key not found`
Generate the key: `openssl genrsa -out keys/ssh_host_rsa_key 2048`

### `Failed to bind to 0.0.0.0:2222`
Another process is using the port. Change `HONEYPOT_PORT` or stop the conflicting service.

### `GeoIP enrichment disabled`
Install `geoip2` and download GeoLite2 databases. Set `GEOIP_CITY_DB` and `GEOIP_ASN_DB` paths in `.env`.

### Dashboard shows "No attack data available"
The honeypot hasn't received any connections yet. Test with `ssh -p 2222 localhost`.

### No duplicate log entries
Duplicate logging was fixed in `app.py`. The `"ssh_honeypot"` logger is configured once with `propagate=False` to prevent double-handling between `app.py` and `logger.py`.

## Security Notes

- This tool is for **defensive security research and education only**.
- The honeypot never grants shell access or executes attacker commands.
- Never expose the honeypot port to the public internet without fail2ban / firewall rules.
- Keep `.env` and `keys/` out of version control. Use `.gitignore`.
- Telegram/Discord/Slack webhooks and API keys should be treated as secrets.

## Recent Changes

- Fixed duplicate log messages by configuring the `"ssh_honeypot"` logger once in `app.py` with `propagate=False`
- Fixed `dashboard.py` indentation in `_render_charts` that broke chart rendering
- Replaced deprecated Streamlit `use_container_width=True` with `width="stretch"`
- Added missing `threading` import in `logger.py` for async Telegram alerts
- Moved `_env_float` before `GeoConfig` in `config.py` to fix NameError
- Renamed `database._sanitize` to `_clean_string` (all call sites updated)
- Cached RSA host key in `honeypot.py` to avoid repeated file I/O
- Removed double `transport.accept()` call that could cause hangs
- Added XSS escaping (`_escape_html`) and Plotly layout helper (`_plotly_layout`) in dashboard
- Updated `.env.example` to cover all config fields (honeypot, database, geo, threat intel, alerts, dashboard, API)
- Added `.gitignore` for `__pycache__`, `.env`, `logs/`, `keys/`, venv, IDE files
- Removed unused `pydantic` and `maxminddb` from `requirements.txt`

## Todo

- [ ] Enforce `HONEYPOT_MAX_AUTH_TRIES` per-session in `honeypot.py`
- [ ] Add TLS wrapper for REST API
- [ ] Add JWT auth for API endpoints
- [ ] Add fail2ban integration toggle in .env
- [ ] Add attack replay / PCAP export
- [ ] Add Slack message formatting (blocks)
- [ ] Add unit tests for database, logger, and honeypot handler
- [ ] Add Dockerfile + docker-compose for one-command deployment
- [ ] Add Grafana / Prometheus metrics exporter
- [ ] Add multi-honeypot support (HTTP, Telnet, RDP)
- [ ] Add automated threat scoring (aggregate AbuseIPDB + VirusTotal + GreyNoise into single score)
