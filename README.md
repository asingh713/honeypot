# Honeypot

A multi-service honeypot for passive threat intelligence collection. Emulates SSH, HTTP admin panels, and Telnet to capture attacker behavior — credentials tried, commands run, and scanner fingerprints — with a real-time web dashboard and IP geolocation.

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
└──────────────┬──────────────┬──────────────────────────────┘
               │              │              │
        SSH :2222      HTTP :8080      Telnet :2323
               │              │              │
       ┌───────▼──────────────▼──────────────▼───────┐
       │            Honeypot Services                 │
       │   • Tarpit (delayed auth failure)            │
       │   • Fake interactive shell (SSH/Telnet)      │
       │   • Fake admin login page (HTTP)             │
       └───────────────────┬──────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  SQLite DB  │  ← events + geo cache
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Dashboard  │  :5000
                    │  Overview / Events / Map
                    └─────────────┘
```

## Features

- **SSH honeypot** — impersonates OpenSSH 7.4; logs every credential attempt; traps configured credentials into a fake interactive shell with realistic command responses; tarpits failed auth with a configurable delay to waste scanner time
- **HTTP honeypot** — convincing fake admin login page (router / WordPress / NAS personas); logs credentials POSTed to `/login`; baits common scanner paths (`.env`, `wp-login.php`, `phpMyAdmin`, etc.)
- **Telnet honeypot** — targets Mirai-style IoT botnet scanners; serves fake router banners; logs `admin/admin`, `root/root`, and other default credentials
- **Session correlation** — commands within a single SSH/Telnet session share a `session_id` UUID, enabling behavioral chain analysis
- **IP geolocation** — country, city, ISP, and ASN via ip-api.com; results cached in SQLite; rate-limited to stay within free-tier quota
- **Rate limiting** — per-IP event cap prevents log flooding from aggressive scanners
- **Web dashboard** — live overview, paginated event log with filters, world map of attacker origins (Leaflet.js)
- **JSON/CSV export** — CLI tool for piping data to a SIEM or spreadsheet
- **Docker-ready** — single `docker compose up` deployment; runs as a non-root user; resource-capped

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/youruser/honeypot
cd honeypot
cp .env.example .env
docker compose up -d
```

Dashboard: http://localhost:5000

### Local (dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdir -p data logs
python main.py
```

## Configuration

Edit `config.yaml` to tune ports, fake personas, trap credentials, tarpit delays, and rate limits.

| Key | Default | Description |
|---|---|---|
| `ssh.port` | `2222` | SSH honeypot port |
| `ssh.auth_fail_delay` | `2.0s` | Tarpit delay on failed auth |
| `ssh.trap_credentials` | `admin/admin`, `root/root`, … | Credentials that open the fake shell |
| `http.persona` | `router` | Fake admin panel style (`router`, `wordpress`, `nas`) |
| `telnet.port` | `2323` | Telnet honeypot port |
| `dashboard.port` | `5000` | Dashboard port |
| `geo.enabled` | `true` | Toggle IP geolocation |
| `rate_limit.max_events_per_ip_per_minute` | `30` | Anti-flood cap |

Environment variables override config file values: `HONEYPOT_SSH_PORT`, `HONEYPOT_HTTP_PORT`, `HONEYPOT_TELNET_PORT`, `HONEYPOT_DASHBOARD_PORT`.

## Export

```bash
# All events as JSON
python scripts/export_report.py --format json

# SSH events since April 1, output to file
python scripts/export_report.py --format csv --service ssh --since 2026-04-01 --output ssh_events.csv

# Top 20 attacker IPs
python scripts/export_report.py --top-ips 20
```

## Sample Captured Data

```json
[
  {
    "id": 1,
    "timestamp": "2026-04-09T14:23:01+00:00",
    "service": "ssh",
    "src_ip": "185.220.101.x",
    "src_port": 49321,
    "username": "root",
    "password": "123456",
    "command": null,
    "session_id": "a1b2c3d4-..."
  },
  {
    "id": 47,
    "timestamp": "2026-04-09T14:25:18+00:00",
    "service": "ssh",
    "src_ip": "185.220.101.x",
    "src_port": 49321,
    "username": null,
    "password": null,
    "command": "cat /etc/passwd",
    "session_id": "a1b2c3d4-..."
  }
]
```

## Tests

```bash
pip install pytest
pytest tests/ -v
```

## Security Considerations

- **Deploy only on infrastructure you own and control.** Running a honeypot on a cloud VM is typical; never deploy on a network you don't have written permission to monitor.
- **Don't expose the dashboard publicly.** Bind it to localhost or protect it with a reverse proxy + auth.
- **No real credentials are stored.** The honeypot never actually authenticates anyone to a real system.
- **Container runs as UID 1000** (non-root) with CPU and memory limits set in `docker-compose.yml`.
- **Logs may contain attacker data.** Treat `data/honeypot.db` and `logs/` as potentially sensitive; don't commit them (`.gitignore` excludes both).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for design rationale, trade-off analysis, and notes on what you'd change at larger scale.
