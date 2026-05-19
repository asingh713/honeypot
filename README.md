# Honeypot

A multi-service deception system for threat intelligence. Emulates SSH, HTTP, and Telnet services to capture and analyze attacker behavior, with geo-IP enrichment and a real-time web dashboard.

## Services

| Service | Default Port | Emulates |
|---------|-------------|----------|
| SSH | 2222 | OpenSSH 7.4 |
| HTTP | 8080 | Apache 2.4 / PHP 7.4 router |
| Telnet | 2323 | Generic terminal |
| Dashboard | 5000 | Flask web UI |

## Features

- Captures login attempts, commands, and session data per attacker IP
- Geo-IP enrichment with caching and rate limiting
- SQLite event storage
- Rate limiting per IP
- Rotating file logs
- YAML-based configuration with env var overrides

## Structure

```
honeypot/
├── honeypot/
│   ├── core/            # config, database, geo, logger
│   ├── services/        # ssh_honeypot, http_honeypot, telnet_honeypot, base_service
│   ├── dashboard/       # Flask app and routes
│   └── fake_data/       # decoy credentials and response data
├── tests/
└── config.yaml
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml   # edit ports/credentials as needed
python -m honeypot
```

Dashboard available at `http://localhost:5000`.

## Configuration

All settings live in `config.yaml`. Key env var overrides:

```bash
HONEYPOT_SSH_PORT=2222
HONEYPOT_HTTP_PORT=8080
HONEYPOT_TELNET_PORT=2323
HONEYPOT_DASHBOARD_PORT=5000
HONEYPOT_CONFIG_PATH=config.yaml
```
