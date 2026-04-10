# Architecture

Technical design notes for the honeypot project.

## Why asyncio

SSH and Telnet honeypots use `asyncio` rather than threads or processes. A honeypot that implements tarpit delays (sleeping 2 seconds per failed auth attempt) would exhaust a thread pool almost immediately under any real scanner load — scanners like Masscan or ZMap fire thousands of parallel connections. With asyncio, each connection is a coroutine that yields during `await asyncio.sleep(delay)`, so a single thread handles thousands of concurrent tarpitted connections at zero extra memory cost.

The HTTP honeypot uses Flask in a daemon thread (WSGI, not async). Flask's `threaded=True` mode is sufficient here because HTTP honeypot connections are short-lived and don't tarpit — the overhead of a full asyncio HTTP server (e.g. aiohttp) isn't warranted.

## Tarpit strategy

Auth failure delay is configurable (default 2 seconds per attempt). Even at 2s, a scanner testing 5 passwords against 10 honeypot IPs ties up 50 connections for 2 seconds each. Most mass scanners have connection pools of 100–500; 2s delays mean a honeypot can meaningfully slow down a mid-tier botnet scanner with no CPU cost.

Deliberate delay on success (0.5s) makes the tarpit non-detectable: both success and failure paths have delay, so timing attacks can't fingerprint the honeypot as a honeypot.

## Session correlation

Every TCP connection (SSH or Telnet) generates a `session_id` UUID at connect time. All events from that connection — auth attempts, individual commands — share the same `session_id`. This enables analyst queries like "show me all commands run in sessions where the attacker initially tried root/1234", which reveals attacker behavioral chains rather than isolated events. SQLite's `GROUP BY session_id` makes this cheap to query.

## Fake shell design

The fake shell (`services/fake_shell.py`) focuses on the 15–20 commands attackers actually run immediately after gaining shell access:

- **Reconnaissance**: `uname -a`, `id`, `whoami`, `cat /etc/passwd`, `cat /etc/shadow`, `ifconfig`
- **Persistence setup**: `crontab -l`, `cat /etc/crontab`
- **Payload download**: `wget <url>`, `curl <url>`
- **Environment**: `env`, `echo $PATH`, `history`

Commands outside this set return `command not found`, which is realistic — most IoT/VPS targets run minimal shells. Returning plausible output for `wget` and `curl` (connection refused) avoids revealing the sandbox: a real honeypot would want to log the full payload URL, not silently succeed or return an error that exposes the environment.

## Geolocation accuracy

`ip-api.com` returns city-level geolocation, which is accurate to within ~50km for most ISP-assigned IPs but is effectively useless for Tor exit nodes and VPN endpoints (which will geolocate to the VPN provider's HQ). ASN and ISP data is more reliable and more actionable — "AS14061 DigitalOcean" tells you more about attacker infrastructure than "City: Clifton, NJ".

The 24-hour cache TTL is a deliberate trade-off: IP-to-ASN mapping changes infrequently, but the free tier limit (45 req/min) means uncached fresh traffic would exhaust the quota within seconds during an active scan wave.

## SQLite vs. alternatives

SQLite is the right choice for a single-node honeypot:
- Zero ops overhead — no database daemon to manage
- The DB file is trivially portable and inspectable with standard tooling (`sqlite3` CLI, DB Browser)
- Write throughput (INSERT + commit) handles ~1,000 events/sec on a modern SSD, which exceeds any realistic honeypot ingest rate

You'd reach for **PostgreSQL** if you were aggregating data from multiple distributed honeypot nodes. You'd reach for **Elasticsearch** if you needed full-text search across command strings or wanted to feed Kibana dashboards. Neither is warranted at single-node scale.

## Known limitations and future work

- **No TLS inspection on HTTP**: attackers using HTTPS won't show up unless you terminate TLS in front of the honeypot.
- **No SMB/FTP/RDP honeypots**: SMB (port 445) and RDP (port 3389) are heavily scanned. Adding them would require implementing or wrapping more protocol parsers.
- **SQLite write contention**: With all three services writing to the same SQLite file from different threads, WAL mode would reduce contention under heavy concurrent load. Currently using the default rollback journal.
- **No alerting**: A production deployment would integrate with a webhook (Slack, PagerDuty) to fire on new unique attacker IPs or specific command patterns (e.g., any `curl`/`wget` command).
- **Dashboard auth**: The dashboard has no authentication. In deployment it should be bound to localhost and accessed via SSH tunnel or protected by a reverse proxy with HTTP basic auth.
