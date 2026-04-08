# GL.iNet Log Analyzer

Local tooling for inspecting GL.iNet router logs from either a command line or a browser.

## What it does

- Parses plaintext router logs line by line.
- Detects timestamps, likely severity, component names, and network/security categories.
- Detects GL.iNet-relevant signals such as WAN up/down, DHCP leases, Wi-Fi joins, DNS failures, auth failures, firewall drops, VPN handshakes, modem events, and firmware updates.
- Handles single files plus `.zip`, `.tar`, `.tar.gz`, `.tgz`, and `.gz` bundles by extracting likely log files inside them.
- Highlights notable events and builds an operational timeline for browser and CLI review.
- Exposes the same analysis engine through a CLI and a small FastAPI web UI.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

Analyze a file in the terminal:

```bash
glinet-log-analyzer analyze sample_logs/sample.log
glinet-log-analyzer analyze sample_logs/sample.log --output json
glinet-log-analyzer analyze router-support-bundle.zip --signal dns_failure --export filtered.csv
```

Run the web UI:

```bash
glinet-log-analyzer web --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000`.

Uploaded reports can then be filtered by severity, category, signal, source path, or free-text search, and exported from the web UI as JSON or CSV.

## Docker

Build and run directly:

```bash
docker build -t glinet-log-analyzer .
docker run --rm -p 8000:8000 glinet-log-analyzer
```

Or with Compose:

```bash
docker compose up --build
```

Then open `http://localhost:8000`.

Deployment notes:

- The container serves the ASGI app with `uvicorn glinet_log_analyzer.asgi:app`.
- Health checks can use `GET /healthz`.
- Uploaded reports are stored on disk under `GLINET_LOG_ANALYZER_DATA_DIR` and persist across container restarts when `/data` is backed by a volume.
- For public hosting behind Nginx, Caddy, Traefik, or a cloud load balancer, proxy traffic to container port `8000`.

Relevant environment variables:

- `GLINET_LOG_ANALYZER_HOST`
- `GLINET_LOG_ANALYZER_PORT`
- `GLINET_LOG_ANALYZER_DATA_DIR`

Reverse proxy examples are included in [deploy/nginx.conf](C:/Users/nick/Documents/GitHub/GL.iNet-Log-Analyzer/deploy/nginx.conf) and [deploy/Caddyfile](C:/Users/nick/Documents/GitHub/GL.iNet-Log-Analyzer/deploy/Caddyfile).

## Project layout

```text
src/glinet_log_analyzer/analyzer.py   Shared parsing and classification logic
src/glinet_log_analyzer/cli.py        CLI entrypoints
src/glinet_log_analyzer/web.py        FastAPI application
src/glinet_log_analyzer/templates/    Web UI templates
tests/                                Smoke tests for parsing behavior
sample_logs/                          Sample input for local testing
```

## Current GL.iNet-focused coverage

- WAN state changes and DHCP lease acquisition
- Wi-Fi client joins
- DNS lookup failures
- Authentication failures
- Firewall drops
- WireGuard/OpenVPN handshake activity
- Modem, SIM, and cellular signal metrics
- `mwan3` and failover/offline events
- USB tethering interfaces
- Firmware update activity
