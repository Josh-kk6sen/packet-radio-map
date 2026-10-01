# PacketRadio Map

A self-contained packet-radio (APRS/AX.25) **live map + dashboard** that listens to a
[KISS](https://en.wikipedia.org/wiki/KISS_(TNC)) TNC on TCP, decodes AX.25 frames, stores
them in SQLite, and serves an interactive Leaflet map and a statistics dashboard over HTTP.

Built for — and running on — the **KK6SEN** station (145.050 MHz). The code is deliberately
simple: no build step, no framework, just a single Python daemon and a couple of static
HTML pages.

> **Live demo:** see this running on the KK6SEN station at
> [**map.kk6sen.com**](https://map.kk6sen.com) (map at `/map.html`).

## What it does

- Connects to a KISS TNC (e.g. Direwolf) over TCP and decodes incoming AX.25 frames.
- Extracts APRS-style station reports (position, call sign, display name) including
  `<MAP:lat,lon,node,text>` messages.
- Stores packets and marker state in SQLite (`db/packet_radio.db`).
- Serves:
  - `map.html` — a live Leaflet map (OpenStreetMap tiles) of heard stations & links.
  - `index.html` — a statistics dashboard (recent packets, stations, messages).
  - JSON API: `/api/markers`, `/api/packets`, `/api/stats`, `/api/stations`,
    `/api/links`, `/api/mapmsg` (+ `/all`, `/pin`).
- `tunnel_proxy.py` — optional thin reverse proxy (port 9090) used behind a Cloudflare
  tunnel in production; you don't need it for a local setup.

## Requirements

- Python 3.8+
- A KISS TNC reachable over TCP (e.g. **Direwolf** in KISS mode, `-P 8001`)
- No third-party Python packages — the stdlib does it all.

## Quick start

1. Point the daemon at your TNC (default `127.0.0.1:8001`):

   ```bash
   export DIGIPI_HOST=127.0.0.1   # your KISS TNC host
   export KISS_PORT=8001          # your KISS TCP port
   ```

2. Start:

   ```bash
   ./start.sh start
   ```

   Or run the daemon directly:

   ```bash
   python3 daemon/kiss_capture.py
   ```

3. Open the dashboard at [`http://localhost:8080`](http://localhost:8080)
   (map at `/map.html`).

## Configuration

All settings are overridable via environment variables (defaults in parentheses):

| Variable          | Purpose                          | Default              |
|-------------------|----------------------------------|----------------------|
| `DIGIPI_HOST`     | KISS TNC host                    | `127.0.0.1`          |
| `KISS_PORT`       | KISS TNC TCP port                | `8001`               |
| `WEB_HOST`        | Web server bind address          | `0.0.0.0`            |
| `WEB_PORT`        | Web server port                  | `8080`               |
| `DB_PATH`         | SQLite database file             | `<repo>/db/packet_radio.db` |
| `STATIC_DIR`      | Directory with the HTML pages    | `<repo>/web/static`  |
| `RECONNECT_DELAY` | Seconds between TNC reconnects   | `5`                  |

The local database and logs live under `db/` and `*.log` — all git-ignored.

## Optional: `tunnel_proxy.py`

Production serves the map through a Cloudflare tunnel; `tunnel_proxy.py` is a minimal
allow-list reverse proxy in front of the daemon. It is **not** required for a local install.
To run it:

```bash
python3 tunnel_proxy.py   # listens on 127.0.0.1:9090, proxies to :8080
```

## Health monitoring

`monitor_map_updates.py` is a cron-friendly checker that reports MAP packets which
failed to update their marker (stale/unmatched `display_name`). Run it on a schedule:

```bash
# crontab example — every 2 hours
0 */2 * * * python3 /path/to/monitor_map_updates.py
```

## Project layout

```
daemon/
  kiss_capture.py       # KISS TNC listener + AX.25 decode + SQLite + web server
web/static/
  map.html              # live Leaflet map
  index.html            # dashboard
monitor_map_updates.py  # cron health checker
tunnel_proxy.py         # optional allow-list reverse proxy
start.sh                # start/stop/status/logs helper
```

## License

[MIT](LICENSE).