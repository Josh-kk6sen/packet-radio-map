#!/usr/bin/env python3
"""Check for MAP packets that failed to update map markers.
Runs every 2 hours via cron. Reports only when issues found or when all clear.
"""
import sqlite3
import re
import sys
import os
from datetime import datetime, timezone, timedelta

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("DB_PATH", os.path.join(PROJECT_DIR, "db", "packet_radio.db"))
STATE_FILE = os.environ.get("CTL_STATE_FILE", os.path.join(PROJECT_DIR, ".map_monitor_state"))
FIRST_GOOD_TIME = "2026-06-01T03:46:00+00:00"
LOOKBACK_MARGIN = 5  # overlap 5 min to avoid edge gaps

def extract_display_name(info_ascii):
    if not info_ascii:
        return None
    m = re.search(r'<MAP:-?\d+\.\d+,-?\d+\.\d+,([^,]+),([^>]+)>', info_ascii, re.IGNORECASE)
    if m:
        return m.group(2).strip()
    m = re.search(r'<MAP:-?\d+\.\d+,-?\d+\.\d+\|([^|]+)\|([^|]+)>', info_ascii, re.IGNORECASE)
    if m:
        return m.group(2).strip()
    m = re.search(r'<MAP:-?\d+\.\d+,-?\d+\.\d+,([^,>]+)>', info_ascii, re.IGNORECASE)
    if m:
        return m.group(1).strip().upper()
    m = re.search(r'<MAP:-?\d+\.\d+,-?\d+\.\d+\|([^|]+)>', info_ascii, re.IGNORECASE)
    if m:
        return m.group(1).strip().upper()
    return None

def read_cutoff():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return f.read().strip()
    return FIRST_GOOD_TIME

def write_cutoff(ts):
    with open(STATE_FILE, 'w') as f:
        f.write(ts)

def parse_ts(ts_str):
    if not ts_str:
        return None
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None

def fmt_pdt(utc_dt):
    """Format a UTC datetime as PDT time string."""
    pdt = utc_dt - timedelta(hours=7)
    return pdt.strftime("%I:%M %p").lstrip("0")

def main():
    cutoff_str = read_cutoff()
    cutoff = parse_ts(cutoff_str)
    if cutoff:
        cutoff = cutoff - timedelta(minutes=LOOKBACK_MARGIN)
    else:
        cutoff = parse_ts(FIRST_GOOD_TIME)
    
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    
    db = sqlite3.connect(DB_PATH)
    
    cur = db.execute(
        "SELECT id, timestamp, source, info_ascii FROM packets "
        "WHERE (info_ascii LIKE '%<MAP:%' OR info_ascii LIKE '%<map:%') "
        "AND timestamp >= ? "
        "ORDER BY id ASC",
        (cutoff.isoformat() if cutoff else FIRST_GOOD_TIME,)
    )
    map_packets = cur.fetchall()
    
    if not map_packets:
        write_cutoff(now_str)
        db.close()
        return  # Silent - nothing to report
    
    cur = db.execute("SELECT display_name, last_seen, packet_count FROM map_markers")
    markers = {row[0]: {"last_seen": row[1], "packet_count": row[2]} for row in cur.fetchall()}
    db.close()
    
    failures = []
    successes = 0
    latest_ts = cutoff_str
    
    for pid, ts, src, info in map_packets:
        if ts > latest_ts:
            latest_ts = ts
        
        disp_name = extract_display_name(info)
        if not disp_name:
            failures.append(
                f"    Packet {pid} ({ts}): Could not parse display_name from: {info[:100]}")
            continue
        
        pkt_time = parse_ts(ts)
        
        if disp_name not in markers:
            failures.append(
                f"    Packet {pid} ({ts}): nodename='{disp_name}' from {src} "
                f"has NO matching marker!")
            continue
        
        marker_time = parse_ts(markers[disp_name]["last_seen"])
        if pkt_time and marker_time and marker_time < pkt_time:
            time_diff = (pkt_time - marker_time).total_seconds()
            if time_diff > 60:
                failures.append(
                    f"    Packet {pid} ({ts}): nodename='{disp_name}' from {src} NOT UPDATED. "
                    f"Marker last_seen={markers[disp_name]['last_seen']} "
                    f"({int(time_diff)}s stale). count={markers[disp_name]['packet_count']}.")
                continue
        
        successes += 1
    
    write_cutoff(latest_ts)
    
    if failures:
        print(f"⚠ MAP Monitor [{fmt_pdt(now)} PDT]: "
              f"{successes} OK, {len(failures)} FAILED")
        for f in failures:
            print(f)
    elif successes > 0:
        print(f"✓ MAP Monitor [{fmt_pdt(now)} PDT]: "
              f"All {successes} MAP packets updated markers OK")

if __name__ == "__main__":
    main()
