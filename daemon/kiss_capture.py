#!/usr/bin/env python3
"""
KISS TNC Capture Daemon + Web Dashboard Server
Connects to a Direwolf KISS TCP port, parses AX.25 frames,
stores them in SQLite, and serves a live web dashboard.

Designed for Phase 1 (passive monitoring) with Phase 2 (active
transmission) in mind — structured for extension.
"""

import sqlite3
import json
import time
import threading
import socket
import os
import sys
import re
import http.server
import urllib.parse
import zoneinfo
from zoneinfo import ZoneInfo
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ─── Configuration ────────────────────────────────────────────────
# All values can be overridden via environment variables for easy
# deployment elsewhere (e.g. DIGIPI_HOST=10.0.0.5 ./start.sh).
DIGIPI_HOST = os.environ.get("DIGIPI_HOST", "127.0.0.1")
KISS_PORT = int(os.environ.get("KISS_PORT", "8001"))
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "packet_radio.db"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
STATIC_DIR = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "static"))
RECONNECT_DELAY = int(os.environ.get("RECONNECT_DELAY", "5"))  # seconds between reconnect attempts

# ─── KISS Protocol Constants ──────────────────────────────────────
FEND = 0xC0   # Frame End delimiter
FESC = 0xDB   # Escape byte
TFEND = 0xDC  # Escaped FEND (after FESC)
TFESC = 0xDD  # Escaped FESC (after FESC)

# ─── NET/ROM Routing Decoder ─────────────────────────────────────
def ax25_decode(addr_bytes):
    """Decode 6 bytes of AX.25-encoded callsign to plain ASCII.

    Each byte is left-shifted by 1 (bit 0 = extension/C-R flag).
    Reverse by right-shifting by 1.
    """
    result = []
    for b in addr_bytes[:6]:
        c = (b >> 1) & 0x7F
        if c == 0:
            c = 0x20  # space for null padding
        result.append(chr(c))
    return ''.join(result).rstrip()


def _is_valid_node(name):
    """Check if a node name looks valid: 2-6 chars, alphanumeric only."""
    if len(name) < 2:
        return False
    return all(c.isalnum() for c in name)


def decode_netrom_routing(payload_bytes):
    """Decode a NET/ROM routing table from raw binary payload bytes.

    Format observed from AGWPE line-mode (DigiPi) NODES broadcasts:
    1. Leading 0xFF byte (AGWPE/KISS framing indicator) is skipped.
    2. Each entry is 13 bytes:
       - 6 bytes: originating node name (plain ASCII, space-padded)
       - 6 bytes: neighbor callsign (AX.25-encoded — left-shifted by 1)
       - 1 byte:  quality (routing cost / hop metric)

    Some entries in the broadcast have node names in mixed format
    (first byte plain ASCII, remaining 5 AX25-encoded). This function
    scans the payload linearly and validates each potential entry.

    Returns a human-readable string like 'BERRY->KF6ANX(8) | BANNER->KF6DQU(18)'
    or None if no valid routing entries found.
    """
    data = payload_bytes
    # Skip leading AGWPE port/framing byte
    if data and data[0] == 0xFF:
        data = data[1:]

    entries = []
    i = 0
    while i + 12 < len(data):
        # Try to read a 6-byte plain-ASCII node name
        raw_node = data[i:i+6]
        node_ascii = raw_node.rstrip(b' \\x00').decode('ascii', errors='replace')

        # Try to read a 6-byte AX.25-encoded node name
        node_ax25 = ax25_decode(raw_node)

        # Read the neighbor (always 6 bytes AX.25-encoded)
        neighbor_raw = data[i+6:i+12]
        if len(neighbor_raw) < 6:
            break
        neighbor = ax25_decode(neighbor_raw)

        # Quality byte
        quality = data[i+12] if i+12 < len(data) else 0

        candidate = None
        if _is_valid_node(node_ascii) and _is_valid_node(neighbor) and node_ascii != neighbor:
            candidate = (node_ascii, neighbor, quality)
        elif _is_valid_node(node_ax25) and _is_valid_node(neighbor) and node_ax25 != neighbor:
            candidate = (node_ax25, neighbor, quality)

        if candidate:
            entries.append(candidate)
            i += 13
        else:
            i += 1

    if not entries:
        return None

    # Deduplicate by (node, neighbor) keeping first (highest quality wins
    # the spot, but in practice first seen = correct)
    seen = set()
    unique = []
    for node, neighbor, quality in entries:
        key = (node, neighbor)
        if key not in seen:
            seen.add(key)
            unique.append((node, neighbor, quality))

    # Group neighbors by node with quality
    node_map = {}
    for node, neighbor, quality in unique:
        node_map.setdefault(node, {})[neighbor] = quality

    parts = []
    for node in sorted(node_map, key=str.lower):
        neighbors = node_map[node]
        neighbor_strs = [f"{n}({neighbors[n]})" for n in sorted(neighbors, key=str.lower)]
        parts.append(f"{node}: {', '.join(neighbor_strs)}")

    return " | ".join(parts)

# AX.25 Control Field Values
CTRL_UI   = 0x03
CTRL_SABM = 0x2F
CTRL_DISC = 0x43
CTRL_DM   = 0x0F
CTRL_UA   = 0x63

FRAME_TYPE_NAMES = {
    0x03: "UI",     # Unnumbered Information (broadcast/beacon)
    0x2F: "SABM",   # Connect request
    0x43: "DISC",   # Disconnect
    0x0F: "DM",     # Disconnected Mode
    0x63: "UA",     # Unnumbered Acknowledgment
}

S_FRAME_TYPES = ["RR", "RNR", "REJ", "SREJ"]


def resolve_frame_type(control):
    """Resolve a control byte to a human-readable frame type name.
    Handles U-frames, I-frames, and S-frames."""
    if control in FRAME_TYPE_NAMES:
        return FRAME_TYPE_NAMES[control]
    if (control & 0x01) == 0:      # bit 0 = 0 → I-frame
        return "I"
    if (control & 0x03) == 0x01:   # bits 0-1 = 01 → S-frame
        return S_FRAME_TYPES[(control >> 2) & 0x03]
    if (control & 0x03) == 0x03:   # bits 0-1 = 11 → U-frame (unnamed)
        # Try common U-frame modifiers not in FRAME_TYPE_NAMES
        u_mod = (control >> 2) & 0x3F
        U_NAMES = {0x00: "UI", 0x0B: "SABM", 0x10: "DISC", 0x18: "UA",
                   0x03: "DM", 0x21: "FRMR", 0x1B: "SABME",
                   # P/F=1 variants
                   0x07: "DM", 0x14: "DISC", 0x1C: "UA",
                   0x2B: "XID", 0x38: "TEST"}
        return U_NAMES.get(u_mod, f"?0x{control:02X}")
    return f"0x{control:02X}"


def _fmt_time(ts):
    """Parse ISO timestamp string, return HH:MM:SS in Pacific Time."""
    if not ts:
        return "--:--:--"
    try:
        dt = datetime.fromisoformat(ts)
        local = dt.astimezone(ZoneInfo("America/Los_Angeles"))
        return local.strftime("%H:%M:%S")
    except (ValueError, AttributeError, zoneinfo.ZoneInfoNotFoundError):
        return ts[-8:] if len(ts) >= 8 else ts


# ─── Database Layer ───────────────────────────────────────────────
def get_db():
    """Get a thread-local database connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            dest TEXT NOT NULL,
            digipeaters TEXT DEFAULT '',
            source_ssid INTEGER DEFAULT 0,
            dest_ssid INTEGER DEFAULT 0,
            control INTEGER,
            control_name TEXT DEFAULT '',
            pid INTEGER,
            info_hex TEXT DEFAULT '',
            info_ascii TEXT DEFAULT '',
            raw_hex TEXT DEFAULT '',
            raw_text TEXT DEFAULT '',
            hop_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS stations (
            callsign TEXT NOT NULL,
            ssid INTEGER DEFAULT 0,
            first_heard TEXT NOT NULL,
            last_heard TEXT NOT NULL,
            packet_count INTEGER DEFAULT 1,
            last_info TEXT DEFAULT '',
            PRIMARY KEY (callsign, ssid)
        );

        CREATE TABLE IF NOT EXISTS node_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            source_ssid INTEGER DEFAULT 0,
            dest TEXT NOT NULL,
            dest_ssid INTEGER DEFAULT 0,
            via TEXT DEFAULT '',
            link_type TEXT DEFAULT 'heard',
            first_seen TEXT NOT NULL,
            last_seen TEXT,
            count INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS map_markers (
            callsign TEXT NOT NULL,
            ssid INTEGER DEFAULT 0,
            display_name TEXT NOT NULL PRIMARY KEY,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            packet_count INTEGER DEFAULT 1,
            last_path TEXT DEFAULT '',
            static INTEGER DEFAULT 0,
            high_value INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS map_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            pinned INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_packets_source ON packets(source);
        CREATE INDEX IF NOT EXISTS idx_stations_last ON stations(last_heard DESC);
        CREATE INDEX IF NOT EXISTS idx_links_source ON node_links(source);
    """)
    conn.commit()


def insert_packet(conn, data):
    now = datetime.now(timezone.utc).isoformat()
    
    conn.execute("""
        INSERT INTO packets (timestamp, source, dest, digipeaters,
            source_ssid, dest_ssid, control, control_name, pid,
            info_hex, info_ascii, raw_hex, raw_text, hop_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now, data["source"], data["dest"], data["digipeaters_str"],
        data["source_ssid"], data["dest_ssid"],
        data.get("control"), data.get("control_name", ""),
        data.get("pid"), data.get("info_hex", ""),
        data.get("info_ascii", ""), data.get("raw_hex", ""),
        data.get("raw_text", ""),
        data.get("hop_count", 0)
    ))
    packet_id = conn.cursor().lastrowid

    # Update stations (source only — dest-only entries clutter the heard list)
    for callsign, ssid, label in [
        (data["source"], data["source_ssid"], "source"),
    ]:
        row = conn.execute(
            "SELECT * FROM stations WHERE callsign=? AND ssid=?",
            (callsign, ssid)
        ).fetchone()
        if row:
            conn.execute("""
                UPDATE stations SET last_heard=?, packet_count=packet_count+1,
                    last_info=?
                WHERE callsign=? AND ssid=?
            """, (now, data.get("info_ascii", "")[:200], callsign, ssid))
        else:
            conn.execute("""
                INSERT INTO stations (callsign, ssid, first_heard, last_heard,
                    packet_count, last_info)
                VALUES (?, ?, ?, ?, 1, ?)
            """, (callsign, ssid, now, now, data.get("info_ascii", "")[:200]))

    # Track source→dest link
    link = conn.execute("""
        SELECT * FROM node_links
        WHERE source=? AND source_ssid=? AND dest=? AND dest_ssid=?
    """, (data["source"], data["source_ssid"], data["dest"], data["dest_ssid"])).fetchone()
    
    via_str = data.get("digipeaters_str", "")
    if link:
        conn.execute("""
            UPDATE node_links SET last_seen=?, count=count+1, via=?
            WHERE id=?
        """, (now, via_str, link["id"]))
    else:
        conn.execute("""
            INSERT INTO node_links (source, source_ssid, dest, dest_ssid,
                via, link_type, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, 'heard', ?, ?, 1)
        """, (data["source"], data["source_ssid"],
              data["dest"], data["dest_ssid"],
              via_str, now, now))

    conn.commit()
    return packet_id


# ─── AX.25 Frame Parser ──────────────────────────────────────────
def decode_ax25_call(addr_bytes):
    """Decode a 7-byte AX.25 address field into (callsign, ssid)."""
    if len(addr_bytes) != 7:
        return ("???", 0)
    
    callsign = ""
    for b in addr_bytes[:6]:
        c = (b >> 1) & 0x7F
        if c == ord(' '):
            break
        callsign += chr(c)
    
    ssid_byte = addr_bytes[6]
    ssid = (ssid_byte >> 1) & 0x0F
    
    return (callsign.strip(), ssid)


def parse_ax25_frame(frame_data):
    """
    Parse an AX.25 frame (after KISS port byte stripping).
    Returns dict with parsed fields or None on failure.
    """
    if len(frame_data) < 15:
        return None
    
    try:
        offset = 0
        # Destination address (7 bytes)
        dest, dest_ssid = decode_ax25_call(frame_data[offset:offset+7])
        offset += 7
        
        # Source address (7 bytes)
        src, src_ssid = decode_ax25_call(frame_data[offset:offset+7])
        offset += 7
        
        # Digipeaters (0-8 addresses)
        digipeaters = []
        while offset < len(frame_data) and len(digipeaters) < 8:
            if offset + 7 > len(frame_data):
                break
            addr_bytes = frame_data[offset:offset+7]
            
            # Validate candidate address: ALL 6 callsign bytes, when
            # right-shifted (AX.25 encoding), must yield a valid ASCII
            # character (A-Z, 0-9, space, /, -, .).  If any don't, we've
            # hit the control/PID/info area — some radios mis-set the HDLC
            # extension bit on the source SSID byte, causing the parser to
            # read into non-address fields as bogus digipeaters.
            all_valid = True
            for i in range(6):
                c = (addr_bytes[i] >> 1) & 0x7F
                if not (0x20 <= c <= 0x5A or c == 0x2E):
                    all_valid = False
                    break
            if not all_valid:
                break  # Not a valid AX.25 callsign — stop parsing addresses
            
            call, ssid = decode_ax25_call(addr_bytes)
            digipeaters.append((call, ssid))
            offset += 7
            # Note: We do NOT check the HDLC extension bit (bit 7 of the
            # SSID byte) here because Direwolf sends frames where this bit
            # is unreliable.  The all-6-byte check above handles it.
        
        # Control field
        if offset >= len(frame_data):
            return None
        control = frame_data[offset]
        offset += 1
        
        # PID (present for UI frames and I-frames)
        pid = None
        info_start = offset
        
        # UI frames have PID after control
        # I-frames (control & 0x01 == 0) also have PID
        if control == 0x03 or (control & 0x01) == 0:
            if offset < len(frame_data):
                pid = frame_data[offset]
                offset += 1
                info_start = offset
        # SABM, DISC, UA, DM have no PID
        
        # Information field (everything remaining)
        info_bytes = frame_data[info_start:] if info_start < len(frame_data) else b""
        
        # Decode info as ASCII, filtering control chars
        info_ascii = ""
        for b in info_bytes:
            if 32 <= b < 127:
                info_ascii += chr(b)
            elif b in (9, 10, 13):  # tab, LF, CR
                info_ascii += chr(b)
            else:
                info_ascii += "."
        
        control_name = resolve_frame_type(control)
        
        # Determine frame type
        if control == CTRL_UI:
            frame_type = "UI"
        elif control == CTRL_SABM:
            frame_type = "SABM"
        elif control == CTRL_UA:
            frame_type = "UA"
        elif control == CTRL_DISC:
            frame_type = "DISC"
        elif control == CTRL_DM:
            frame_type = "DM"
        elif (control & 0x01) == 0:
            frame_type = "I"
        elif (control & 0x03) == 0x01:
            frame_type = S_FRAME_TYPES[(control >> 2) & 0x03]
        else:
            frame_type = f"0x{control:02X}"
        
        # For I-frames, strip connected-mode layer 3 headers to show the
        # inner payload.  These frames often encapsulate a UI frame with
        # readable text after a binary header + \x03\xf0 (UI+PID) marker.
        if frame_type == "I" and len(info_bytes) > 4:
            inner_marker = info_bytes.find(b'\x03\xf0')
            if inner_marker != -1:
                inner_bytes = info_bytes[inner_marker + 2:]
                info_ascii = ""
                for b in inner_bytes:
                    if 32 <= b < 127:
                        info_ascii += chr(b)
                    elif b in (9, 10, 13):
                        info_ascii += chr(b)
                    else:
                        info_ascii += "."
        
        digi_str = ",".join(f"{c}-{s}" if s else c for c, s in digipeaters) if digipeaters else ""
        
        return {
            "source": src,
            "dest": dest,
            "source_ssid": src_ssid,
            "dest_ssid": dest_ssid,
            "digipeaters": digipeaters,
            "digipeaters_str": digi_str,
            "hop_count": len(digipeaters),
            "control": control,
            "control_name": control_name,
            "frame_type": frame_type,
            "pid": pid,
            "info_hex": info_bytes.hex() if info_bytes else "",
            "info_ascii": info_ascii,
            "info_raw": info_bytes,
            "raw_hex": frame_data.hex(),
        }
    except Exception as e:
        return None


# ─── AGW Frame Helpers ───────────────────────────────────────────
AGW_HEADER_FMT = '<B3xBxBx10s10sII'
AGW_HEADER_SIZE = 36


def _recv_exact(sock, n):
    """Read exactly n bytes from a socket.

    Timeouts are normal (quiet periods on the radio) — retry transparently
    instead of disconnecting. Only returns None on a true TCP disconnect.
    """
    data = b''
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except socket.timeout:
            continue  # quiet period — loop back and wait some more
        if not chunk:
            return None
        data += chunk
    return data


# ─── KISS Capture Thread ──────────────────────────────────────────
class KissCaptureThread(threading.Thread):
    """Background thread that maintains the KISS TNC connection and processes frames."""
    
    def __init__(self, my_call=b'N0CALL'):
        super().__init__(daemon=True)
        self.daemon = True
        self.running = True
        self.my_call = my_call
        self.conn = get_db()
        init_db(self.conn)
        # Migrate: add raw_text column if upgrading from older version
        try:
            self.conn.execute("ALTER TABLE packets ADD COLUMN raw_text TEXT DEFAULT ''")
        except Exception:
            pass  # Column already exists
        # Migrate: add last_path column to map_markers
        try:
            self.conn.execute("ALTER TABLE map_markers ADD COLUMN last_path TEXT DEFAULT ''")
        except Exception:
            pass  # Column already exists
        # Migrate: add static and high_value columns
        try:
            self.conn.execute("ALTER TABLE map_markers ADD COLUMN static INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            self.conn.execute("ALTER TABLE map_markers ADD COLUMN high_value INTEGER DEFAULT 0")
        except Exception:
            pass
        # Migrate: rebuild map_markers with display_name as PRIMARY KEY
        try:
            cursor = self.conn.execute("PRAGMA table_info(map_markers)")
            cols = {row[1]: row[5] for row in cursor.fetchall()}
            if cols.get('display_name') != 1 or cols.get('ssid') == 2:
                self.conn.execute("BEGIN TRANSACTION")
                self.conn.execute('''
                    CREATE TABLE map_markers_new (
                        callsign TEXT NOT NULL,
                        ssid INTEGER DEFAULT 0,
                        display_name TEXT NOT NULL PRIMARY KEY,
                        lat REAL NOT NULL,
                        lon REAL NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        packet_count INTEGER DEFAULT 1,
                        last_path TEXT DEFAULT '',
                        static INTEGER DEFAULT 0,
                        high_value INTEGER DEFAULT 0
                    )
                ''')
                self.conn.execute('''
                    INSERT OR REPLACE INTO map_markers_new
                    SELECT * FROM map_markers
                    ORDER BY last_seen ASC
                ''')
                self.conn.execute("DROP TABLE map_markers")
                self.conn.execute("ALTER TABLE map_markers_new RENAME TO map_markers")
                self.conn.commit()
                print("[MIGRATE] map_markers PK changed to (display_name)", flush=True)
            else:
                print("[MIGRATE] map_markers PK already (display_name), skipping", flush=True)
        except Exception as e:
            self.conn.rollback()
            print(f"[MIGRATE] Error rebuilding map_markers: {e}", flush=True)
        # Migrate: create map_messages table for MAPMSG feature
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS map_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        # Migrate: add pinned column for existing databases
        try:
            self.conn.execute("ALTER TABLE map_messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass  # Column already exists
        self.conn.commit()
        self._recent_packets = []  # For dashboard polling
        self._lock = threading.Lock()
        self._sock = None
        self._stats = {
            "total_packets": 0,
            "unique_stations": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "disconnected",
        }
    
    def run(self):
        while self.running:
            try:
                self._connect_and_capture()
            except Exception as e:
                print(f'[KISS] Connection error: {e}', flush=True)
                with self._lock:
                    self._stats['status'] = f'error: {e}'
                time.sleep(RECONNECT_DELAY)

    def _connect_and_capture(self):
        with self._lock:
            self._stats['status'] = 'connecting...'
        print(f'[KISS] Connecting to {DIGIPI_HOST}:{KISS_PORT}...', flush=True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((DIGIPI_HOST, KISS_PORT))
        self._sock = sock
        print('[KISS] Connected!', flush=True)

        # KISS does not require a handshake
        with self._lock:
            self._stats['status'] = 'connected'

        # KISS frame buffer
        buf = b''

        try:
            while self.running:
                # Read raw bytes from socket
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    print('[KISS] Connection closed by remote', flush=True)
                    break

                buf += chunk

                # Extract complete KISS frames from the buffer
                while True:
                    # Find first FEND (frame start)
                    start = buf.find(b'\xc0')
                    if start == -1:
                        break  # No frame start, wait for more data

                    # Find next FEND (frame end)
                    end = buf.find(b'\xc0', start + 1)
                    if end == -1:
                        break  # Incomplete frame, wait for more

                    # Extract frame content between FEND markers
                    frame_bytes = buf[start + 1:end]
                    buf = buf[end + 1:]  # Keep rest of buffer for next frame

                    if not frame_bytes:
                        continue  # Empty frame

                    # Unescape KISS: FESC+TFEND -> FEND, FESC+TFESC -> FESC
                    frame = frame_bytes.replace(b'\xdb\xdc', b'\xc0').replace(b'\xdb\xdd', b'\xdb')

                    # First byte is the port number
                    if len(frame) < 2:
                        continue
                    port = frame[0]
                    data = frame[1:]

                    # Parse as a raw AX.25 binary frame
                    self._process_ax25_frame(data)

        except Exception as e:
            print(f'[KISS] Read error: {e}', flush=True)
        finally:
            self._sock = None
            sock.close()
            with self._lock:
                self._stats['status'] = 'disconnected'
    
    def _process_ax25_frame(self, frame_data):
        """Process raw binary AX.25 frame data received via KISS.

        frame_data is the raw AX.25 frame bytes (after KISS unescaping
        and port byte removal).
        """
        # Parse as a raw AX.25 binary frame
        parsed = parse_ax25_frame(frame_data)
        if parsed is None:
            return

        # ── NET/ROM Routing Table Decode ─────────────────────────
        # NODES-addressed packets (pid=CF) carry binary routing tables
        # For KISS frames, the info_raw field IS the NET/ROM payload
        if parsed.get('dest') == 'NODES' and parsed.get('frame_type') == 'UI':
            raw_payload = parsed.get('info_raw', b'')
            if raw_payload:
                # Strip trailing frame-terminator bytes
                raw_payload = raw_payload.rstrip(b'\r\x00.')
                if len(raw_payload) >= 16:
                    route_text = decode_netrom_routing(raw_payload)
                    if route_text:
                        parsed['info_ascii'] = f"[NET/ROM Route] {route_text}"
                        parsed['frame_type'] = 'Route'
                        parsed['control_name'] = 'Route'
                        parsed['info_hex'] = raw_payload.hex()
                        print(f"  [NET/ROM] Decoded: {route_text}", flush=True)
                    else:
                        dbg_hex = raw_payload.hex()
                        print(f"  [NET/ROM] DECODE FAILED! Raw ({len(raw_payload)}b): {dbg_hex}", flush=True)
                        parsed['info_ascii'] = f"[NET/ROM] Route ({len(raw_payload)}b)"
                        parsed['frame_type'] = 'Route'
                        parsed['control_name'] = 'Route'
                        parsed['info_hex'] = raw_payload.hex()
                else:
                    # Short NET/ROM payload (< 16 bytes) — extract node name from binary
                    short_payload = raw_payload
                    # Skip leading AGWPE port/framing byte (0xFF)
                    if short_payload and short_payload[0] == 0xFF:
                        short_payload = short_payload[1:]
                    # Try to extract a 6-byte space-padded ASCII node name
                    if len(short_payload) >= 6:
                        node_bytes = short_payload[:6]
                        node_name = node_bytes.rstrip(b' \x00').decode('ascii', errors='replace')
                        # Accept only valid-looking node names (printable, non-empty)
                        if node_name and all(c.isprintable() or c == ' ' for c in node_name):
                            parsed['info_ascii'] = f"[NET/ROM] Node: {node_name.strip()}"
                            parsed['info_hex'] = raw_payload.hex()
                            print(f"  [NET/ROM] Short decode: {node_name.strip()}", flush=True)
                        else:
                            parsed['info_ascii'] = f"[NET/ROM] Route ({len(raw_payload)}b)"
                            parsed['info_hex'] = raw_payload.hex()
                    else:
                        parsed['info_ascii'] = f"[NET/ROM] Route ({len(raw_payload)}b)"
                        parsed['info_hex'] = raw_payload.hex()
                    parsed['frame_type'] = 'Route'
                    parsed['control_name'] = 'Route'

        # Store in DB
        try:
            packet_id = insert_packet(self.conn, parsed)

            src_label = f"{parsed['source']}-{parsed['source_ssid']}" if int(parsed.get('source_ssid', 0)) != 0 else parsed['source']
            dst_label = f"{parsed['dest']}-{parsed['dest_ssid']}" if int(parsed.get('dest_ssid', 0)) != 0 else parsed['dest']

            now = datetime.now(timezone.utc).isoformat()

            # Parse MAP markers from info_ascii
            # Comma format: <MAP:lat,lon,callsign> or <MAP:lat,lon,callsign,nodename>
            # Pipe format:  <MAP:lat,lon|callsign> or <MAP:lat,lon|callsign|nodename>
            info_ascii = parsed.get("info_ascii", "")
            map_match = None

            # 1. Comma format with nodename: <MAP:38.86,-121.09,KK6SEN,AUBNOD>
            if not map_match:
                map_match = re.search(r'<MAP:(-?\d+\.\d+),(-?\d+\.\d+),([^,\r<]+),([^>\r<]+)>', info_ascii)
            # 2. Comma format without nodename: <MAP:38.86,-121.09,KK6SEN>
            if not map_match:
                map_match = re.search(r'<MAP:(-?\d+\.\d+),(-?\d+\.\d+),([^,>]+)>', info_ascii)
            # 3. Pipe format with callsign + nodename: <MAP:38.86,-121.09|KK6SEN|AUBNOD>
            if not map_match:
                map_match = re.search(r'<MAP:(-?\d+\.\d+),(-?\d+\.\d+)\|([^|\r<]+)\|([^|\r<]+)>', info_ascii)
            # 4. Pipe format without nodename: <MAP:38.86,-121.09|KK6SEN>
            if not map_match:
                map_match = re.search(r'<MAP:(-?\d+\.\d+),(-?\d+\.\d+)\|([^|\r<]+)>', info_ascii)

            if map_match:
                lat = float(map_match.group(1))
                lon = float(map_match.group(2))

                if map_match.lastindex == 4:
                    marker_callsign = map_match.group(3).strip().upper()
                    disp_name = map_match.group(4).strip()
                    marker_ssid = 0
                    if '-' in marker_callsign:
                        base, sid = marker_callsign.rsplit('-', 1)
                        try:
                            marker_ssid = int(sid)
                            marker_callsign = base
                        except ValueError:
                            pass
                else:
                    marker_callsign = map_match.group(3).strip().upper()
                    disp_name = marker_callsign
                    marker_ssid = 0
                    if '-' in marker_callsign:
                        base, sid = marker_callsign.rsplit('-', 1)
                        try:
                            marker_ssid = int(sid)
                            marker_callsign = base
                        except ValueError:
                            pass

                try:
                    row = self.conn.execute(
                        "SELECT * FROM map_markers WHERE display_name=?",
                        (disp_name,)
                    ).fetchone()
                    if row:
                        self.conn.execute("""
                            UPDATE map_markers SET callsign=?, ssid=?, last_seen=?, packet_count=packet_count+1,
                                lat=?, lon=?, last_path=?
                            WHERE display_name=?
                        """, (marker_callsign, marker_ssid, now, lat, lon, parsed["digipeaters_str"], disp_name))
                    else:
                        self.conn.execute("""
                            INSERT INTO map_markers (callsign, ssid, display_name, lat, lon,
                                first_seen, last_seen, packet_count, last_path)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                        """, (marker_callsign, marker_ssid,
                              disp_name, lat, lon, now, now, parsed["digipeaters_str"]))
                    self.conn.commit()
                    print(f"  [MAP] {disp_name} ({marker_callsign}) → {lat},{lon}", flush=True)
                except Exception as e:
                    print(f"[MAP] Error: {e}", flush=True)


            # Any packet from or through a known marker updates last_seen (no <MAP:> tag needed)
            try:
                # Check source callsign
                src_call = parsed.get("source", "").strip().upper()
                if src_call:
                    marker_row = self.conn.execute(
                        "SELECT callsign FROM map_markers WHERE callsign=? "
                        "OR display_name=? "
                        "OR display_name LIKE ? "
                        "OR display_name LIKE ? LIMIT 1",
                        (src_call, src_call, f"{src_call}/%", f"%/{src_call}")
                    ).fetchone()
                    if marker_row:
                        self.conn.execute(
                            "UPDATE map_markers SET last_seen=? WHERE callsign=?", 
                            (now, marker_row[0])
                        )

                # Check digipeater hops — process all hops (Kenwood * only marks heard-from hop)
                digi_str = parsed.get("digipeaters_str", "").strip()
                if digi_str:
                    import re as _re
                    hops = _re.split(r'[,\s>]+', digi_str)
                    for hop in hops:
                        hop = hop.replace('*', '').split('-')[0].strip().upper()
                        if hop and hop != src_call:
                            digi_row = self.conn.execute(
                                "SELECT callsign FROM map_markers WHERE callsign=? "
                                "OR display_name=? "
                                "OR display_name LIKE ? "
                                "OR display_name LIKE ? LIMIT 1",
                                (hop, hop, f"{hop}/%", f"%/{hop}")
                            ).fetchone()
                            if digi_row:
                                self.conn.execute(
                                    "UPDATE map_markers SET last_seen=? WHERE callsign=?", 
                                    (now, digi_row[0])
                                )

                if src_call or digi_str:
                    self.conn.commit()
            except Exception as e:
                print(f"[KEEPALIVE] Error updating marker: {e}", flush=True)

            # Parse MAPMSG from info_ascii: <MAPMSG:some message text>
            mapmsg_match = re.search(r'<MAPMSG:([^>]+)>', info_ascii, re.IGNORECASE)
            if mapmsg_match:
                msg_text = mapmsg_match.group(1).strip()
                if msg_text:
                    try:
                        source_call = parsed.get("source", "?")
                        source_ssid = parsed.get("source_ssid", 0)
                        src_label_msg = f"{source_call}-{source_ssid}" if int(source_ssid) != 0 else source_call
                        expires_at = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
                        # Dedup: skip if same source posted same message within last 10 minutes
                        dup_check = self.conn.execute(
                            "SELECT COUNT(*) FROM map_messages WHERE message = ? AND source = ? AND created_at > ?",
                            (msg_text, src_label_msg,
                             (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat())
                        ).fetchone()[0]
                        if dup_check == 0:
                            self.conn.execute(
                                "INSERT INTO map_messages (message, source, created_at, expires_at) VALUES (?, ?, ?, ?)",
                                (msg_text, src_label_msg, now, expires_at)
                            )
                            self.conn.commit()
                            print(f"  [MAPMSG] {src_label_msg}: {msg_text}", flush=True)
                        else:
                            print(f"  [MAPMSG] (dedup) {src_label_msg}: {msg_text}", flush=True)
                    except Exception as e:
                        print(f"[MAPMSG] Error: {e}", flush=True)
            entry = {
                "id": packet_id,
                "time": datetime.now(timezone.utc).astimezone(ZoneInfo("America/Los_Angeles")).strftime("%H:%M:%S"),
                "source": src_label,
                "dest": dst_label,
                "type": parsed["frame_type"],
                "info": parsed["info_ascii"][:120],
                "digipeaters": parsed["digipeaters_str"],
                "raw": parsed["raw_hex"][:80],
            }

            with self._lock:
                self._recent_packets.append(entry)
                self._recent_packets = self._recent_packets[-200:]
                self._stats["total_packets"] += 1
                self._stats["unique_stations"] = self.conn.execute(
                    "SELECT COUNT(*) FROM stations"
                ).fetchone()[0]

            digi_show = parsed["digipeaters_str"][:40] if parsed["digipeaters_str"] else ""
            info_show = parsed["info_ascii"][:50] if parsed["info_ascii"] else ""
            print(f"  [{parsed['frame_type']}] {src_label} → {dst_label}  via={digi_show}  {info_show}", flush=True)

        except Exception as e:
            print(f"[DB] Error inserting packet: {e}", flush=True)

    _KENWOOD_RE = re.compile(
        r'^\s*\d+:Fm\s+(\S+(?:-\d+)?)\s+To\s+(\S+(?:-\d+)?)'
        r'(?:\s+Via\s+([^<\r]+))?'
        r'(?:\s*<[^>]*>)?(?:\s*\[[^\]]*\])?\r?'
    )

    @staticmethod
    def _parse_kenwood_monitor(text):
        """Parse a Kenwood-format monitor line into structured AX.25 fields.

        Input example:
          '1:Fm K6BER-4 To ID Via K6HTD-2,WIDE2-1* <UI pid=F0 Len=33 PF=0 >[20:13:28]\\rK6BER-4/R K6BER/D K6BER/N\\r\\r'

        Returns dict matching insert_packet() expectations, or None.
        """
        m = KissCaptureThread._KENWOOD_RE.match(text)
        if not m:
            # Maybe it's a bare payload line (second line of monitor output)
            text_clean = text.strip('\r\n\x00.')
            if text_clean and any(c.isascii() and c.isprintable() for c in text_clean):
                return {
                    'source': '?', 'source_ssid': 0,
                    'dest': '?', 'dest_ssid': 0,
                    'digipeaters': [], 'digipeaters_str': '',
                    'hop_count': 0, 'control': None,
                    'control_name': 'MON', 'pid': None,
                    'frame_type': 'MON',
                    'info_ascii': text_clean,
                    'info_hex': text_clean.encode('ascii', errors='replace').hex(),
                    'raw_hex': text.encode('ascii', errors='replace').hex(),
                    'raw_text': text,
                }
            return None

        src_call = m.group(1)
        src_ssid = 0
        if '-' in src_call:
            base, sid = src_call.rsplit('-', 1)
            try:
                src_ssid = int(sid)
                src_call = base
            except ValueError:
                pass

        dst_call = m.group(2)
        dst_ssid = 0
        if '-' in dst_call:
            base, sid = dst_call.rsplit('-', 1)
            try:
                dst_ssid = int(sid)
                dst_call = base
            except ValueError:
                pass

        # Parse digipeaters from Via clause
        via_text = (m.group(3) or '').strip()
        digipeaters = []
        if via_text:
            for part in via_text.split(','):
                part = part.strip().rstrip('*')
                if not part:
                    continue
                if '-' in part:
                    call, ssid_str = part.rsplit('-', 1)
                    try:
                        digipeaters.append((call.strip(), int(ssid_str)))
                    except ValueError:
                        digipeaters.append((part, 0))
                else:
                    digipeaters.append((part, 0))

        # Payload is everything after the first \r
        payload = ''
        idx = text.find('\r')
        if idx != -1:
            payload = text[idx+1:].strip().rstrip('\x00').rstrip('.')
        # Also check for payload in the angular-bracket timestamp section
        # e.g. sometimes it's: >[20:13:28]\rMAIL/B...
        if not payload and '>' in text:
            after = text.split('>', 1)[-1].strip().rstrip('\x00').rstrip('.')
            # Only use if it's actual content, not just a timestamp [HH:MM:SS]
            if after and not re.fullmatch(r'\[\d{2}:\d{2}:\d{2}\]', after):
                payload = after

        # Extract frame type from Kenwood <TYPE ...> section (e.g. <UI pid=F0...>, <SABM PF=1>)
        ft_match = re.search(r'<(\w+)', text)
        frame_type_val = ft_match.group(1) if ft_match else 'MON'

        digi_str = ', '.join(f'{c}-{s}' if s else c for c, s in digipeaters) if digipeaters else ''

        raw_hex = text.encode('ascii', errors='replace').hex()

        return {
            'source': src_call, 'source_ssid': src_ssid,
            'dest': dst_call, 'dest_ssid': dst_ssid,
            'digipeaters': digipeaters, 'digipeaters_str': digi_str,
            'hop_count': len(digipeaters), 'control': None,
            'control_name': frame_type_val, 'pid': None,
            'frame_type': frame_type_val,
            'info_ascii': payload,
            'info_hex': payload.encode('ascii', errors='replace').hex() if payload else '',
            'raw_hex': raw_hex,
            'raw_text': text,
        }
    
    def get_recent_packets(self, limit=50):
        with self._lock:
            return list(self._recent_packets[-limit:])
    
    def get_stats(self):
        with self._lock:
            return dict(self._stats)
    
    def stop(self):
        self.running = False


# ─── Web Dashboard Server ─────────────────────────────────────────
class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that serves the dashboard and API."""
    
    capture = None  # Set by the server
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        
        if path == "/api/packets":
            limit = int(params.get("limit", [50])[0])
            conn = get_db()
            rows = conn.execute(
                "SELECT id, timestamp, source, source_ssid, dest, dest_ssid, "
                "control_name, digipeaters, info_ascii, raw_hex, raw_text "
                "FROM packets ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            conn.close()
            packets = [
                {
                    "id": r["id"],
                    "time": _fmt_time(r["timestamp"]),
                    "timestamp": r["timestamp"],
                    "source": f"{r['source']}{'-' + str(r['source_ssid']) if r['source_ssid'] else ''}",
                    "dest": f"{r['dest']}{'-' + str(r['dest_ssid']) if r['dest_ssid'] else ''}",
                    "type": r["control_name"],
                    "info": (r["info_ascii"] or "")[:120],
                    "digipeaters": (r["digipeaters"] or ""),
                    "raw": (r["raw_hex"] or "")[:80],
                    "raw_text": r["raw_text"] or "",
                }
                for r in rows
            ]
            self._send_json(packets)
        elif path == "/api/stats":
            stats = self.capture.get_stats()
            
            # Add some DB queries
            conn = get_db()
            
            stats["stations"] = [
                dict(r) for r in conn.execute(
                    "SELECT callsign, ssid, first_heard, last_heard, packet_count, last_info "
                    "FROM stations ORDER BY last_heard DESC LIMIT 100"
                ).fetchall()
            ]
            
            stats["frame_type_counts"] = [
                {"type": r["type"], "count": r["count"]}
                for r in conn.execute(
                    "SELECT control_name AS type, COUNT(*) AS count "
                    "FROM packets GROUP BY control_name ORDER BY count DESC"
                ).fetchall()
            ]

            stats["top_links"] = [
                dict(r) for r in conn.execute(
                    "SELECT source, source_ssid, dest, dest_ssid, via, "
                    "first_seen, last_seen, count FROM node_links "
                    "ORDER BY count DESC LIMIT 20"
                ).fetchall()
            ]
            
            conn.close()
            self._send_json(stats)
        elif path == "/api/stations":
            conn = get_db()
            stations = [
                dict(r) for r in conn.execute(
                    "SELECT callsign, ssid, first_heard, last_heard, packet_count, "
                    "last_info FROM stations ORDER BY last_heard DESC LIMIT 200"
                ).fetchall()
            ]
            conn.close()
            self._send_json(stations)
        elif path == "/api/links":
            conn = get_db()
            links = [
                dict(r) for r in conn.execute(
                    "SELECT source, source_ssid, dest, dest_ssid, via, "
                    "first_seen, last_seen, count FROM node_links "
                    "ORDER BY last_seen DESC LIMIT 100"
                ).fetchall()
            ]
            conn.close()
            self._send_json(links)
        elif path == "/api/markers":
            conn = get_db()
            # Clean up markers not seen in 1 year (skip static=1)
            conn.execute(
                "DELETE FROM map_markers WHERE last_seen < datetime('now', '-1 year') AND static = 0"
            )
            markers = [
                dict(r) for r in conn.execute(
                    "SELECT callsign, ssid, display_name, lat, lon, "
                    "first_seen, last_seen, packet_count, last_path, "
                    "static, high_value FROM map_markers "
                    "ORDER BY last_seen DESC"
                ).fetchall()
            ]
            conn.close()
            self._send_json(markers)
        elif path == "/api/mapmsg":
            conn = get_db()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
            msgs = [
                dict(r) for r in conn.execute(
                    "SELECT id, message, source, created_at, pinned FROM map_messages "
                    "WHERE created_at >= ? OR pinned = 1 "
                    "ORDER BY created_at DESC LIMIT 100",
                    (cutoff,)
                ).fetchall()
            ]
            conn.close()
            self._send_json(msgs)
        elif path == "/api/mapmsg/all":
            conn = get_db()
            msgs = [
                dict(r) for r in conn.execute(
                    "SELECT id, message, source, created_at, pinned FROM map_messages "
                    "ORDER BY created_at DESC LIMIT 100"
                ).fetchall()
            ]
            conn.close()
            self._send_json(msgs)
        elif path == "/" or path == "":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/markers":
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self._send_error(400, "No body")
                return
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")
                return

            display_name = data.get("display_name")
            if not display_name:
                self._send_error(400, "Missing display_name")
                return

            conn = get_db()
            existing = conn.execute(
                "SELECT display_name FROM map_markers WHERE display_name=?", (display_name,)
            ).fetchone()

            if not existing:
                conn.close()
                self._send_error(404, f"Marker '{display_name}' not found")
                return

            updates = []
            params = []
            for col in ("static", "high_value"):
                if col in data:
                    updates.append(f"{col}=?")
                    params.append(1 if data[col] else 0)
            if updates:
                params.append(display_name)
                conn.execute(
                    f"UPDATE map_markers SET {', '.join(updates)} WHERE display_name=?",
                    params
                )
                conn.commit()
            conn.close()
            self._send_json({"status": "ok", "display_name": display_name})
        elif path == "/api/mapmsg/pin":
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self._send_error(400, "No body")
                return
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")
                return
            msg_id = data.get("id")
            if msg_id is None:
                self._send_error(400, "Missing id")
                return
            pinned = 1 if data.get("pinned", True) else 0
            conn = get_db()
            conn.execute("UPDATE map_messages SET pinned=? WHERE id=?", (pinned, msg_id))
            conn.commit()
            conn.close()
            self._send_json({"status": "ok", "id": msg_id, "pinned": bool(pinned)})
        else:
            self._send_error(404, "Not found")

    def _send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _send_error(self, status, message):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def log_message(self, format, *args):
        """Quiet the server logs."""
        pass


def run_web_server(capture):
    DashboardHandler.capture = capture
    server = http.server.HTTPServer((WEB_HOST, WEB_PORT), DashboardHandler)
    print(f"[WEB] Dashboard at http://{WEB_HOST}:{WEB_PORT}", flush=True)
    server.serve_forever()


# ─── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    def banner_line(s):
        return "║  " + s.ljust(42) + "  ║"
    print("╔══════════════════════════════════════════════╗")
    print(banner_line("Packet Radio KISS Capture + Dashboard"))
    print(banner_line(f"Target:  {DIGIPI_HOST}:{KISS_PORT}"))
    print(banner_line(f"Dashboard: http://{WEB_HOST}:{WEB_PORT}"))
    print("╚══════════════════════════════════════════════╝")
    print()
    
    capture = KissCaptureThread(my_call=b'N0CALL')
    capture.start()
    
    # Give capture a moment to connect
    time.sleep(1)
    
    try:
        run_web_server(capture)
    except KeyboardInterrupt:
        print("\nShutting down...")
        capture.stop()
        sys.exit(0)
