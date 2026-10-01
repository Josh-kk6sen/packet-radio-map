#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KK6SEN (Josh)
# Start/stop the packet radio monitor
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$PROJECT_DIR/daemon/kiss_capture.py"
PIDFILE="$PROJECT_DIR/kiss_capture.pid"
LOGFILE="$PROJECT_DIR/kiss_capture.log"

mkdir -p "$PROJECT_DIR/db"

case "${1:-start}" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "Already running (PID $(cat "$PIDFILE"))"
      exit 1
    fi
    echo "Starting packet radio monitor..."
    nohup python3 "$DAEMON" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "Started (PID $(cat "$PIDFILE")). Dashboard at http://localhost:8080"
    sleep 2
    tail -5 "$LOGFILE"
    ;;
  stop)
    if [ ! -f "$PIDFILE" ]; then
      echo "Not running"
      exit 0
    fi
    echo "Stopping..."
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "Stopped"
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "Running (PID $(cat "$PIDFILE"))"
      tail -3 "$LOGFILE"
    else
      echo "Not running"
      [ -f "$PIDFILE" ] && echo "(stale PID file)"
    fi
    ;;
  logs)
    tail -f "$LOGFILE"
    ;;
  *)
    echo "Usage: $0 {start|stop|status|logs}"
    exit 1
    ;;
esac
