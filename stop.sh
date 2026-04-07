#!/usr/bin/env bash
# TruConfirm QRDI — Shutdown Script (Mac / Linux)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "==============================================="
echo " TruConfirm QRDI — Stopping Services"
echo "==============================================="
echo ""

# ── Stop backend ────────────────────────────────
echo "[1/2] Stopping backend (port 3001)..."
if [ -f "$SCRIPT_DIR/.backend.pid" ]; then
  kill "$(cat "$SCRIPT_DIR/.backend.pid")" 2>/dev/null && echo "[OK] Backend stopped (PID file)"
  rm -f "$SCRIPT_DIR/.backend.pid"
else
  # Fallback: kill by port
  PID=$(lsof -ti tcp:3001 2>/dev/null)
  if [ -n "$PID" ]; then kill $PID && echo "[OK] Backend stopped (port 3001)"; fi
fi

# ── Stop frontend ───────────────────────────────
echo "[2/2] Stopping frontend (port 3000)..."
if [ -f "$SCRIPT_DIR/.frontend.pid" ]; then
  kill "$(cat "$SCRIPT_DIR/.frontend.pid")" 2>/dev/null && echo "[OK] Frontend stopped (PID file)"
  rm -f "$SCRIPT_DIR/.frontend.pid"
else
  PID=$(lsof -ti tcp:3000 2>/dev/null)
  if [ -n "$PID" ]; then kill $PID && echo "[OK] Frontend stopped (port 3000)"; fi
fi

echo ""
echo "==============================================="
echo " All services stopped."
echo "==============================================="
echo ""
