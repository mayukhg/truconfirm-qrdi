#!/usr/bin/env bash
# TruConfirm QRDI — Startup Script (Mac / Linux)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "==============================================="
echo " TruConfirm QRDI — Starting Services"
echo "==============================================="
echo ""

# ── Check dependencies ──────────────────────────
if ! command -v node &>/dev/null; then
  echo "[ERROR] Node.js not found. Install from https://nodejs.org"; exit 1
fi
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "[ERROR] Python not found. Install from https://python.org"; exit 1
fi

PYTHON=$(command -v python3 || command -v python)

# ── Install backend deps if needed ─────────────
if [ ! -d "$SCRIPT_DIR/backend/node_modules" ]; then
  echo "[INFO] Installing backend dependencies..."
  cd "$SCRIPT_DIR/backend" && npm install --silent
  echo "[OK] Dependencies installed"
fi

# ── Start backend ───────────────────────────────
echo "[1/2] Starting backend on port 3001..."
cd "$SCRIPT_DIR/backend"
node server.js &
BACKEND_PID=$!
echo $BACKEND_PID > "$SCRIPT_DIR/.backend.pid"
sleep 1

# ── Start frontend ──────────────────────────────
echo "[2/2] Starting frontend on port 3000..."
cd "$SCRIPT_DIR"
$PYTHON -m http.server 3000 &
FRONTEND_PID=$!
echo $FRONTEND_PID > "$SCRIPT_DIR/.frontend.pid"
sleep 1

echo ""
echo "==============================================="
echo " Both servers are running!"
echo ""
echo "  App  →  http://localhost:3000"
echo "  API  →  http://localhost:3001/api"
echo ""
echo "  Run ./stop.sh to stop both servers."
echo "==============================================="
echo ""

# Open browser
if command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:3000" &>/dev/null &
elif command -v open &>/dev/null; then
  open "http://localhost:3000" &>/dev/null &
fi

# Wait so Ctrl+C stops both servers
wait $BACKEND_PID $FRONTEND_PID
