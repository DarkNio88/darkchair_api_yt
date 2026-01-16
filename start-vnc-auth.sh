#!/usr/bin/env bash
set -euo pipefail

# Helper to start Xvfb + window manager + x11vnc then run the auth server
# Usage: ./start-vnc-auth.sh [port]

PORT=${1:-3001}
DISPLAY_NUM=${DISPLAY_NUM:-99}
SCREEN_RES=${SCREEN_RES:-1280x720x24}

echo "Starting virtual display :${DISPLAY_NUM} (${SCREEN_RES}) and VNC on :5901..."

if ! command -v Xvfb >/dev/null 2>&1; then
  echo "Xvfb not found. Install with: sudo apt-get install -y xvfb" >&2
  exit 1
fi
if ! command -v x11vnc >/dev/null 2>&1; then
  echo "x11vnc not found. Install with: sudo apt-get install -y x11vnc" >&2
  exit 1
fi

mkdir -p /tmp/darkchair_vnc

# start Xvfb
Xvfb :${DISPLAY_NUM} -screen 0 ${SCREEN_RES} &
XVFB_PID=$!
echo "Xvfb pid=${XVFB_PID}"

export DISPLAY=:${DISPLAY_NUM}

# start a lightweight window manager if available
if command -v fluxbox >/dev/null 2>&1; then
  fluxbox &
  WM_PID=$!
  echo "fluxbox pid=${WM_PID}"
else
  echo "fluxbox not found; continuing without a window manager"
  WM_PID=0
fi

# x11vnc: use ~/.vnc/passwd if present, otherwise run without auth
if [ -f "$HOME/.vnc/passwd" ]; then
  x11vnc -display ${DISPLAY} -rfbport 5901 -forever -shared -rfbauth $HOME/.vnc/passwd &
else
  x11vnc -display ${DISPLAY} -rfbport 5901 -forever -shared &
fi
X11VNC_PID=$!
echo "x11vnc pid=${X11VNC_PID}"

cleanup() {
  echo "Shutting down..."
  kill ${X11VNC_PID} 2>/dev/null || true
  if [ "$WM_PID" -ne 0 ]; then kill ${WM_PID} 2>/dev/null || true; fi
  kill ${XVFB_PID} 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM EXIT

echo "Running auth-server (port=${PORT})"
AUTH_PORT=${PORT} AUTH_HEADLESS=0 node index.js
