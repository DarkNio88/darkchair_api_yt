#!/usr/bin/env bash
set -euo pipefail

# Install Node deps and download yt-dlp binary for linux
# Usage: bash scripts/install-deps.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Installing in: $ROOT_DIR"

cd "$ROOT_DIR"

echo "Running npm install..."
npm install --no-audit --no-fund

YTDLP_URL="https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp"
YTDLP_DEST="$ROOT_DIR/yt-dlp"

echo "Downloading yt-dlp to $YTDLP_DEST"
if command -v curl >/dev/null 2>&1; then
  curl -L -o "$YTDLP_DEST.tmp" "$YTDLP_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$YTDLP_DEST.tmp" "$YTDLP_URL"
else
  echo "Error: curl or wget required to download yt-dlp" >&2
  exit 2
fi

chmod +x "$YTDLP_DEST.tmp"
mv -f "$YTDLP_DEST.tmp" "$YTDLP_DEST"

echo "yt-dlp downloaded to $YTDLP_DEST"

# Try to install into /usr/local/bin if writable or sudo available
if [ -w "/usr/local/bin" ]; then
  echo "Copying yt-dlp to /usr/local/bin/yt-dlp"
  cp -f "$YTDLP_DEST" /usr/local/bin/yt-dlp
  chmod +x /usr/local/bin/yt-dlp || true
  echo "Installed /usr/local/bin/yt-dlp"
else
  if command -v sudo >/dev/null 2>&1; then
    echo "/usr/local/bin not writable; attempting sudo install"
    sudo cp -f "$YTDLP_DEST" /usr/local/bin/yt-dlp
    sudo chmod +x /usr/local/bin/yt-dlp || true
    echo "Installed /usr/local/bin/yt-dlp (sudo)"
  else
    echo "/usr/local/bin not writable and sudo not available. Leaving yt-dlp in project root: $YTDLP_DEST"
    echo "The module prepends project root to PATH, so spawn('yt-dlp') should find it when running index.js from project root."
  fi
fi

echo "Done. To test: node index.js OR npm run auth"

# Ensure xvfb-run is available (used when running headful browsers in a virtual framebuffer)
if command -v xvfb-run >/dev/null 2>&1; then
  echo "xvfb-run is already installed"
else
  echo "xvfb-run not found — attempting to install system package"
  if command -v apt-get >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
      apt-get update && apt-get install -y xvfb || echo "apt-get install failed"
    else
      if command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y xvfb || echo "sudo apt-get install failed"
      else
        echo "Cannot install xvfb: sudo not available. Please install package 'xvfb' manually."
      fi
    fi
  elif command -v dnf >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
      dnf install -y xorg-x11-server-Xvfb || echo "dnf install failed"
    else
      if command -v sudo >/dev/null 2>&1; then
        sudo dnf install -y xorg-x11-server-Xvfb || echo "sudo dnf install failed"
      else
        echo "Cannot install Xvfb: sudo not available. Please install 'xorg-x11-server-Xvfb' manually."
      fi
    fi
  elif command -v yum >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
      yum install -y xorg-x11-server-Xvfb || echo "yum install failed"
    else
      if command -v sudo >/dev/null 2>&1; then
        sudo yum install -y xorg-x11-server-Xvfb || echo "sudo yum install failed"
      else
        echo "Cannot install Xvfb: sudo not available. Please install 'xorg-x11-server-Xvfb' manually."
      fi
    fi
  else
    echo "No supported package manager found (apt-get/dnf/yum). Please install Xvfb/xvfb-run manually."
  fi

  if command -v xvfb-run >/dev/null 2>&1; then
    echo "xvfb-run installed successfully"
  else
    echo "xvfb-run still not available — you may need to install it manually depending on your OS."
  fi
fi
