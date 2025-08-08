#!/usr/bin/env bash
set -euo pipefail

# Build NetGuardian macOS .app and place it on Desktop
# Usage: ./build_macos_app.sh

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$HOME/Desktop"

# Ensure we run all subsequent commands from project root
cd "$PROJECT_ROOT"

# Ensure Python 3
PY=python3

# Ensure venv to isolate build
VENV_DIR="$PROJECT_ROOT/.venv-build"
if [ ! -d "$VENV_DIR" ]; then
  $PY -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

pip install --upgrade pip wheel setuptools
# Pin PyInstaller to a stable version compatible with PyQt6
pip install "pyinstaller>=6.3" -r "$PROJECT_ROOT/requirements.txt"

# Clean previous build artifacts to avoid symlink conflicts
rm -rf "$PROJECT_ROOT/build" "$PROJECT_ROOT/dist"

# Build with spec (run from project root so pathex='.' resolves correctly)
pyinstaller --clean --noconfirm "$PROJECT_ROOT/netguardian_gui.spec"

# Copy .app to Desktop
APP_PATH="$PROJECT_ROOT/dist/NetGuardian.app"
if [ -d "$APP_PATH" ]; then
  rm -rf "$DESKTOP_DIR/NetGuardian.app" || true
  cp -R "$APP_PATH" "$DESKTOP_DIR/"
  echo "Built app copied to $DESKTOP_DIR/NetGuardian.app"
else
  echo "Build failed: $APP_PATH not found" >&2
  exit 1
fi

echo "Done. You can double-click NetGuardian.app on your Desktop."

