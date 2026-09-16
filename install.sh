#!/usr/bin/env bash
# Install secret-guard into a Droid or Devin config dir.
#
# Usage:
#   ./install.sh              # install to ~/.config/droid/hooks
#   ./install.sh devin        # install to ~/.config/devin/hooks
#   ./install.sh /abs/path    # install to a custom dir
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-droid}"

case "$TARGET" in
  droid)  DEST="${DROID_HOOKS_DIR:-$HOME/.config/droid/hooks}" ;;
  devin)  DEST="${DEVIN_HOOKS_DIR:-$HOME/.config/devin/hooks}" ;;
  /*|./*) DEST="$TARGET" ;;
  *)      echo "unknown target: $TARGET (use droid|devin|/path)" >&2; exit 2 ;;
esac

mkdir -p "$DEST"
mkdir -p "$DEST/tests"
cp -p "$PLUGIN_DIR"/scripts/* "$DEST"/
cp -p "$PLUGIN_DIR"/tests/test_secret_guard.py "$DEST"/tests/
chmod +x "$DEST"/secret_guard.py "$DEST"/secret-fetch "$DEST"/redacted-cat "$DEST"/sync_gitleaks.py

HOOKS_JSON="$(dirname "$DEST")/hooks.json"
if [ ! -f "$HOOKS_JSON" ]; then
  cat > "$HOOKS_JSON" <<EOF
{
  "PreToolUse": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "python3 $DEST/secret_guard.py",
          "timeout": 10
        }
      ]
    }
  ],
  "PostToolUse": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "python3 $DEST/secret_guard.py",
          "timeout": 10
        }
      ]
    }
  ]
}
EOF
  echo "wrote $HOOKS_JSON"
else
  echo "kept existing $HOOKS_JSON (edit manually if hooks aren't wired)"
fi

echo "installed secret-guard → $DEST"
echo "verify:  python3 $DEST/tests/test_secret_guard.py"
