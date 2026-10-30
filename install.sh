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
  droid)    DEST="${DROID_HOOKS_DIR:-$HOME/.config/droid/hooks}" ;;
  devin)    DEST="${DEVIN_HOOKS_DIR:-$HOME/.config/devin/hooks}" ;;
  claude)   DEST="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}" ;;
  opencode) DEST="${OPENCODE_HOOKS_DIR:-$HOME/.config/opencode/plugin}" ;;
  grok)     DEST="${GROK_HOOKS_DIR:-$HOME/.grok/hooks}" ;;
  cursor)   DEST="${CURSOR_HOOKS_DIR:-$HOME/.cursor/hooks}"; CURSOR_CFG="${CURSOR_CFG:-$HOME/.cursor/hooks.json}" ;;
  codex)    DEST="${CODEX_HOOKS_DIR:-$HOME/.codex/hooks}"; CODEX_CFG="${CODEX_CFG:-$HOME/.codex/hooks.json}" ;;
  omp)      DEST="${OMP_HOOKS_DIR:-$HOME/.omp/agent/hooks}" ;;
  /*|./*)   DEST="$TARGET" ;;
  *)        echo "unknown target: $TARGET (use droid|devin|claude|opencode|grok|cursor|codex|omp|/path)" >&2; exit 2 ;;
esac

mkdir -p "$DEST/scripts" "$DEST/tests"
for f in "$PLUGIN_DIR"/scripts/*; do
  [ -f "$f" ] && cp -p "$f" "$DEST/scripts/"
done
cp -p "$PLUGIN_DIR"/tests/test_secret_guard.py "$DEST"/tests/
chmod +x "$DEST"/scripts/secret_guard.py "$DEST"/scripts/secret-fetch "$DEST"/scripts/redacted-cat "$DEST"/scripts/sync_gitleaks.py "$DEST"/scripts/cursor_adapter.py 2>/dev/null || true
HOOK_PY="$DEST/scripts/secret_guard.py"

# Shared by the config merges below: refuse to touch a file that does not
# parse, and replace it atomically, keeping the original as <file>.bak.
IFS= read -r -d '' PY_IO <<'PY' || true
import json, os, shutil, sys
def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        raw = f.read()
    if not raw.strip():
        return default
    try:
        return json.loads(raw)
    except ValueError as e:
        sys.exit(f"cannot parse {path} ({e}); add the snippet manually")
def save(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
PY
CLAUDE_POST_MATCHER='Bash|Read|Grep|WebFetch|WebSearch|Task|Agent|mcp__.*'

case "$TARGET" in
  claude)
    SETTINGS="$HOME/.claude/settings.json"
    ENTRY="\"python3 $DEST/scripts/secret_guard.py\""
    if grep -q "secret_guard.py" "$SETTINGS" 2>/dev/null; then
      echo "claude settings.json already wires secret_guard.py"
    else
      echo "---"
      echo "claude: add this to $SETTINGS under \"hooks\" (or re-run to auto-merge)"
      cat <<SNIP
{
  "hooks": {
    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "python3 $DEST/scripts/secret_guard.py", "timeout": 10, "onFailure": "block"}]}],
    "PostToolUse": [{"matcher": "$CLAUDE_POST_MATCHER", "hooks": [{"type": "command", "command": "python3 $DEST/scripts/secret_guard.py", "timeout": 10}]}]
  }
}
SNIP
      echo "---"
      echo "auto-merge? [y/N] "
      read -r ans
      if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        python3 - <<PYEOF "$SETTINGS" "$DEST" "$CLAUDE_POST_MATCHER"
$PY_IO
path, dest, post_matcher = sys.argv[1], sys.argv[2], sys.argv[3]
data = load(path, {})
data.setdefault("hooks", {})
cmd = f"python3 {dest}/scripts/secret_guard.py"
wiring = {
    "PreToolUse": ("*", {"type": "command", "command": cmd, "timeout": 10, "onFailure": "block"}),
    "PostToolUse": (post_matcher, {"type": "command", "command": cmd, "timeout": 10}),
}
for ev, (matcher, hook) in wiring.items():
    arr = data["hooks"].setdefault(ev, [])
    grp = next((g for g in arr if g.get("matcher") == matcher), None)
    if grp is None:
        grp = {"matcher": matcher, "hooks": []}
        arr.append(grp)
    if hook not in grp["hooks"]:
        grp["hooks"].append(hook)
save(path, data)
print(f"merged into {path}")
PYEOF
      fi
    fi
    ;;
  opencode)
    SNIP_TGT="$DEST/secret-guard.ts"
    cp "$PLUGIN_DIR/extensions/ai.opencode/plugin/secret-guard.ts" "$SNIP_TGT"
    OC_CONFIG="$HOME/.config/opencode/opencode.json"
    if grep -q "secret-guard.ts" "$OC_CONFIG" 2>/dev/null; then
      echo "opencode.json already wires secret-guard.ts"
    else
      echo "opencode: ensure $OC_CONFIG has \"plugin\": [\"$SNIP_TGT\"]"
      echo "auto-merge? [y/N] "
      read -r ans
      if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        python3 - <<PYEOF "$OC_CONFIG" "$SNIP_TGT"
$PY_IO
path, tgt = sys.argv[1], sys.argv[2]
data = load(path, {})
data.setdefault("plugin", [])
if tgt not in data["plugin"]:
    data["plugin"].append(tgt)
save(path, data)
print(f"merged into {path}")
PYEOF
      fi
    fi
    ;;
  grok)
    ;;
  cursor)
    # Cursor hooks.json merges — existing entries are kept; we append ours.
    CURSOR_HOOKS="${CURSOR_CFG:-$HOME/.cursor/hooks.json}"
    if [ -f "$CURSOR_HOOKS" ] && grep -q "secret_guard\|cursor_adapter" "$CURSOR_HOOKS" 2>/dev/null; then
      echo "cursor hooks.json already wires secret-guard"
    else
      python3 - <<PYEOF "$CURSOR_HOOKS" "$DEST/scripts/cursor_adapter.py"
$PY_IO
path, adapter = sys.argv[1], sys.argv[2]
data = load(path, {"version": 1, "hooks": {}})
data.setdefault("version", 1)
data.setdefault("hooks", {})
cmd = f"python3 {adapter}"
data["hooks"].setdefault("preToolUse", []).append({"command": cmd, "matcher": ".*", "timeout": 10, "failClosed": True})
data["hooks"].setdefault("postToolUse", []).append({"command": cmd, "matcher": ".*", "timeout": 10})
for ev in ("beforeShellExecution", "beforeReadFile", "beforeMCPExecution"):
    data["hooks"].setdefault(ev, []).append({"command": cmd, "timeout": 10, "failClosed": True})
save(path, data)
print(f"merged secret-guard into {path}")
PYEOF
    fi
    ;;
  codex)
    # Codex reads ~/.codex/hooks.json OR ~/.codex/config.toml [hooks] tables.
    # Write ~/.codex/hooks.json directly; Codex merges with any other sources.
    CODEX_HOOKS="${CODEX_CFG:-$HOME/.codex/hooks.json}"
    if [ -f "$CODEX_HOOKS" ] && grep -q "secret_guard" "$CODEX_HOOKS" 2>/dev/null; then
      echo "codex hooks.json already wires secret-guard"
    else
      python3 - <<PYEOF "$CODEX_HOOKS" "$DEST/scripts/secret_guard.py"
$PY_IO
path, script = sys.argv[1], sys.argv[2]
data = load(path, {"hooks": {}})
data.setdefault("hooks", {})
cmd = f"python3 {script}"
entry = {
  "matcher": "Bash|apply_patch|Edit|Write|MultiEdit|Read|mcp__.*",
  "hooks": [{"type": "command", "command": cmd, "timeout": 10}]
}
for ev in ("PreToolUse", "PostToolUse"):
    data["hooks"].setdefault(ev, []).append(entry)
save(path, data)
print(f"merged secret-guard into {path}")
print("codex: hooks need one-time trust review — run codex and accept the prompt, or use --dangerously-bypass-hook-trust.")
PYEOF
    fi
    ;;
  omp)
    # omp discovers hook factories only in hooks/pre|post/*.ts; the Python
    # core stays in hooks/scripts/ (discovery is non-recursive, so it is
    # never picked up as a hook). The adapter resolves it via ../scripts/.
    mkdir -p "$DEST/pre"
    cp -p "$PLUGIN_DIR/extensions/dev.omp/secret-guard.ts" "$DEST/pre/secret-guard.ts"
    echo "omp: installed $DEST/pre/secret-guard.ts (core in $DEST/scripts/)"
    echo "omp: disable with OMP_SECRET_GUARD=off"
    ;;
  droid|devin|/*|./*)
    ;;
esac

if [ "$TARGET" = "grok" ]; then
  GL_HOOKS="$DEST/secret-guard.json"
  if [ ! -f "$GL_HOOKS" ]; then
    cat > "$GL_HOOKS" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|run_terminal_command|Shell|Read|Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 $DEST/scripts/secret_guard.py",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|run_terminal_command|Shell",
        "hooks": [
          {
            "type": "command",
            "command": "python3 $DEST/scripts/secret_guard.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
EOF
    echo "wrote $GL_HOOKS"
  else
    echo "kept existing $GL_HOOKS"
  fi
elif [ "$TARGET" = "devin" ]; then
  # Devin user-level: ~/.config/devin/config.json under "hooks" key.
  # Per-project: .devin/hooks.v1.json (same shape but entire-file).
  DEVIN_CFG="${DEVIN_CFG:-$HOME/.config/devin/config.json}"
  if [ -f "$DEVIN_CFG" ] && grep -q "secret_guard" "$DEVIN_CFG" 2>/dev/null; then
    echo "devin config.json already wires secret-guard"
  else
    python3 - <<PYEOF "$DEVIN_CFG" "$DEST/scripts/secret_guard.py"
$PY_IO
path, script = sys.argv[1], sys.argv[2]
data = load(path, {})
data.setdefault("hooks", {})
entry = {
    "matcher": "exec|edit",
    "hooks": [{"type": "command", "command": f"python3 {script}", "timeout": 10}]
}
for ev in ("PreToolUse", "PostToolUse"):
    data["hooks"].setdefault(ev, [])
    if not any(e.get("matcher") == "exec|edit" for e in data["hooks"][ev]):
        data["hooks"][ev].append(entry)
save(path, data)
print(f"merged secret-guard into {path}")
PYEOF
  fi
elif [ "$TARGET" = "droid" ]; then
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
          "command": "python3 $DEST/scripts/secret_guard.py",
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
          "command": "python3 $DEST/scripts/secret_guard.py",
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
fi

case "$TARGET" in
  /*|./*) echo "custom dir: wire python3 $DEST/scripts/secret_guard.py into your agent's PreToolUse/PostToolUse hooks" ;;
esac

echo "installed secret-guard → $DEST"
echo "verify:  python3 $DEST/tests/test_secret_guard.py"
