#!/usr/bin/env python3
"""Translate Cursor's hook event shape → Droid shape so secret_guard.py
doesn't need to know anything about Cursor.

Cursor sends on stdin:
  { conversation_id, hook_event_name: 'preToolUse', tool_name, tool_input,
    cursor_version, workspace_roots, ... }
Cursor expects on stdout:
  { permission: 'allow' | 'deny' }   (beforeShellExecution, beforeReadFile, etc.)
  { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny' } }
"""
import os, sys, json, subprocess

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_guard.py")

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

ev_raw = (data.get("hook_event_name") or "").lower()

# Map cursor lowerCamel event → canonical event name.
EV = {
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "beforeshellexecution": "PreToolUse",   # treat shell pre-hooks as PreToolUse
    "aftershellexecution": "PostToolUse",
    "beforereadfile": "PreToolUse",
    "afterfileedit": "PostToolUse",
    "beforemcpexecution": "PreToolUse",
    "aftermcpexecution": "PostToolUse",
    "beforetabfileread": "PreToolUse",
    "aftertabfiledit": "PostToolUse",
}.get(ev_raw, None)
if not EV:
    sys.exit(0)

# Build a tool-shaped payload. Cursor's beforeShellExecution uses
# { command } and beforeReadFile uses { file_path } + { content }.
tool_name = data.get("tool_name") or ""
tool_input = data.get("tool_input") or {}

# Cursor's hook-specific fields live at top level, not under tool_input:
#   beforeShellExecution  → { command: str, ... }
#   beforeReadFile        → { file_path, content }
#   afterFileEdit         → { file_path, edits: [{new_string, ...}] }
if ev_raw == "beforeshellexecution":
    tool_name = tool_name or "Shell"
    cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not cmd:
        cmd = data.get("command") or data.get("input") or ""
    if isinstance(cmd, str):
        tool_input = {"command": cmd}
elif ev_raw == "beforereadfile":
    tool_name = tool_name or "Read"
    fp = (tool_input.get("file_path") if isinstance(tool_input, dict) else None) or data.get("file_path")
    if fp:
        tool_input = {"file_path": fp}
elif ev_raw == "afterfileedit":
    tool_name = tool_name or "Write"
    fp = (tool_input.get("file_path") if isinstance(tool_input, dict) else None) or data.get("file_path")
    edits = data.get("edits") or []
    content = "\n".join(e.get("new_string") or "" for e in edits if isinstance(e, dict))
    tool_input = {"file_path": fp or "", "content": content}
elif ev_raw in ("beforemcpexecution", "aftermcpexecution"):
    tool_name = tool_name or "MCP:unknown"

payload = {
    "hook_event_name": EV,
    "tool_name": tool_name,
    "tool_input": tool_input,
}

try:
    r = subprocess.run(
        ["python3", SCRIPT],
        input=json.dumps(payload), capture_output=True, text=True, timeout=10,
    )
except Exception:
    sys.exit(0)

if r.returncode == 2 or "permissionDecision" in r.stdout:
    # Translate guard's hookSpecificOutput back to Cursor's { permission:"deny" }.
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
        inner = out.get("hookSpecificOutput") or {}
        if inner.get("permissionDecision") == "deny":
            # Cursor uses `"permission"` at top level for before*shell/read events.
            print(json.dumps({"permission": "deny"}))
            sys.exit(2)
    except Exception:
        pass
    # Fallback: deny-by-exit-2.
    sys.exit(2)

# Empty stdout => allow.
sys.exit(0)
