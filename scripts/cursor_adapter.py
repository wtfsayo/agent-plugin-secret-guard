#!/usr/bin/env python3
"""Translate Cursor's hook event shape → Droid shape so secret_guard.py
doesn't need to know anything about Cursor (https://cursor.com/docs/hooks).

Cursor sends on stdin:
  { conversation_id, hook_event_name: 'preToolUse', tool_name, tool_input,
    cursor_version, workspace_roots, ... }
  plus per-event fields: beforeShellExecution {command}, beforeReadFile
  {file_path}, postToolUse {tool_output}, afterShellExecution {output},
  afterMCPExecution {result_json}.
Cursor expects on stdout:
  pre events:  { permission: 'deny', user_message, agent_message }
  post events: { additional_context }
"""
import json
import os
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_guard.py")

# Cursor lowerCamel event → canonical event name.
EV = {
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "beforeshellexecution": "PreToolUse",
    "aftershellexecution": "PostToolUse",
    "beforereadfile": "PreToolUse",
    "beforemcpexecution": "PreToolUse",
    "aftermcpexecution": "PostToolUse",
    "beforetabfileread": "PreToolUse",
}
# Where each post event carries the output the model will see.
OUTPUT_FIELD = {
    "posttooluse": "tool_output",
    "aftershellexecution": "output",
    "aftermcpexecution": "result_json",
}


def build_payload(data):
    ev_raw = (data.get("hook_event_name") or "").lower()
    event = EV.get(ev_raw)
    if not event:
        return None
    tool_name = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}
    # Cursor's hook-specific fields live at top level, not under tool_input.
    if ev_raw in ("beforeshellexecution", "aftershellexecution"):
        tool_name = tool_name or "Shell"
        cmd = tool_input.get("command") if isinstance(tool_input, dict) else None
        tool_input = {"command": cmd or data.get("command") or data.get("input") or ""}
    elif ev_raw in ("beforereadfile", "beforetabfileread"):
        tool_name = "Read"
        fp = (tool_input.get("file_path") if isinstance(tool_input, dict) else None) or data.get("file_path")
        tool_input = {"file_path": fp or ""}
    elif ev_raw in ("beforemcpexecution", "aftermcpexecution"):
        tool_name = f"MCP:{tool_name or 'unknown'}"
    payload = {"hook_event_name": event, "tool_name": tool_name, "tool_input": tool_input}
    if event == "PostToolUse":
        payload["tool_response"] = {"output": data.get(OUTPUT_FIELD.get(ev_raw, ""), "")}
    return payload


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    payload = build_payload(data)
    if payload is None:
        return 0
    pre = payload["hook_event_name"] == "PreToolUse"
    try:
        r = subprocess.run(
            [sys.executable, SCRIPT],
            input=json.dumps(payload), capture_output=True, text=True, timeout=9,
        )
        out = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {}
    except Exception:
        if pre:  # fail closed, like the core
            msg = "Blocked: secret-guard could not run; retry or check the hook install."
            print(json.dumps({"permission": "deny", "user_message": msg, "agent_message": msg}))
            return 2
        return 0
    inner = out.get("hookSpecificOutput") or {}
    if inner.get("permissionDecision") == "deny":
        msg = inner.get("permissionDecisionReason") or "Blocked by secret-guard"
        print(json.dumps({"permission": "deny", "user_message": msg, "agent_message": msg}))
        return 2
    if inner.get("additionalContext"):
        print(json.dumps({"additional_context": inner["additionalContext"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
