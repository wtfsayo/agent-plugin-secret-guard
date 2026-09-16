#!/usr/bin/env python3
"""PreToolUse/PostToolUse hook: keep secret values out of the session.

Droid port of ~/.config/devin/hooks/secret_guard.py. Tool names and hook
payload shapes follow the Factory Droid hooks contract:
https://docs.factory.ai/harness/hooks

PreToolUse blocks commands that would print secrets, reads of sensitive
files (or files containing secret-like values), writes/edits containing
literal secrets, and secrets forwarded to other tools. PostToolUse warns
when a tool response already leaked a secret-like value.

Escape hatch: DROID_SECRET_GUARD=off (or legacy DEVIN_SECRET_GUARD=off)
disables the hook entirely. Never fails the CLI: malformed stdin or any
exception exits 0; tracebacks go to secret_guard.log only.
"""
import json
import os
import re
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secret_patterns as sp

# ponytail: hooks dir this script lives under — same for droid/devin/plugin installs.
HELPERS = os.path.abspath(os.path.dirname(__file__))
LOG = os.path.join(HELPERS, "secret_guard.log")

# Helper invocations are stripped segment-by-segment before checking, so a
# helper call can't whitewash a leaky command chained after it. Match the
# tools by basename so any install location works (default ~/.config/{droid,
# devin}/hooks, a plugin-installed dir, or a custom path).
HELPER_SEG = re.compile(
    r"(^|[;&|\n]\s*)(?:[\w./~-]*/)?(?:secret-fetch|redacted-cat)\b[^;&|\n]*"
)

LEAKY_REASON = (
    "Blocked: this command would print secrets into the session. Use "
    f"`{HELPERS}/redacted-cat <file>` (masks values), list env "
    "NAMES only (`env | cut -d= -f1`), or reference secrets via `$VAR`."
)


def block(reason):
    # Droid PreToolUse deny: JSON permissionDecision on stdout.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    # Belt-and-suspenders: exit 2 + stderr also blocks if JSON is ignored.
    print(reason, file=sys.stderr)
    sys.exit(2)


def scan_lines_for_secrets(text):
    kinds, lines, n = [], [], 0
    for i, line in enumerate(text.splitlines(), 1):
        hits = sp.find_secrets(line)
        n += len(hits)
        for kind, _ in hits:
            if kind not in kinds:
                kinds.append(kind)
            if len(lines) < 5:
                lines.append(i)
    return kinds, lines, n


# Canonical tool names across clients. Droid uses Execute/Read/Create/Edit;
# Cursor/Grok Bot use Shell/Write; Devin uses shell commands + fs.write/abs_path.
# We treat each canonical family the same way regardless of client spelling.
_SHELL_TOOLS = frozenset({
    "Execute", "write_to_process",
    "Shell", "run_terminal_command", "terminal", "exec",
    "shell", "bash", "sh",
})
_FILE_READ_TOOLS = frozenset({
    "Read", "read_file",
})
_FILE_WRITE_TOOLS = frozenset({
    "Create", "Write", "str_replace_editor", "fs_write", "write_file",
    "apply_patch", "Edit", "MultiEdit", "edit",
})


def _tool_family(tool):
    if tool in _SHELL_TOOLS:
        return "shell"
    if tool in _FILE_READ_TOOLS:
        return "read"
    if tool in _FILE_WRITE_TOOLS:
        return "write"
    return None


def pre_tool_use(data):
    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}
    family = _tool_family(tool)

    if family == "shell":
        cmd = ti.get("command") or ti.get("text_input") or ""
        cmd = HELPER_SEG.sub(lambda m: m.group(1), cmd)
        if not cmd.strip(" ;&|\n"):
            return
        reason = sp.check_secret_cli(cmd)
        if reason:
            block(reason)
        if sp.is_leaky_cmd(cmd):
            block(LEAKY_REASON)
        hits = sp.find_secrets(cmd, include_medium=True)
        if hits:
            kind, val = hits[0]
            block(
                "Blocked: command contains a literal secret-like value ("
                + sp.mask(val, kind)
                + "). Reference it via an environment variable instead of "
                "pasting the value."
            )
        return

    if family == "read":
        path = ti.get("file_path") or ""
        norm = os.path.abspath(os.path.expanduser(path))
        if sp.sensitive_path_re().search(norm):
            block(
                "Blocked: this path may contain secrets. View it with "
                f"`{HELPERS}/redacted-cat <file>` (masks values) "
                "or list env NAMES only (`env | cut -d= -f1`); reference "
                "secrets via `$VAR`."
            )
        try:
            if not os.path.isfile(norm) or os.path.getsize(norm) >= 2 * 1024 * 1024:
                return
            with open(norm, encoding="utf-8", errors="strict") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            return
        kinds, lines, n = scan_lines_for_secrets(text)
        if kinds:
            block(
                f"Blocked: {path} contains {n} secret-like value(s) "
                f"({', '.join(kinds)}) at line(s) {', '.join(map(str, lines))}. "
                f"View with `{HELPERS}/redacted-cat {path}` or "
                "read a line range excluding them."
            )
        return

    if family == "write":
        if tool == "ApplyPatch":
            text = json.dumps(ti, ensure_ascii=False)
        else:
            # Create uses `content`; Edit uses `new_str`/`new_string`;
            # str_replace_editor/fs_write use `new_str`/`new_content`/`content`.
            text = "\n".join(
                str(ti.get(k) or "")
                for k in (
                    "content", "new_str", "new_string", "new_source",
                    "new_content", "file_text", "patch", "new",
                )
            )
        hits = sp.find_secrets(text, include_medium=True)
        if hits:
            kind, val = hits[0]
            path = ti.get("file_path") or "file"
            block(
                "Blocked: about to write a literal secret-like value ("
                + sp.mask(val, kind)
                + f") into {path}. Load it from the environment or a "
                "gitignored .env instead."
            )
        return

    hits = sp.find_secrets(json.dumps(ti, ensure_ascii=False), include_medium=True)
    if hits:
        kind, val = hits[0]
        block(
            "Blocked: tool arguments contain a literal secret-like value ("
            + sp.mask(val, kind)
            + "). Do not forward secrets to subagents, MCP servers, or URLs."
        )


def post_tool_use(data):
    resp = data.get("tool_response") or {}
    if isinstance(resp, dict):
        text = str(resp.get("output") or "") + "\n" + str(resp.get("error") or "")
    else:
        text = str(resp)
    hits = sp.find_secrets(text, include_medium=True) + sp.find_kv_secrets(text)
    if not hits:
        return
    kinds = []
    for kind, _ in hits:
        if kind not in kinds:
            kinds.append(kind)
    masked = ", ".join(sp.mask(v, k) for k, v in hits[:3])
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"SECRET GUARD: the previous tool output contained "
                f"{len(hits)} secret-like value(s) [{', '.join(kinds)}; "
                f"{masked}]. Do not repeat these values in chat, files, "
                "commit messages, commands, or subagent briefs — refer to "
                "them by variable name or write <redacted>. Use "
                f"{HELPERS}/redacted-cat or secret-fetch next time."
            ),
        }
    }))


def main():
    if os.environ.get("DROID_SECRET_GUARD") == "off" or os.environ.get("DEVIN_SECRET_GUARD") == "off":
        return
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    event = data.get("hook_event_name") or ""
    if event == "PreToolUse":
        pre_tool_use(data)
    elif event == "PostToolUse":
        post_tool_use(data)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            with open(LOG, "a") as f:
                f.write(traceback.format_exc() + "\n")
        except OSError:
            pass
        sys.exit(0)
