#!/usr/bin/env python3
"""PreToolUse/PostToolUse hook: keep secret values out of the session.

Droid port of ~/.config/devin/hooks/secret_guard.py. Tool names and hook
payload shapes follow the Factory Droid hooks contract:
https://docs.factory.ai/harness/hooks

PreToolUse blocks commands that would print secrets, reads and content
greps of sensitive files (or file ranges containing secret-like values),
writes/edits containing literal secrets, and secrets forwarded to other
tools. PostToolUse warns when a tool response already leaked a secret-like
value.

Escape hatch: SECRET_GUARD=off (or legacy DROID_SECRET_GUARD=off /
DEVIN_SECRET_GUARD=off) disables the hook entirely.

Failure policy: PreToolUse fails closed. A scan that runs past SCAN_BUDGET_S,
or an internal error, denies the call with a reason naming a way forward.
PostToolUse fails open (the output already exists); an unfinished scan adds a
"treat as possibly containing secrets" warning. Malformed stdin is ignored.
Tracebacks go to secret_guard.log under $CLAUDE_PLUGIN_DATA, or
~/.cache/secret-guard/ elsewhere.
"""
import fnmatch
import json
import os
import re
import shutil
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secret_patterns as sp

# ponytail: hooks dir this script lives under — same for droid/devin/plugin installs.
HELPERS = os.path.abspath(os.path.dirname(__file__))
PLUGIN_ROOT = os.path.dirname(HELPERS)
BIN = os.path.join(PLUGIN_ROOT, "bin")
LOG = os.path.join(
    os.environ.get("CLAUDE_PLUGIN_DATA")
    or os.path.join(os.path.expanduser("~"), ".cache", "secret-guard"),
    "secret_guard.log",
)

# Deadline for one hook call's scanning. Hook timeouts are 10 s; finishing
# well inside lets PreToolUse deny instead of timing out, which fails open.
SCAN_BUDGET_S = 5.0
_DEADLINE = time.monotonic() + SCAN_BUDGET_S
# PostToolUse scans the first POST_SCAN_CAP chars of model-visible output.
POST_SCAN_CAP = 256 * 1024
# Files under this size are scanned whole when a Read gives no offset/limit;
# larger ones are scanned over the first DEFAULT_READ_LINES lines, which is
# what Claude Code's Read shows by default.
WHOLE_FILE_MAX = 2 * 1024 * 1024
DEFAULT_READ_LINES = 2000

# Helper invocations are stripped segment-by-segment before checking, so a
# helper call can't whitewash a leaky command chained after it. A segment is
# stripped only when its executable is this install's own helper (see
# _trusted_helper) and it carries no command substitution.
HELPER_SEG = re.compile(
    r"(^|[;&|\n]\s*)(?P<exe>(?:[\w./~-]*/)?(?P<name>secret-fetch|redacted-cat))"
    r"(?=[\s;&|]|$)(?P<args>[^;&|\n]*)"
)
_SUBST = re.compile(r"\$\(|`|<\(|>\(")
# Commands that print every exported variable; inside `secret-fetch
# --env-exec` that includes the secrets it just exported.
_ENV_DUMP = re.compile(r"(?:sudo\s+)?(?:printenv\b|set\s*$|export\s+-p\b|env(?:\s+-\S+)*\s*$)")

_EVENT = ""


def _on_plugin_path():
    """True in a Claude Code plugin session: bin/ is on the Bash tool's PATH."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    return (bool(root) and os.path.isdir(BIN)
            and os.path.realpath(root) == os.path.realpath(PLUGIN_ROOT))


def helper(name):
    """How the agent should invoke a bundled helper in this install."""
    return name if _on_plugin_path() else os.path.join(HELPERS, name)


def _own_helper_paths(name):
    return {os.path.realpath(os.path.join(HELPERS, name)),
            os.path.realpath(os.path.join(BIN, name))}


def _trusted_helper(exe, name):
    if "/" in exe:
        return os.path.realpath(os.path.expanduser(exe)) in _own_helper_paths(name)
    if _on_plugin_path():
        return True
    found = shutil.which(name)
    return bool(found) and os.path.realpath(found) in _own_helper_paths(name)


def _env_exec_leaks(tail):
    tail = tail.strip()
    if _ENV_DUMP.match(tail) or sp.is_leaky_cmd(tail):
        return True
    m = re.search(r"\b(?:ba|z|da)?sh\s+-c\s+(['\"])(.*?)\1", tail)
    return bool(m) and _env_exec_leaks(m.group(2))


def _strip_helpers(cmd):
    def repl(m):
        args = m.group("args")
        if m.group("name") == "secret-fetch":
            em = re.search(r"--env-exec\s+--\s+(.*)", args)
            if em and _env_exec_leaks(em.group(1)):
                block(
                    "Blocked: the command after `secret-fetch --env-exec --` would "
                    "print the exported secrets. Run a program that consumes them "
                    "(e.g. `python3 script.py` reading os.environ) instead."
                )
        if not _trusted_helper(m.group("exe"), m.group("name")) or _SUBST.search(args):
            return m.group(0)
        return m.group(1)
    return HELPER_SEG.sub(repl, cmd)


def leaky_reason():
    return (
        "Blocked: this command would print secrets into the session. Use "
        f"`{helper('redacted-cat')} <file>` (masks values), list env "
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


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _read_window(norm, ti):
    """Return (text, first_line) for the lines this Read call will show, or
    None when the file is missing or not UTF-8 text."""
    offset, limit = ti.get("offset"), ti.get("limit")
    try:
        if offset is None and limit is None and os.path.getsize(norm) < WHOLE_FILE_MAX:
            with open(norm, encoding="utf-8", errors="strict") as f:
                return f.read(), 1
        first = max(_int(offset, 1), 1)
        last = first + max(_int(limit, DEFAULT_READ_LINES), 1) - 1
        lines = []
        with open(norm, encoding="utf-8", errors="strict") as f:
            for i, line in enumerate(f, 1):
                if i > last:
                    break
                if i >= first:
                    lines.append(line)
        return "".join(lines), first
    except (OSError, UnicodeDecodeError):
        return None


# Representative names of sensitive files, used to judge Grep globs.
_SENSITIVE_SAMPLES = (
    ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
    "server.pem", "server.key", "cert.p12", "cert.pfx", "credentials.json",
    "secrets.json", "app.secrets.yml", "keypair.json", ".netrc", ".npmrc",
    ".pypirc", ".git-credentials",
)
_SENSITIVE_STEM = re.compile(r"env|pem|key|p12|pfx|id_rsa|id_ed25519|credential|secret|netrc|npmrc|pypirc")


def _expand_braces(glob):
    m = re.search(r"\{([^{}]*)\}", glob)
    if not m:
        return [glob]
    return [x for alt in m.group(1).split(",")
            for x in _expand_braces(glob[:m.start()] + alt + glob[m.end():])]


def _glob_hits_sensitive(glob):
    for pat in _expand_braces(glob):
        base = pat.rstrip("/").rsplit("/", 1)[-1]
        literal = re.sub(r"[*?\[\]]", "", base)
        if not _SENSITIVE_STEM.search(literal):
            continue
        if any(fnmatch.fnmatchcase(s, base) for s in _SENSITIVE_SAMPLES):
            return True
    return False


# Default output_mode per grep tool: Claude Code's Grep lists files unless
# asked for content; opencode's grep always prints matching lines.
_GREP_TOOLS = {"Grep": "files_with_matches", "grep": "content"}

# Canonical tool names across clients. Droid uses Execute/Read/Create/Edit;
# Cursor/Grok Bot use Shell/Write; Devin uses shell commands + fs.write/abs_path.
# We treat each canonical family the same way regardless of client spelling.
_SHELL_TOOLS = frozenset({
    "Execute", "write_to_process",
    "Shell", "run_terminal_command", "terminal", "exec",
    "shell", "bash", "sh",
    "Bash",  # Claude Code
})
_FILE_READ_TOOLS = frozenset({
    "Read", "read_file",
})
_FILE_WRITE_TOOLS = frozenset({
    "Create", "Write", "str_replace_editor", "fs_write", "write_file",
    "apply_patch", "Edit", "MultiEdit", "edit",
    "NotebookEdit",  # Claude Code
})


def _tool_family(tool):
    if tool in _SHELL_TOOLS:
        return "shell"
    if tool in _FILE_READ_TOOLS:
        return "read"
    if tool in _FILE_WRITE_TOOLS:
        return "write"
    if tool in _GREP_TOOLS:
        return "grep"
    return None


def pre_tool_use(data):
    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}
    family = _tool_family(tool)

    if family == "shell":
        cmd = ti.get("command") or ti.get("text_input") or ""
        cmd = _strip_helpers(cmd)
        if not cmd.strip(" ;&|\n"):
            return
        reason = sp.check_secret_cli(cmd, fetch=helper("secret-fetch"))
        if reason:
            block(reason)
        if sp.is_leaky_cmd(cmd):
            block(leaky_reason())
        hits = sp.find_secrets(cmd, include_medium=True, deadline=_DEADLINE)
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
        rcat = helper("redacted-cat")
        if sp.sensitive_path_re().search(norm):
            block(
                "Blocked: this path may contain secrets. View it with "
                f"`{rcat} <file>` (masks values) "
                "or list env NAMES only (`env | cut -d= -f1`); reference "
                "secrets via `$VAR`."
            )
        if not os.path.isfile(norm):
            return
        window = _read_window(norm, ti)
        if window is None:
            return
        text, first = window
        try:
            hits = sp.scan(text, deadline=_DEADLINE)
        except sp.ScanBudgetExceeded:
            block(
                f"Blocked: secret-guard could not finish scanning {path}. Read "
                f"a smaller range (offset/limit) or view it with `{rcat} {path} "
                "-n START,END` (masks values)."
            )
        if hits:
            kinds = list(dict.fromkeys(k for k, _, _ in hits))
            lines = sorted({first + ln - 1 for _, _, ln in hits})
            block(
                f"Blocked: {path} contains {len(hits)} secret-like value(s) "
                f"({', '.join(kinds)}) at line(s) {', '.join(map(str, lines[:10]))}. "
                f"Read a line range (offset/limit) that excludes those lines, or "
                f"view them masked with `{rcat} {path} -n START,END`."
            )
        return

    if family == "grep":
        mode = ti.get("output_mode") or _GREP_TOOLS[tool]
        context = any(ti.get(k) for k in ("-A", "-B", "-C", "context"))
        if mode != "content" and not context:
            return
        path = ti.get("path") or ""
        glob = ti.get("glob") or ti.get("include") or ""
        norm = os.path.abspath(os.path.expanduser(path)) if path else ""
        if (norm and sp.sensitive_path_re().search(norm)) or (glob and _glob_hits_sensitive(glob)):
            block(
                "Blocked: this search would print lines from files that may "
                "contain secrets. Use output_mode `files_with_matches` or "
                f"`count`, or view a file masked with `{helper('redacted-cat')} "
                "<file> -n START,END`."
            )
        return

    if family == "write":
        if tool == "ApplyPatch":
            text = json.dumps(ti, ensure_ascii=False)
        else:
            # Create uses `content`; Edit uses `new_str`/`new_string`;
            # str_replace_editor/fs_write use `new_str`/`new_content`/`content`;
            # Codex apply_patch carries the patch in `input`/`command`.
            text = "\n".join(
                str(ti.get(k) or "")
                for k in (
                    "content", "new_str", "new_string", "new_source",
                    "new_content", "file_text", "patch", "new", "input",
                    "command",
                )
            )
            # Claude Code MultiEdit nests its replacements in `edits`.
            for edit in ti.get("edits") or []:
                if isinstance(edit, dict):
                    text += "\n" + str(edit.get("new_string") or "")
        hits = sp.find_secrets(text, include_medium=True, deadline=_DEADLINE)
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

    hits = sp.find_secrets(json.dumps(ti, ensure_ascii=False), include_medium=True,
                           deadline=_DEADLINE)
    if hits:
        kind, val = hits[0]
        block(
            "Blocked: tool arguments contain a literal secret-like value ("
            + sp.mask(val, kind)
            + "). Do not forward secrets to subagents, MCP servers, or URLs."
        )


# Edit/Write responses echo file content the model never sees (Claude Code's
# originalFile, structuredPatch) or that it wrote itself (PreToolUse already
# checked new content).
_EDIT_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_EDIT_ECHO_KEYS = frozenset({"originalFile", "structuredPatch", "oldString", "newString", "content"})


def _response_text(resp, skip=frozenset()):
    # Droid/Devin/omp send {"output", "error"}; Claude Code sends tool-specific
    # shapes ({"stdout", "stderr"} for Bash, {"file": {"content"}} for Read,
    # content-block lists for MCP), so scan every string leaf.
    if isinstance(resp, dict):
        return "\n".join(_response_text(v, skip) for k, v in resp.items() if k not in skip)
    if isinstance(resp, list):
        return "\n".join(_response_text(v, skip) for v in resp)
    return resp if isinstance(resp, str) else ""


def _context(text):
    print(json.dumps({
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}
    }))


def post_tool_use(data):
    skip = _EDIT_ECHO_KEYS if data.get("tool_name") in _EDIT_TOOLS else frozenset()
    text = _response_text(data.get("tool_response"), skip)[:POST_SCAN_CAP]
    try:
        hits = sp.find_secrets(text, include_medium=True, deadline=_DEADLINE)
    except sp.ScanBudgetExceeded:
        _context(
            "SECRET GUARD: could not finish scanning the previous tool output. "
            "Treat it as possibly containing secrets: do not repeat values from "
            "it in chat, files, commit messages, commands, or subagent briefs."
        )
        return
    hits += sp.find_kv_secrets(text)
    seen, unique = set(), []
    for k, v in hits:
        if v not in seen:
            seen.add(v)
            unique.append((k, v))
    if not unique:
        return
    kinds = list(dict.fromkeys(k for k, _ in unique))
    masked = ", ".join(sp.mask(v, k) for k, v in unique[:3])
    _context(
        f"SECRET GUARD: the previous tool output contained "
        f"{len(unique)} secret-like value(s) [{', '.join(kinds)}; "
        f"{masked}]. Do not repeat these values in chat, files, "
        "commit messages, commands, or subagent briefs — refer to "
        "them by variable name or write <redacted>. Use "
        f"{helper('redacted-cat')} or {helper('secret-fetch')} next time."
    )


def main():
    global _EVENT
    if any(os.environ.get(v) == "off"
           for v in ("SECRET_GUARD", "DROID_SECRET_GUARD", "DEVIN_SECRET_GUARD")):
        return
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    _EVENT = data.get("hook_event_name") or ""
    if _EVENT == "PreToolUse":
        try:
            pre_tool_use(data)
        except sp.ScanBudgetExceeded:
            block("Blocked: secret-guard could not finish scanning this call in "
                  f"{SCAN_BUDGET_S:.0f} s. Split it into smaller pieces.")
    elif _EVENT == "PostToolUse":
        post_tool_use(data)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            with open(LOG, "a") as f:
                f.write(traceback.format_exc() + "\n")
        except OSError:
            pass
        if _EVENT == "PreToolUse":
            block(f"Blocked: secret-guard hit an internal error; see {LOG}.")
        sys.exit(0)
