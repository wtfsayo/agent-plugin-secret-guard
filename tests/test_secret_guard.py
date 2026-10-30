#!/usr/bin/env python3
"""Tests for secret_guard.py, secret-fetch, and redacted-cat.
Drives the hook as a subprocess with JSON stdin. Synthetic secrets only.
"""
import json
import os
import random
import re
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stdout
from io import StringIO

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.dirname(os.path.abspath(__file__)) + "/../scripts"
GUARD = os.path.join(HOOKS, "secret_guard.py")
FETCH = os.path.join(HOOKS, "secret-fetch")
RCAT = os.path.join(HOOKS, "redacted-cat")
ADAPTER = os.path.join(HOOKS, "cursor_adapter.py")
# The guard logs tracebacks under $CLAUDE_PLUGIN_DATA; point it at a scratch dir.
DATA_DIR = tempfile.mkdtemp(prefix="secret-guard-test-")
LOG = os.path.join(DATA_DIR, "secret_guard.log")

sys.path.insert(0, HOOKS)
import secret_patterns as sp  # noqa: E402
import sync_gitleaks  # noqa: E402
import gitleaks_patterns  # noqa: E402

# Synthetic placeholders, not real credentials.
SK = "sk-" + "Ab3dEf9Gh8Jk2Mn4qRs6TuVwXy" + "Zz0123456789"   # 42 chars, lowercase digits tail
GHP = "ghp_" + "Ab3dEf9" * 6            # 42 chars
WHSEC = "whsec_" + "Zx9Qw8Er7Ty6Ui5O" * 2 + "As4Df6Gh"   # 46 chars
PGURL = "postgres" + "://" + "u" + ":" + "p4ssw0rdXYZ123" + "@" + "host/db"
AKIA = "AKIA" + "Q7XJ3MZK5RT2WLPB"


def _log_size():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def _env(env_off=False, extra=None):
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_ROOT"}
    env["CLAUDE_PLUGIN_DATA"] = DATA_DIR
    if env_off:
        env["DEVIN_SECRET_GUARD"] = "off"
    env.update(extra or {})
    return env


def run_guard(payload, env_off=False, env=None, cwd=None):
    before = _log_size()
    r = subprocess.run(
        [sys.executable, GUARD], input=json.dumps(payload),
        capture_output=True, text=True, env=_env(env_off, env), cwd=cwd,
    )
    if _log_size() != before:
        with open(LOG) as f:
            f.seek(before)
            raise AssertionError("guard crashed:\n" + f.read())
    return r


def pre(tool, tool_input):
    return {"hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": tool_input, "session_id": "t", "prompt_id": "p"}


def post(output="", error=""):
    return {"hook_event_name": "PostToolUse", "tool_name": "Execute",
            "tool_input": {}, "session_id": "t", "prompt_id": "p",
            "tool_response": {"success": True, "output": output, "error": error}}


def decision(r):
    """Return 'block', 'context', or 'allow' from hook stdout."""
    out = r.stdout.strip()
    if not out:
        return "allow"
    d = json.loads(out)
    if d.get("decision") == "block":
        return "block"
    hso = d.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "deny":
        return "block"
    if "hookSpecificOutput" in d:
        return "context"
    return "allow"


class ExecGeneric(unittest.TestCase):
    def check(self, cmd, expect):
        r = run_guard(pre("Execute", {"command": cmd}))
        # Droid port: blocks exit 2 with stderr + JSON deny; allows exit 0.
        if expect == "allow":
            self.assertEqual(r.returncode, 0, r.stderr)
        else:
            self.assertIn(r.returncode, (0, 2), r.stderr)
        self.assertEqual(decision(r), expect,
                         f"{cmd!r} -> {decision(r)}: {r.stdout}")

    def test_cat_env(self): self.check("cat .env", "block")
    def test_cat_env_example(self): self.check("cat .env.example", "allow")
    def test_cat_env_local(self): self.check("cat /tmp/x/.env.local", "block")
    def test_env_bare(self): self.check("env", "block")
    def test_env_names_only(self): self.check("env | cut -d= -f1", "allow")
    def test_printenv_key(self): self.check("printenv OPENAI_API_KEY", "block")
    def test_echo_key(self): self.check("echo $OPENAI_API_KEY", "block")
    def test_echo_home(self): self.check('echo "$HOME"', "allow")
    def test_ssh_config(self): self.check("cat ~/.ssh/config", "allow")
    def test_ssh_key(self): self.check("cat ~/.ssh/id_ed25519", "block")
    def test_zshrc(self): self.check("cat ~/.zshrc", "block")
    def test_ssh_remote_hermes(self): self.check("ssh box 'cat ~/.hermes/auth.json'", "block")
    def test_gh_auth_token(self): self.check("gh auth token", "block")
    def test_git_status(self): self.check("git status", "allow")
    def test_curl_bearer_var(self):
        self.check('curl -H "Authorization: Bearer $TOKEN" http://x', "allow")
    def test_curl_bearer_literal(self):
        self.check(f'curl -H "Authorization: Bearer {SK}" http://x', "block")
    def test_redacted_cat_helper(self):
        self.check(f"{RCAT} .env", "allow")
    def test_ssm_decrypt(self):
        self.check("aws ssm get-parameter --name x --with-decryption", "block")

    # --- rework items ---
    # 1. path-based detection
    def test_py_open_opencodex(self):
        self.check('python3 -c "import json; d=json.load(open(\''
                   '" + os.path.expanduser("~/.opencodex/config.json") + '"\'))\"", "block")
    def test_cat_pi_models(self):
        self.check("cat ~/.pi/agent/models.json | head", "block")
    def test_grep_zshrc_chain(self):
        self.check("cd /tmp; grep -n HOME ~/.zshrc; echo done", "block")
    def test_ssh_grep_hermes(self):
        self.check("ssh host 'grep -nE \"token|secret\" ~/.hermes/config.yaml'",
                   "block")
    def test_ls_zshrc_allowed(self):
        self.check("ls -la ~/.zshrc", "allow")
    def test_stat_env_allowed(self):
        self.check("stat -f '%z' .env; test -f .env && echo exists", "allow")
    def test_chmod_rm_allowed(self):
        self.check("chmod 600 ~/.ssh/id_rsa; wc -c ~/.zshrc", "allow")
    def test_zsh_history(self):
        self.check("grep foo ~/.zsh_history", "block")
    # 2a. list-form aws invocation in python
    def test_aws_listform_heredoc(self):
        self.check('python3 <<\'EOF\'\nimport subprocess\n'
                   'subprocess.run(["aws","secretsmanager","get-secret-value",'
                   '"--secret-id","s"])\nEOF', "block")
    def test_aws_listform_allowed_sub(self):
        self.check('python3 -c "import subprocess; subprocess.run('
                   '[\'aws\',\'secretsmanager\',\'describe-secret\','
                   '\'--secret-id\',\'s\'])"', "allow")
    # 3. aws configure list-profiles allowed
    def test_aws_configure_list_profiles(self):
        self.check("aws configure list-profiles", "allow")
        self.check("aws configure list-profiles | head", "allow")
        self.check("aws configure list", "allow")
        self.check("aws configure get region", "block")
    # 4. cat heredoc write to .env.example
    def test_cat_heredoc_env_example(self):
        self.check("cat > .env.example <<'EOF'\nOPENAI_API_KEY=\n"
                   "DATABASE_URL=\nEOF", "allow")
    def test_cat_heredoc_env_real(self):
        self.check("cat > .env <<'EOF'\nOPENAI_API_KEY=\nEOF", "block")
    # 5. strings|grep on a binary
    def test_strings_grep_binary(self):
        self.check('strings /tmp/app.bin | grep -oE "[a-z_]{3,40}" | '
                   'grep -iE "secret|token|credential|env" | head', "allow")
    # 6. secrets.sh scripts allowed, dotfile secrets still blocked
    def test_head_secrets_script(self):
        self.check("head -30 scripts/sync-foo-secrets.sh", "allow")
        self.check("cat scripts/sync-foo-secrets.sh", "allow")
        self.check("cat .devin_secrets.sh", "block")
        self.check("cat app_secrets.json", "block")
    # 7. helper prefix is not a bypass
    def test_helper_bypass(self):
        self.check(f"{FETCH} aws x --keys; cat .env", "block")
        self.check(f"{RCAT} .env | head", "allow")
    # 8. op --fields safe-list
    def test_op_fields_username(self):
        self.check('echo "user: $(op item get I --fields username)"', "allow")
        self.check('U=$(op item get I --fields username); echo "$U"', "allow")
        self.check("op item get I --fields username,email", "allow")
        self.check("op item get I --fields notesPlain", "block")
    # 11. captured var revealed via heredoc / environ access
    def test_capture_heredoc_reveal(self):
        self.check("S=$(op read op://V/I/p)\ncat <<EOF\n$S\nEOF", "block")
        self.check("S=$(op read op://V/I/p); "
                   "python3 -c 'import os; print(os.environ[\"S\"])'", "block")
        self.check("S=$(op read op://V/I/p); "
                   "node -e 'console.log(process.env.S)'", "block")


class ExecAws(unittest.TestCase):
    def check(self, cmd, expect):
        r = run_guard(pre("Execute", {"command": cmd}))
        self.assertEqual(decision(r), expect, f"{cmd!r}: {r.stdout}")

    def test_list_versions(self):
        self.check("aws secretsmanager list-secret-version-ids --secret-id s "
                   "--query 'Versions[]' --output table", "allow")
    def test_describe(self):
        self.check("aws secretsmanager describe-secret --secret-id s", "allow")
    def test_get_pipe_head(self):
        self.check("aws secretsmanager get-secret-value --secret-id s "
                   "--output json | head -20", "block")
    def test_get_2to1(self):
        self.check("aws secretsmanager get-secret-value --secret-id s "
                   "2>&1 | head -10", "block")
    def test_get_pipe_python(self):
        self.check("aws secretsmanager get-secret-value --secret-id s --query "
                   "SecretString --output text | python3 -c \"import json,sys; "
                   "d=json.load(sys.stdin); print(sorted(d.keys()))\"", "block")
        r = run_guard(pre("Execute", {"command": "aws secretsmanager get-secret-value "
                                             "--secret-id s | head"}))
        self.assertIn("secret-fetch", r.stdout)
    def test_get_with_export(self):
        self.check("export AWS_PROFILE=p; aws secretsmanager get-secret-value "
                   "--secret-id s --version-id v --query SecretString --output "
                   "text | python3 -c \"print(1)\"", "block")
    def test_get_captured_use(self):
        self.check("S=$(aws secretsmanager get-secret-value --secret-id s "
                   "--query SecretString --output text); psql \"$S\" -c 'select 1'",
                   "allow")
    def test_get_captured_echo(self):
        self.check("S=$(aws secretsmanager get-secret-value --secret-id s "
                   "--query SecretString --output text); echo \"$S\"", "block")
    def test_get_captured_len(self):
        self.check("S=$(aws secretsmanager get-secret-value --secret-id s "
                   "--query SecretString --output text); echo \"len ${#S}\"",
                   "allow")
    def test_secret_fetch_allowed(self):
        self.check(f"{FETCH} aws s --hash", "allow")
    def test_put_literal(self):
        self.check('aws secretsmanager put-secret-value --secret-id s '
                   f'--secret-string \'{{"DATABASE_URL":"{PGURL}"}}\'', "block")
    def test_put_file(self):
        self.check("aws secretsmanager put-secret-value --secret-id s "
                   "--secret-string file:///tmp/new.json", "allow")
    def test_put_var(self):
        self.check('aws secretsmanager put-secret-value --secret-id s '
                   '--secret-string "$NEW"', "allow")


class ExecOp(unittest.TestCase):
    def check(self, cmd, expect):
        r = run_guard(pre("Execute", {"command": cmd}))
        self.assertEqual(decision(r), expect, f"{cmd!r}: {r.stdout}")

    def test_whoami_vault(self): self.check("op whoami; op vault list", "allow")
    def test_item_list(self):
        self.check('op item list --vault "V" --format json | head', "allow")
    def test_item_get_json(self):
        self.check('op item get "Item" --vault V --format json | head -80', "block")
    def test_item_get_plain(self): self.check('op item get "Item"', "block")
    def test_op_read(self): self.check('op read "op://V/I/password"', "block")
    def test_op_read_captured(self):
        self.check('PASS=$(op read "op://V/I/password"); agent-browser fill e5 "$PASS"',
                   "allow")
    def test_op_read_len_echo(self):
        self.check('PASS=$(op read "op://V/I/password"); '
                   'echo "user: $U, pass length: ${#PASS}"', "allow")
    def test_op_read_echoed(self):
        self.check('PASS=$(op read "op://V/I/password"); echo $PASS', "block")
    def test_item_get_captured(self):
        self.check('U=$(op item get I --fields username --format json | '
                   'python3 -c "import json,sys;print(json.load(sys.stdin)[\'value\'])")',
                   "allow")
    def test_item_get_reveal(self):
        self.check("op item get I --fields password --reveal", "block")
    def test_op_run(self):
        self.check("op run --env-file .env.tpl -- npm start", "allow")
    def test_op_inject_outfile(self):
        self.check("op inject -i cfg.tpl -o cfg.yml", "allow")
    def test_op_inject_stdout(self): self.check("op inject -i cfg.tpl", "block")
    def test_doc_get_outfile(self):
        self.check('op document get "Doc" -o /tmp/d', "allow")
    def test_doc_get_stdout(self): self.check('op document get "Doc"', "block")
    def test_secret_fetch_op(self):
        self.check(f'{FETCH} op "Item" --vault V', "allow")


class FileTools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def wfile(self, name, text):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def check_read(self, path, expect, needle=None):
        r = run_guard(pre("Read", {"file_path": path}))
        self.assertEqual(decision(r), expect, f"{path}: {r.stdout}")
        if needle:
            self.assertIn(needle, r.stdout)

    def test_read_zshrc(self): self.check_read("~/.zshrc", "block")
    def test_read_mcpjson(self): self.check_read("~/.cursor/mcp.json", "block")

    def test_read_secret_file(self):
        p = self.wfile("cfg.txt", f"line one\nline two\nkey = {SK}\nlast\n")
        self.check_read(p, "block", "line(s) 3")

    def test_read_plain(self):
        p = self.wfile("plain.txt", "nothing secret here\n")
        self.check_read(p, "allow")

    def test_read_missing(self):
        self.check_read(os.path.join(self.tmp.name, "nope"), "allow")

    def test_write_secret(self):
        r = run_guard(pre("Create", {"file_path": "/tmp/f", "content": f"tok={GHP}"}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_write_plain(self):
        r = run_guard(pre("Create", {"file_path": "/tmp/f", "content": "hello"}))
        self.assertEqual(decision(r), "allow")

    def test_edit_secret(self):
        r = run_guard(pre("Edit", {"file_path": "/tmp/f", "old_str": "x",
                                   "new_str": f"hook={WHSEC}"}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_subagent_secret(self):
        r = run_guard(pre("run_subagent", {"task": f"use key {SK}"}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_subagent_plain(self):
        r = run_guard(pre("run_subagent", {"task": "summarize the repo"}))
        self.assertEqual(decision(r), "allow")

    def test_mcp_secret(self):
        r = run_guard(pre("mcp_call_tool", {"arguments": {"key": SK}}))
        self.assertEqual(decision(r), "block", r.stdout)


class PostToolUse(unittest.TestCase):
    def test_output_secret(self):
        r = run_guard(post(output=f"fetched: {SK}"))
        self.assertEqual(decision(r), "context", r.stdout)
        self.assertIn("SECRET GUARD", r.stdout)
        self.assertNotIn(SK, r.stdout)

    def test_output_kv(self):
        r = run_guard(post(output='{"password": "' + "p4ssw0rdXYZabc123" + '"}'))
        self.assertEqual(decision(r), "context", r.stdout)
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    # 9. kv heuristic must not fire on code reading env vars
    def test_output_code_not_kv(self):
        r = run_guard(post(output='api_key = os.environ["OPENAI_API_KEY"]\n'
                                  'token = process.env.TOKEN'))
        self.assertEqual(r.stdout.strip(), "", r.stdout)

    def test_output_plain(self):
        r = run_guard(post(output="all good"))
        self.assertEqual(r.stdout.strip(), "")


class EscapeHatch(unittest.TestCase):
    def test_off(self):
        r = run_guard(pre("Execute", {"command": "cat .env"}), env_off=True)
        self.assertEqual(r.stdout.strip(), "")


class SecretFetch(unittest.TestCase):
    """secret-fetch against fake aws/op executables on PATH."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bindir)
        self.env = dict(os.environ, PATH=self.bindir + ":" + os.environ["PATH"])

        secret_json = json.dumps({
            "DATABASE_URL": "postgres" + "://" + "u" + ":" + "p4ssw0rdXYZ123" + "@" + "h:5432/db",
            "STRIPE_WEBHOOK_SECRET": WHSEC,
        })
        self._exe("aws", f'#!/bin/sh\nprintf \'%s\' \'{secret_json}\'\n')
        op_item = json.dumps({
            "title": "Item", "vault": {"name": "V"},
            "fields": [
                {"label": "username", "type": "STRING", "purpose": "USERNAME",
                 "value": "bob"},
                {"label": "password", "type": "CONCEALED", "purpose": "PASSWORD",
                 "value": "hunter2fakevalue"},
            ],
        })
        self._exe("op", f'#!/bin/sh\nprintf \'%s\' \'{op_item}\'\n')

    def _exe(self, name, body):
        p = os.path.join(self.bindir, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def fetch(self, *args):
        return subprocess.run([FETCH] + list(args), capture_output=True,
                              text=True, env=self.env)

    def test_keys(self):
        r = self.fetch("aws", "s", "--keys")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DATABASE_URL", r.stdout)
        self.assertIn("STRIPE_WEBHOOK_SECRET", r.stdout)
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    def test_shape(self):
        r = self.fetch("aws", "s", "--shape", "DATABASE_URL")
        self.assertIn("postgres://u:<redacted", r.stdout)
        self.assertIn("@h:5432/db", r.stdout)
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    def test_hash(self):
        r = self.fetch("aws", "s", "--hash")
        for line in r.stdout.strip().splitlines():
            self.assertRegex(line, r"^\w+: sha256=[0-9a-f]{12}$")
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    def test_masked_json(self):
        r = self.fetch("aws", "s", "--masked-json")
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)
        self.assertNotIn(WHSEC, r.stdout)

    def test_len(self):
        r = self.fetch("aws", "s", "--len")
        self.assertIn("DATABASE_URL: len=", r.stdout)
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    def test_env_exec(self):
        r = self.fetch("aws", "s", "--env-exec", "--",
                       "sh", "-c", "echo ${#DATABASE_URL}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(),
                         str(len("postgres://u:p4ssw0rdXYZ123@h:5432/db")))
        self.assertNotIn("p4ssw0rdXYZ123", r.stdout)

    def test_op(self):
        r = self.fetch("op", "Item", "--vault", "V")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("<concealed len=", r.stdout)
        self.assertIn("op://V/Item/password", r.stdout)
        self.assertNotIn("hunter2fakevalue", r.stdout)


class RedactedCat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_masks_value_keeps_key(self):
        p = os.path.join(self.tmp.name, "f.txt")
        with open(p, "w") as f:
            f.write(f"OPENAI_API_KEY={SK}\nplain line here\n")
        r = subprocess.run([RCAT, p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OPENAI_API_KEY=", r.stdout)
        self.assertIn("plain line here", r.stdout)
        self.assertNotIn(SK, r.stdout)
        self.assertIn("<redacted:", r.stdout)


class ClaudeCode(unittest.TestCase):
    """Claude Code tool names and payload shapes."""

    def test_bash_tool_guarded(self):
        r = run_guard(pre("Bash", {"command": "cat .env"}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_bash_tool_plain(self):
        r = run_guard(pre("Bash", {"command": "git status"}))
        self.assertEqual(decision(r), "allow", r.stdout)

    def test_notebook_edit_secret(self):
        r = run_guard(pre("NotebookEdit", {"notebook_path": "/tmp/n.ipynb",
                                           "new_source": f"key = '{SK}'"}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_multiedit_secret_in_edits(self):
        r = run_guard(pre("MultiEdit", {"file_path": "/tmp/f", "edits": [
            {"old_string": "a", "new_string": "b"},
            {"old_string": "x", "new_string": f"tok={GHP}"},
        ]}))
        self.assertEqual(decision(r), "block", r.stdout)

    def test_multiedit_plain(self):
        r = run_guard(pre("MultiEdit", {"file_path": "/tmp/f", "edits": [
            {"old_string": "a", "new_string": "b"}]}))
        self.assertEqual(decision(r), "allow", r.stdout)

    def _post(self, tool, response):
        return run_guard({"hook_event_name": "PostToolUse", "tool_name": tool,
                          "tool_input": {}, "session_id": "t",
                          "tool_response": response})

    def test_post_bash_stdout_leak(self):
        r = self._post("Bash", {"stdout": f"key={SK}", "stderr": "",
                                "interrupted": False, "isImage": False})
        self.assertEqual(decision(r), "context", r.stdout)

    def test_post_read_file_content_leak(self):
        r = self._post("Read", {"type": "text", "file": {
            "filePath": "/tmp/f", "content": f"token: {GHP}"}})
        self.assertEqual(decision(r), "context", r.stdout)

    def test_post_bash_plain(self):
        r = self._post("Bash", {"stdout": "On branch main", "stderr": "",
                                "interrupted": False, "isImage": False})
        self.assertEqual(decision(r), "allow", r.stdout)


class ExecOpCaptureForms(unittest.TestCase):
    def check(self, cmd, expect):
        r = run_guard(pre("Execute", {"command": cmd}))
        self.assertEqual(decision(r), expect, f"{cmd!r}: {r.stdout}")

    def test_quoted_capture(self):
        self.check('PASS="$(op read "op://V/I/password")"; tool --pw "$PASS"',
                   "allow")

    def test_quoted_inline_prefix(self):
        self.check("TOKEN=\"$(op read 'op://V/I/credential')\" wrangler deploy",
                   "allow")

    def test_quoted_capture_as_echo_arg(self):
        self.check('echo X="$(op read "op://V/I/password")"', "block")

    def test_unquoted_capture_as_printf_arg(self):
        self.check('printf "%s" X=$(op read "op://V/I/password")', "block")

    def test_exported_capture_printed_by_child(self):
        self.check('export T="$(op read "op://V/I/password")"; '
                   'python3 -c "import os;print(os.environ.get(\'T\'))"', "block")

    def test_exported_capture_printenv(self):
        self.check('export T="$(op read "op://V/I/password")"; printenv T', "block")

    def test_exported_capture_env_dump(self):
        self.check('export T="$(op read "op://V/I/password")"; env | sort', "block")

    def test_inline_capture_env_prefix_runs_tool(self):
        self.check('T="$(op read "op://V/I/password")" env FOO=1 tool', "allow")

    def test_export_capture(self):
        self.check('export T="$(op read "op://V/I/password")"; tool --pw "$T"',
                   "allow")

    def test_quoted_capture_echoed(self):
        self.check('PASS="$(op read "op://V/I/password")"; echo $PASS', "block")

    def test_item_get_json_labels(self):
        self.check("op item get I --vault V --format json | jq '.fields[].label'",
                   "allow")

    def test_item_get_json_labels_raw(self):
        self.check('op item get I --format=json | jq -r ".fields[].label"', "allow")

    def test_item_get_jq_filter_file(self):
        self.check("op item get I --format json | jq -f '.fields[].label'", "block")

    def test_item_get_jq_combined_file_flag(self):
        self.check("op item get I --format json | jq -rf '.fields[].label'", "block")

    def test_item_get_jq_shell_function(self):
        self.check("jq() { cat; }; op item get I --format json | jq '.fields[].label'",
                   "block")

    def test_item_get_json_values(self):
        self.check("op item get I --format json | jq '.fields[].value'", "block")

    def test_item_get_json_whole(self):
        self.check("op item get I --format json | jq '.'", "block")

    def test_item_get_json_labels_then_pipe(self):
        self.check("op item get I --format json | jq '.fields[].label' | tee x",
                   "block")

    def test_item_get_json_labels_extra_filter(self):
        self.check("op item get I --format json | jq '.fields[].label, .fields[].value'",
                   "block")


class GitleaksCatalog(unittest.TestCase):
    """scripts/gitleaks_patterns.py is generated by scripts/sync_gitleaks.py."""

    FIXTURE = [
        {"id": "okta-like", "keywords": ["OKTA"], "regex":
            r"""[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))[\s'"]{0,3})(?:=|:)[\x60'"\s=]{0,5}(00[\w=\-]{40})"""},
        {"id": "mid-flag", "keywords": ["p8e-"], "regex": r"\b(p8e-(?i)[a-z0-9]{32})"},
        {"id": "posix", "keywords": ["airtable"], "regex": r"\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b"},
        {"id": "go-z", "keywords": ["sha256~"], "regex": r"\b(sha256~[\w-]{43})(?:[^\w-]|\z)"},
        {"id": "path-only", "path": r"\.p12$"},
    ]

    def test_normalize_fixture(self):
        out, skipped = sync_gitleaks.build(self.FIXTURE)
        self.assertEqual(skipped, [])
        self.assertEqual(out, [
            ("okta-like", r"""(?i:(?:(?-i:[Oo]kta|OKTA))[\s'"]{0,3})(?:=|:)[\x60'"\s=]{0,5}(00[\w=\-]{40})""", ("okta",)),
            ("mid-flag", r"(?i)\b(p8e-[a-z0-9]{32})", ("p8e-",)),
            ("posix", r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b", ("airtable",)),
            ("go-z", r"\b(sha256~[\w-]{43})(?:[^\w-]|\Z)", ("sha256~",)),
        ])

    def test_lazy_prefix_kept_when_anchored(self):
        # Only a leading prefix can match empty without changing the match.
        self.assertEqual(sync_gitleaks.normalize(r"\b[\w.-]{0,50}?x"), r"\b[\w.-]{0,50}?x")

    def test_render_is_deterministic_and_licensed(self):
        a, b = sync_gitleaks.render(self.FIXTURE), sync_gitleaks.render(self.FIXTURE)
        self.assertEqual(a, b)
        self.assertIn("Copyright (c) 2019 Zachary Rice", a)
        self.assertIn(sync_gitleaks.GITLEAKS_REF, a)

    def test_committed_catalog_is_normalized(self):
        # A hand edit or a stale generator shows up as a rule normalize() would change.
        rules = gitleaks_patterns.GITLEAKS_PATTERNS
        self.assertGreater(len(rules), 200)
        for rid, pat, kws in rules:
            self.assertEqual(sync_gitleaks.normalize(pat), pat, rid)
            self.assertFalse(pat.startswith(("[\\w.-]{0,50}?", "(?i)[\\w.-]{0,50}?")), rid)
            self.assertTrue(kws and all(k == k.lower() for k in kws), rid)

    def test_catalog_compiles_without_warnings(self):
        re.purge()  # warnings fire only on a fresh compile
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            for _, pat, _ in gitleaks_patterns.GITLEAKS_PATTERNS:
                re.compile(pat)

    def test_okta_rule_still_matches(self):
        val = "00" + "Ab3dEf9Gh8" * 4
        self.assertIn(("okta-access-token", val), sp.find_secrets(f'OKTA_TOKEN="{val}"'))

    def test_airtable_pat_matches(self):
        val = "pat" + "Ab3dEf9Gh8Jk2M" + "." + "a1b2c3d4e5f60789" * 4
        self.assertIn(("airtable-personnal-access-token", val),
                      sp.find_secrets(f"airtable token {val}\n"))


def _blob(n, alphabet=string.ascii_letters + string.digits):
    rng = random.Random(0)
    return "".join(rng.choice(alphabet) for _ in range(n))


class ScanTiming(unittest.TestCase):
    """Hook timeouts fail open, so scans must finish well inside them."""

    def test_alnum_blob_under_half_second(self):
        blob = _blob(40_000)
        t = time.monotonic()
        sp.find_secrets(blob, include_medium=True)
        self.assertLess(time.monotonic() - t, 0.5)

    def test_blob_with_every_keyword_under_one_second(self):
        # Every 4 KB scan window carries every keyword, so every rule runs everywhere.
        kws = " ".join(k for _, _, ks in gitleaks_patterns.GITLEAKS_PATTERNS for k in ks)
        blob = _blob(40_000, string.ascii_letters + string.digits + "+/")
        text = "\n".join(blob[i:i + 2000] + " " + kws for i in range(0, len(blob), 2000))
        t = time.monotonic()
        sp.find_secrets(text, include_medium=True)
        self.assertLess(time.monotonic() - t, 1.0)

    def test_deadline_raises(self):
        with self.assertRaises(sp.ScanBudgetExceeded):
            sp.find_secrets("x", deadline=time.monotonic() - 1)

    def test_read_pre_data_uri_html_denies_fast(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "logo.html")
            with open(p, "w") as f:
                f.write('<img src="data:image/png;base64,' + _blob(12_000, string.ascii_letters
                        + string.digits + "+/") + '">\n' + f"AWS_KEY={AKIA}\n")
            t = time.monotonic()
            r = run_guard(pre("Read", {"file_path": p}))
            self.assertLess(time.monotonic() - t, 2.0)
            self.assertEqual(decision(r), "block", r.stdout)
            self.assertIn("line(s) 2", r.stdout)

    def test_large_source_read_and_edit_fast(self):
        import argparse
        with open(argparse.__file__) as f:
            src = f.read()
        t = time.monotonic()
        run_guard(pre("Read", {"file_path": argparse.__file__}))
        self.assertLess(time.monotonic() - t, 2.0)
        t = time.monotonic()
        r = run_guard({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {},
                       "tool_response": {"type": "text", "file": {"content": src}}})
        self.assertLess(time.monotonic() - t, 2.0)
        t = time.monotonic()
        r = run_guard({"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": {},
                       "tool_response": {"filePath": argparse.__file__, "originalFile": src,
                                         "oldString": "a", "newString": "b",
                                         "structuredPatch": [{"lines": src.splitlines()[:50]}]}})
        self.assertLess(time.monotonic() - t, 1.0)
        self.assertEqual(r.stdout.strip(), "")


class ScanBudget(unittest.TestCase):
    """Over budget: PreToolUse denies, PostToolUse warns."""

    def setUp(self):
        import secret_guard
        self.sg = secret_guard
        self.saved = secret_guard._DEADLINE
        secret_guard._DEADLINE = time.monotonic() - 1
        self.addCleanup(setattr, secret_guard, "_DEADLINE", self.saved)

    def _call(self, fn, payload):
        out = StringIO()
        with redirect_stdout(out), open(os.devnull, "w") as null:
            saved_err, sys.stderr = sys.stderr, null
            try:
                fn(payload)
                code = None
            except SystemExit as e:
                code = e.code
            finally:
                sys.stderr = saved_err
        return code, out.getvalue()

    def test_read_over_budget_denies(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.txt")
            with open(p, "w") as f:
                f.write("plain\n")
            code, out = self._call(self.sg.pre_tool_use,
                                   {"tool_name": "Read", "tool_input": {"file_path": p}})
        self.assertEqual(code, 2)
        self.assertIn("could not finish scanning", out)
        self.assertIn("redacted-cat", out)

    def test_post_over_budget_warns(self):
        code, out = self._call(self.sg.post_tool_use,
                               {"tool_name": "Bash", "tool_response": {"stdout": "hello"}})
        self.assertIsNone(code)
        self.assertIn("could not finish scanning", out)


class ReadWindow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "fixture.txt")
        with open(self.path, "w") as f:
            f.write("".join(f"line {i}\n" for i in range(1, 6)) + f"key = {SK}\n" + "tail\n")

    def read(self, **kw):
        return run_guard(pre("Read", dict(file_path=self.path, **kw)))

    def test_range_before_secret_allowed(self):
        self.assertEqual(decision(self.read(offset=1, limit=3)), "allow")

    def test_range_covering_secret_denied(self):
        r = self.read(offset=5, limit=3)
        self.assertEqual(decision(r), "block", r.stdout)
        self.assertIn("line(s) 6", r.stdout)

    def test_whole_file_denied(self):
        r = self.read()
        self.assertEqual(decision(r), "block", r.stdout)
        self.assertIn("line(s) 6", r.stdout)


class GrepTool(unittest.TestCase):
    def check(self, tool, ti, expect):
        r = run_guard(pre(tool, ti))
        self.assertEqual(decision(r), expect, f"{tool} {ti}: {r.stdout}")

    def test_content_grep_on_env_denied(self):
        self.check("Grep", {"pattern": "KEY", "path": ".env", "output_mode": "content"}, "block")

    def test_content_grep_env_glob_denied(self):
        self.check("Grep", {"pattern": ".", "path": ".", "glob": ".env*",
                            "output_mode": "content"}, "block")

    def test_context_flag_denied(self):
        self.check("Grep", {"pattern": "KEY", "path": ".env", "-C": 2}, "block")

    def test_files_with_matches_allowed(self):
        self.check("Grep", {"pattern": "KEY", "path": ".env"}, "allow")
        self.check("Grep", {"pattern": "KEY", "path": ".env", "output_mode": "count"}, "allow")

    def test_content_grep_on_source_allowed(self):
        self.check("Grep", {"pattern": "def ", "path": "src", "glob": "*.{py,json}",
                            "output_mode": "content"}, "allow")

    def test_opencode_grep_include_denied(self):
        self.check("grep", {"pattern": "KEY", "path": ".", "include": "*.pem"}, "block")


PLUGIN_ENV = {"CLAUDE_PLUGIN_ROOT": ROOT}


@unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "bin")), "needs the plugin checkout")
class HelperWhitelist(unittest.TestCase):
    def check(self, cmd, expect, env=PLUGIN_ENV):
        with tempfile.TemporaryDirectory() as cwd:
            r = run_guard(pre("Bash", {"command": cmd}), env=env, cwd=cwd)
        self.assertEqual(decision(r), expect, f"{cmd!r}: {r.stdout}")

    def test_subshell_in_helper_args_denied(self):
        self.check("redacted-cat x $(cat .env >/dev/stderr)", "block")

    def test_env_exec_printenv_denied(self):
        self.check("secret-fetch aws prod/db --env-exec -- printenv", "block")
        self.check("secret-fetch aws prod/db --env-exec -- printenv", "block", env=None)

    def test_env_exec_sh_cat_env_denied(self):
        self.check("secret-fetch aws prod/db --env-exec -- sh -c 'cat .env'", "block")

    def test_lookalike_helper_denied(self):
        self.check("./redacted-cat .env", "block")

    def test_bare_helpers_allowed_in_plugin_session(self):
        self.check("secret-fetch aws id --keys", "allow")
        self.check("redacted-cat .env", "allow")
        self.check("secret-fetch aws id --env-exec -- python3 script.py", "allow")

    def test_bare_helper_untrusted_outside_plugin(self):
        self.check("redacted-cat .env", "block", env=None)


class HelperPaths(unittest.TestCase):
    AWS = "aws secretsmanager get-secret-value --secret-id s"

    @unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "bin")), "needs the plugin checkout")
    def test_plugin_session_names_bare_helper(self):
        r = run_guard(pre("Bash", {"command": self.AWS}), env=PLUGIN_ENV)
        self.assertIn("`secret-fetch aws <secret-id>", r.stdout)

    def test_other_installs_name_absolute_helper(self):
        r = run_guard(pre("Bash", {"command": self.AWS}))
        self.assertIn(os.path.join(os.path.abspath(HOOKS), "secret-fetch") + " aws", r.stdout)
        r = run_guard(pre("Bash", {"command": 'op read "op://V/I/password"'}))
        self.assertIn(os.path.join(os.path.abspath(HOOKS), "secret-fetch") + " op", r.stdout)

    def test_no_hardcoded_droid_helper_path(self):
        for base in ("scripts", "skills"):
            for dirpath, _, files in os.walk(os.path.join(ROOT, base)):
                for name in files:
                    with open(os.path.join(dirpath, name), errors="ignore") as f:
                        self.assertNotIn("config/droid/hooks/secret-fetch", f.read(), name)


class PostToolUseShapes(unittest.TestCase):
    def _post(self, tool, response):
        return run_guard({"hook_event_name": "PostToolUse", "tool_name": tool,
                          "tool_input": {}, "session_id": "t", "tool_response": response})

    def test_edit_echo_of_original_file_ignored(self):
        r = self._post("Edit", {"filePath": "/tmp/f", "oldString": "a", "newString": "b",
                                "originalFile": f"a\ntoken: {GHP}\n",
                                "structuredPatch": [{"lines": [f"token: {GHP}"]}],
                                "userModified": False, "replaceAll": False})
        self.assertEqual(r.stdout.strip(), "")

    def test_write_content_ignored(self):
        r = self._post("Write", {"type": "create", "filePath": "/tmp/f",
                                 "content": f"token: {GHP}"})
        self.assertEqual(r.stdout.strip(), "")

    def test_repeated_value_counted_once(self):
        r = self._post("Bash", {"stdout": f"{SK}\n{SK}\nkey={SK}", "stderr": ""})
        self.assertIn("1 secret-like value(s)", r.stdout)


class FailClosed(unittest.TestCase):
    def _raw(self, payload):
        return subprocess.run([sys.executable, GUARD], input=json.dumps(payload),
                              capture_output=True, text=True, env=_env())

    def test_pre_internal_error_denies(self):
        r = self._raw({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": "cat .env"})
        self.assertEqual(r.returncode, 2)
        self.assertEqual(decision(r), "block")
        self.assertIn("internal error", r.stdout)

    def test_post_internal_error_stays_silent(self):
        r = self._raw({"hook_event_name": "PostToolUse", "tool_name": ["x"],
                       "tool_response": {}})
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")

    @unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "extensions")), "needs the plugin checkout")
    def test_claude_hook_wiring(self):
        with open(os.path.join(ROOT, "extensions", "com.anthropic.claude",
                               "hooks.settings.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertEqual(hooks["PreToolUse"][0]["hooks"][0].get("onFailure"), "block")
        self.assertNotIn("onFailure", hooks["PostToolUse"][0]["hooks"][0])
        post = hooks["PostToolUse"][0]["matcher"]
        for tool in ("Bash", "Read", "Grep", "WebFetch", "Task", "mcp__srv__tool"):
            self.assertTrue(re.fullmatch(post, tool), tool)
        for tool in ("Edit", "Write", "MultiEdit", "NotebookEdit", "Glob", "TodoWrite"):
            self.assertFalse(re.fullmatch(post, tool), tool)


class CursorAdapter(unittest.TestCase):
    def run_adapter(self, payload):
        return subprocess.run([sys.executable, ADAPTER], input=json.dumps(payload),
                              capture_output=True, text=True, env=_env())

    def test_pre_tool_use_cat_env_denied(self):
        r = self.run_adapter({"hook_event_name": "preToolUse", "tool_name": "Shell",
                              "tool_input": {"command": "cat .env"}})
        self.assertEqual(r.returncode, 2)
        out = json.loads(r.stdout)
        self.assertEqual(out["permission"], "deny")
        self.assertIn("Blocked", out["agent_message"])

    def test_before_shell_cat_env_denied(self):
        r = self.run_adapter({"hook_event_name": "beforeShellExecution", "command": "cat .env"})
        self.assertEqual(json.loads(r.stdout)["permission"], "deny")

    def test_plain_command_allowed(self):
        r = self.run_adapter({"hook_event_name": "preToolUse", "tool_name": "Shell",
                              "tool_input": {"command": "git status"}})
        self.assertEqual((r.returncode, r.stdout.strip()), (0, ""))

    def test_post_tool_use_leak_adds_context(self):
        r = self.run_adapter({"hook_event_name": "postToolUse", "tool_name": "Shell",
                              "tool_input": {"command": "x"},
                              "tool_output": json.dumps({"stdout": f"key={SK}"})})
        self.assertIn("SECRET GUARD", json.loads(r.stdout)["additional_context"])
        self.assertNotIn(SK, r.stdout)

    @unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "extensions")), "needs the plugin checkout")
    def test_shipped_config_uses_adapter(self):
        with open(os.path.join(ROOT, "extensions", "io.cursor", "hooks.json")) as f:
            hooks = json.load(f)["hooks"]
        for ev, entries in hooks.items():
            for e in entries:
                self.assertIn("cursor_adapter.py", e["command"], ev)


OPENCODE_TS = os.path.join(ROOT, "extensions", "ai.opencode", "plugin", "secret-guard.ts")


@unittest.skipUnless(shutil.which("bun") and os.path.isfile(OPENCODE_TS), "needs bun and the plugin checkout")
class OpencodeAdapter(unittest.TestCase):
    def test_cat_env_and_read_env_blocked_and_leak_appended(self):
        script = f"""
import plugin from {json.dumps(OPENCODE_TS)};
const h = await plugin();
const out: Record<string, string> = {{}};
for (const [key, tool, args] of [["bash", "bash", {{ command: "cat .env" }}],
                                 ["read", "read", {{ filePath: "/tmp/x/.env" }}]] as const) {{
  try {{
    await h["tool.execute.before"]({{ tool, sessionID: "s", callID: "c" }}, {{ args }});
    out[key] = "allowed";
  }} catch (e) {{
    out[key] = String((e as Error).message);
  }}
}}
const o = {{ title: "", output: {json.dumps("key=" + SK)}, metadata: {{}} }};
await h["tool.execute.after"]({{ tool: "bash", sessionID: "s", callID: "c", args: {{ command: "x" }} }}, o);
out.after = o.output;
console.log(JSON.stringify(out));
"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "probe.ts")
            with open(p, "w") as f:
                f.write(script)
            r = subprocess.run(["bun", "run", p], capture_output=True, text=True, env=_env())
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertIn("Blocked", out["bash"])
        self.assertIn("Blocked", out["read"])
        self.assertIn("SECRET GUARD", out["after"])


class ShellGaps(unittest.TestCase):
    def check(self, cmd, expect):
        r = run_guard(pre("Bash", {"command": cmd}))
        self.assertEqual(decision(r), expect, f"{cmd!r}: {r.stdout}")

    def test_names_only_filter_is_per_segment(self):
        self.check("env | cut -d= -f1; env", "block")
        self.check("env | cut -d= -f1 && printenv", "block")
        self.check("env|cut -d= -f1|grep K; env | grep KEY", "block")

    def test_more_content_verbs_and_globs(self):
        for cmd in ("cat .e*", "cat .en?", "sort .env", "od -c .env", "paste .env",
                    "git show HEAD:.env"):
            self.check(cmd, "block")

    def test_quoted_regex_is_not_a_glob(self):
        self.check("grep -E '.*foo' src/app.py", "allow")

    def test_grep_count_on_env_allowed(self):
        self.check("grep -c PORT .env", "allow")
        self.check("grep -c PORT .env | xargs cat", "block")

    def test_env_lookalike_paths_readable(self):
        for path in (".env.local.example", "src/.env.ts", "docs/environment.env.md"):
            r = run_guard(pre("Read", {"file_path": path}))
            self.assertEqual(decision(r), "allow", path)



@unittest.skipUnless(os.path.isfile(os.path.join(ROOT, "install.sh")), "install.sh not shipped in installed copies")
class InstallClaude(unittest.TestCase):
    def test_auto_merge_points_at_real_script(self):
        root = os.path.dirname(os.path.abspath(__file__)) + "/.."
        with tempfile.TemporaryDirectory() as home:
            env = {k: v for k, v in os.environ.items()
                   if not k.endswith("_HOOKS_DIR")}
            env.update(HOME=home,
                       CLAUDE_HOOKS_DIR=os.path.join(home, ".claude", "hooks"))
            os.makedirs(os.path.join(home, ".claude"))
            r = subprocess.run(["bash", os.path.join(root, "install.sh"), "claude"],
                               input="y\n", capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(home, ".claude", "settings.json")) as f:
                hooks = json.load(f)["hooks"]
            for ev in ("PreToolUse", "PostToolUse"):
                cmd = hooks[ev][0]["hooks"][0]["command"]
                script = cmd.split(" ", 1)[1]
                self.assertTrue(os.path.isfile(script), f"{ev}: {cmd}")
                self.assertTrue(script.startswith(home), script)

    def _install(self, home, target="claude"):
        env = {k: v for k, v in os.environ.items() if not k.endswith("_HOOKS_DIR")}
        env.update(HOME=home, CLAUDE_HOOKS_DIR=os.path.join(home, ".claude", "hooks"))
        return subprocess.run(["bash", os.path.join(ROOT, "install.sh"), target],
                              input="y\n", capture_output=True, text=True, env=env)

    def test_unparseable_settings_left_untouched(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(path))
            original = '{"model":"opus","permissions":{"allow":[]},}'
            with open(path, "w") as f:
                f.write(original)
            r = self._install(home)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("cannot parse", r.stderr)
            with open(path) as f:
                self.assertEqual(f.read(), original)

    def test_merge_keeps_keys_and_backup(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as f:
                f.write('{"model": "opus"}')
            r = self._install(home)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["model"], "opus")
            self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"], "block")
            with open(path + ".bak") as f:
                self.assertEqual(f.read(), '{"model": "opus"}')

    def test_custom_dir_leaves_parent_alone(self):
        with tempfile.TemporaryDirectory() as home:
            dest = os.path.join(home, "x", "hooks")
            r = self._install(home, dest)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.isfile(os.path.join(dest, "scripts", "secret_guard.py")))
            self.assertFalse(os.path.exists(os.path.join(home, "x", "hooks.json")))


if __name__ == "__main__":
    unittest.main()
