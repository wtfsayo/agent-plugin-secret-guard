#!/usr/bin/env python3
"""Tests for secret_guard.py, secret-fetch, and redacted-cat.
Drives the hook as a subprocess with JSON stdin. Synthetic secrets only.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HOOKS = "/Users/studio/.config/droid/hooks"
GUARD = os.path.join(HOOKS, "secret_guard.py")
FETCH = os.path.join(HOOKS, "secret-fetch")
RCAT = os.path.join(HOOKS, "redacted-cat")

# Synthetic placeholders, not real credentials.
SK = "sk-" + "Ab3dEf9Gh8Jk2Mn4qRs6TuVwXy" + "Zz0123456789"   # 42 chars, lowercase digits tail
GHP = "ghp_" + "Ab3dEf9" * 6            # 42 chars
WHSEC = "whsec_" + "Zx9Qw8Er7Ty6Ui5O" * 2 + "As4Df6Gh"   # 46 chars
PGURL = "postgres" + "://" + "u" + ":" + "p4ssw0rdXYZ123" + "@" + "host/db"


def run_guard(payload, env_off=False):
    env = dict(os.environ)
    if env_off:
        env["DEVIN_SECRET_GUARD"] = "off"
    r = subprocess.run(
        ["python3", GUARD], input=json.dumps(payload),
        capture_output=True, text=True, env=env,
    )
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
                   "/Users/studio/.opencodex/config.json'))\"", "block")
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


if __name__ == "__main__":
    unittest.main()
