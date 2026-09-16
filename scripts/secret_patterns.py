"""Shared secret-detection patterns for the Devin CLI secret guard.

Stdlib only. Patterns ported from ~/.local/share/devin/secret-audit/scan.py.
Never prints or returns full secret values to the user — use mask().
"""
import os
import re

# Optional: full Gitleaks rule catalog if the bundled module is present.
# Sync it with `python3 scripts/sync_gitleaks.py`.
try:
    from gitleaks_patterns import GITLEAKS_PATTERNS as _GITLEAKS
except ImportError:
    _GITLEAKS = []

# High-confidence patterns: every scan.py PATTERNS entry except the two
# medium-confidence ones (bearer_token, generic_assignment).
HIGH_CONFIDENCE = [
    ("openai_key",        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    ("anthropic_key",     r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("github_token",      r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
    ("github_pat",        r"\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("slack_token",       r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("aws_access_key",    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("google_api_key",    r"\bAIza[0-9A-Za-z_\-]{35}"),
    ("gitlab_pat",        r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    ("npm_token",         r"\bnpm_[A-Za-z0-9]{36,}"),
    ("pypi_token",        r"\bpypi-[A-Za-z0-9_\-]{50,}"),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}"),
    ("stripe_key",        r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("stripe_webhook",    r"\bwhsec_[A-Za-z0-9]{30,}"),
    ("sendgrid_key",      r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("twilio_sid",        r"\bAC[a-f0-9]{32}\b"),
    ("telegram_bot",      r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}"),
    ("discord_token",     r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
    ("vercel_token",      r"\bvercel_[A-Za-z0-9]{24,}"),
    ("supabase_jwt",      r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("db_url_with_pw",    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{4,}@[^\s'\"]+"),
    ("generic_url_password", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'\")]+:[^\s@'\")]{8,}@[^\s'\")]+"),
    ("eth_private_key",   r"\b0x[a-fA-F0-9]{64}\b"),
    ("solana_b58_key",    r"\b[1-9A-HJ-NP-Za-km-z]{87,88}\b"),
    ("solana_byte_array", r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]"),
]

MEDIUM_CONFIDENCE = [
    ("bearer_token",      r"\b[Bb]earer\s+[A-Za-z0-9_\-\.=]{24,}"),
    ("generic_assignment",r"(?i)\b[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|AUTH|CREDENTIAL)[A-Z0-9_]*\s*[=:]\s*[\"']?([A-Za-z0-9_\-/+.=]{16,})[\"']?"),
]

_HIGH = [(n, re.compile(p)) for n, p in HIGH_CONFIDENCE]
_MED = [(n, re.compile(p)) for n, p in MEDIUM_CONFIDENCE]

# Gitleaks rules that fire on ambient code (env-var reads, describe-secret
# calls, config-file hydration) rather than literals — quarantined so the
# curated and other gitleaks rules still trigger.
_GITLEAKS_QUARANTINE = frozenset({
    "generic-api-key",
    "sidekiq-sensitive-url",
    "curl-auth-header",
    "curl-auth-user",
    "jwt",
    "jwt-base64",
    "kubernetes-secret-yaml",
    "nuget-config-password",
})

import warnings as _warnings

_GITLEAKS_COMPILED = []
for _n, _p in _GITLEAKS:
    if _n in _GITLEAKS_QUARANTINE:
        continue
    try:
        with _warnings.catch_warnings():
            _warnings.simplefilter("ignore", FutureWarning)
            _GITLEAKS_COMPILED.append((_n, re.compile(_p)))
    except re.error:
        pass

# Placeholder / example values to skip
PLACEHOLDER = re.compile(r"(?i)(your[_-]?|example|placeholder|xxx+|redacted|<[^>]+>|\$\{|\.\.\.|changeme|dummy|test_?key|test[-_]?token|fake|sample|mock|lorem|deadbeef|sk-ant-api03-\.\.\.|0x0{20,}|0x1{20,}|abcdef0123|1234567890abcdef|0123456789abcdef)")

def _home():
    """Computed lazily so test/CI can override HOME before path checks run."""
    return os.path.abspath(os.path.expanduser("~"))


def _norm_path(tok, home=None):
    base = home if home is not None else _home()
    if tok.startswith("$HOME"):
        tok = base + tok[5:]
    elif tok.startswith("~"):
        tok = base + tok[1:]
    return os.path.abspath(tok)

# Matched against the expanded, normalized (abspath) path.
def _sensitive_path_regex():
    home = _home()
    return re.compile(
        r"(?:"
        r"\.env(?:\.(?!example$|sample$|template$|test$)[^/]*)?$"
        r"|" + re.escape(home) + r"/\.(?:zshrc|zshenv|zprofile|bashrc|bash_profile|profile)$"
        r"|" + re.escape(home) + r"/\.ssh/(?!config$|known_hosts)[^/]+$"
        r"|" + re.escape(home) + r"/\.aws/credentials$"
        r"|" + re.escape(home) + r"/\.(?:netrc|npmrc|pypirc|git-credentials)$"
        r"|" + re.escape(home) + r"/\.(?:zsh_history|bash_history|python_history)$"
        r"|" + re.escape(home) + r"/\.docker/config\.json$"
        r"|" + re.escape(home) + r"/\.config/gh/hosts\.yml$"
        r"|" + re.escape(home) + r"/\.cursor/mcp\.json$"
        r"|" + re.escape(home) + r"/\.claude\.json$"
        r"|" + re.escape(home) + r"/\.opencodex/config\.json$"
        r"|" + re.escape(home) + r"/\.pi/agent/models\.json$"
        r"|" + re.escape(home) + r"/\.hermes/"
        r"|\.(?:pem|key|p12|pfx)$"
        r"|(?:^|/)id_(?:rsa|ed25519)"
        r"|keypair[^/]*\.json$"
        r"|/(?:credentials|auth|secrets)\.json$"
        r"|/\.git-credentials$"
        r"|\.secrets\.[^/]+$"
        r")"
    )


def sensitive_path_re():
    """Per-call regex so tests can override os.environ['HOME'] between calls."""
    return _sensitive_path_regex()

# A pipeline containing one of these prints env var NAMES only, not values.
NAMES_ONLY_FILTER = re.compile(
    r"cut\s+-d=\s+-f\s*1"
    r"|sed\s+['\"]s/=\.\*//"
    r"|awk\s+-F=\s+['\"]\{print\s+\$1\}"
    r"|grep\s+-o\s+['\"]\^\[A-Za-z_\]\*"
)

# Commands whose OUTPUT is likely to dump secrets (ported from scan.py,
# with ~/.ssh/ excluding config/known_hosts and bare-env split out).
LEAKY_CMD = re.compile(
    r"(?x)(?:^|[;&|]\s*|\bsudo\s+)\s*(?:"
    r"(?:cat|bat|less|more|head|tail|tac|nl|strings|xxd|hexdump)\s+(?!>{1,2}\s)[^;|&\n]*(?:\.env(?!\.example|\.sample|\.template)|\bcredentials(?:\.json|\.ya?ml|/|\s|$)|secrets?\.(?:json|ya?ml|toml|env|txt|properties|ini)\b|[._]secrets?\.|auth\.json|\.netrc|\.npmrc|\.pypirc|id_rsa|id_ed25519|\.pem\b|\.key\b|keypair|wallet|\.aws/|\.ssh/(?!config\b|known_hosts)|\.docker/config|\.git-credentials|\.zshrc|\.bashrc|\.zshenv|\.profile|\.hermes/|\.config/gh/hosts\.yml|\.zsh_history|\.bash_history|\.python_history)"
    r"|printenv\s+\S*(?:KEY|SECRET|TOKEN|PASS)"
    r"|echo\s+[\"']?\$\{?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASS|PRIVATE|CREDENTIAL)[A-Z0-9_]*"
    r"|gh\s+auth\s+token|gh\s+auth\s+status\s+.*--show-token"
    r"|security\s+find-(?:generic|internet)-password"
    r"|aws\s+(?:configure\s+(?:get\b|export-credentials\b)|sts\s+get-session-token"
    r"|ssm\s+get-parameters?(?:-by-path)?\b[^;|&]*--with-decryption)"
    r"|gcloud\s+auth\s+print-(?:access|identity)-token"
    r"|vercel\s+env\s+(?:pull|ls|get)|railway\s+variables|fly\s+secrets\s+list|heroku\s+config"
    r"|vault\s+(?:read|kv\s+get)|doppler\s+secrets"
    r"|docker\s+(?:inspect|exec\s+.*\benv\b)"
    r"|kubectl\s+get\s+secret[s]?\s+.*-o\s+(?:yaml|json)"
    r"|solana\s+config\s+get|solana-keygen\s+(?:pubkey|recover)"
    r"|(?:jq|python3?|node)\b[^;|&\n]*(?:\.env\b|secrets?\.json|credentials\.json|keypair|id\.json)"
    r"|grep\s+[^;|&\n]*(?i:KEY|SECRET|TOKEN|PASSWORD)[^;|&\n]*(?:\.env\b|\.zshrc|\.zshenv|\.bashrc|\.profile|\.hermes|mcp\.json|config\.(?:ya?ml|json|toml))"
    r"|(?:curl|wget|http)\b[^;|&\n]*(?:read_secrets|write_secrets|git_credentials|list_secrets)"
    r")"
)

# Bare env-dump commands: leaky only when the same pipeline does NOT contain
# a names-only filter (NAMES_ONLY_FILTER).
BARE_ENV_CMD = re.compile(r"(?:^|[;&|]\s*|\bsudo\s+)\s*(?:printenv|env|export\s+-p|set)\s*(?:$|[|;&])")

# Verbs that read/copy file content (ls/stat/test/chmod/rm/wc are NOT here:
# touching a sensitive path's metadata is fine, reading it is not).
_CONTENT_VERB = re.compile(
    r"\b(?:cat|bat|less|more|head|tail|tac|nl|strings|xxd|hexdump|grep|rg|ag|"
    r"awk|sed|cut|jq|yq|python3?|node|ruby|perl|diff|cmp|base64)\b|open\("
)
# Path-like tokens: ~/…, $HOME/…, /abs/…, ./…/.hidden, or relative a/b.
_PATH_TOKEN = re.compile(
    r"~/[^\s'\"`$;|&()>]+|\$HOME[^\s'\"`$;|&()>]*|/[A-Za-z0-9_.\-/]+|"
    r"(?<![\w/])\.[A-Za-z0-9_.\-/]+|(?<![\w/.-])[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+"
)


def _resolve_tilde(path, home):
    """Expand `~` / `$HOME` against a possibly-overridden HOME. Minus the
    os.path.expanduser call sites so tests that set HOME behave correctly."""
    if path.startswith("~/"):
        return home + path[1:]
    if path.startswith("$HOME"):
        return home + path[5:]
    return path


def references_sensitive_path(cmd):
    """True when a content-reading verb and a sensitive path share a segment."""
    sen = _sensitive_path_regex()
    home = _home()
    for seg in re.split(r";|&&|\|\||\n", cmd):
        if not _CONTENT_VERB.search(seg):
            continue
        for m in _PATH_TOKEN.finditer(seg):
            resolved = _resolve_tilde(m.group(0), home)
            if sen.search(_norm_path(resolved)):
                return True
    return False


def is_leaky_cmd(cmd):
    if LEAKY_CMD.search(cmd):
        return True
    # Bare-env test runs on quote-stripped text so `|env|` inside a quoted
    # grep pattern doesn't trip it (ssh remotes are re-checked below anyway).
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", cmd)
    if BARE_ENV_CMD.search(unquoted) and not NAMES_ONLY_FILTER.search(cmd):
        return True
    if references_sensitive_path(cmd):
        return True
    # `ssh host '<cmd>'` is leaky if the remote command itself is.
    for m in re.finditer(r"\bssh\s+[^;|&]*?(['\"])(.*?)\1", cmd):
        if is_leaky_cmd(m.group(2)):
            return True
    return False


def _accept(name, val):
    """scan.py's per-pattern filtering (placeholders, entropy checks)."""
    if name == "private_key_block":
        return True
    if PLACEHOLDER.search(val):
        return False
    if name == "generic_assignment":
        # require some entropy: letters + digits, not a path/URL/word
        if not (re.search(r"\d", val) and re.search(r"[A-Za-z]", val)) or "/" in val[:1] or val.lower() in ("true", "false"):
            return False
        if len(set(val)) < 8:
            return False
    if name == "solana_b58_key" and not re.search(r"\d", val):
        return False
    if name == "bearer_token":
        if not (re.search(r"\d", val) and re.search(r"[A-Za-z]", val)):
            return False
        if val[0] in "${<":
            return False
    return True


def find_secrets(text, include_medium=False):
    """Return [(kind, value), ...] for secret-like values in text."""
    pats = _HIGH + (_MED if include_medium else [])
    out = []
    # Secrets nested in JSON-in-JSON arrive as \"password\":\"…\"; unescape so
    # the quote-sensitive patterns can see them.
    if '\\"' in text:
        text = text + "\n" + text.replace('\\"', '"').replace("\\/", "/")
    for name, rx in pats:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if _accept(name, val):
                out.append((name, val))
    # Gitleaks catalog coverage (broader than curated list, rules use (?i) prefix).
    for name, rx in _GITLEAKS_COMPILED:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if val and _accept_gitleaks(val):
                out.append((name, val))
                break  # one hit per rule is enough signal
    return out


def _accept_gitleaks(val):
    """Keep high-fidelity gitleaks hits: deny placeholders, short/i-doubt-it values."""
    if not val or len(val) < 6:
        return False
    if PLACEHOLDER.search(val):
        return False
    # don't flag pure punctuation/regex soup
    if len(set(val)) < 4:
        return False
    return True


def mask(value, kind):
    v = value.strip()
    return f"{v[:4]}…{v[-2:]} ({kind}, len={len(v)})"


# PostToolUse heuristic: catches `op` / secretsmanager JSON dumps whose values
# have no fixed prefix, e.g. {"password": "hunter2abc"}.
KV_SECRET_LINE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential)[\"']?\s*[:=]\s*[\"']?([^\s\"',]{8,})"
)


def find_kv_secrets(text):
    out = []
    if '\\"' in text:
        text = text + "\n" + text.replace('\\"', '"')
    for m in KV_SECRET_LINE.finditer(text):
        val = m.group(2)
        if PLACEHOLDER.search(val):
            continue
        if not (re.search(r"\d", val) and re.search(r"[A-Za-z]", val)):
            continue
        if len(set(val)) < 8:
            continue
        if re.search(r"[(\[${<]", val):
            continue
        if val.startswith(("os.", "process.", "env")):
            continue
        out.append(("kv_secret", val))
    return out


_AWS_ALLOW = {
    "list-secrets", "describe-secret", "list-secret-version-ids",
    "get-resource-policy", "tag-resource", "update-secret-version-stage",
    "rotate-secret", "delete-secret", "restore-secret", "cancel-rotate-secret",
}
_AWS_GET = {"get-secret-value", "batch-get-secret-value"}
_AWS_PUT = {"put-secret-value", "update-secret", "create-secret"}

AWS_GET_REASON = (
    "Blocked: `aws secretsmanager get-secret-value` would print secret values "
    "into the session. Use `~/.config/droid/hooks/secret-fetch aws <secret-id> "
    "[--version-id V] [--profile P] [--region R]` with `--keys` (key names), "
    "`--len`, `--hash` (sha256 prefix per key, for comparing versions), "
    "`--shape KEY` (value with the secret parts masked, e.g. "
    "postgres://user:<redacted>@host/db), `--masked-json`, or `--env-exec -- "
    "<cmd>` to run a command with the keys exported as env vars without "
    "revealing them. Or capture silently: `VAR=$(aws … --query SecretString "
    "--output text)` and never echo it. Inside Python use `secret-fetch aws "
    "<id> --env-exec -- python3 script.py` and read os.environ."
)

OP_REASON = (
    "Blocked: `op` would print secret values into the session. Capture "
    "silently: `PASS=$(op read \"op://Vault/Item/password\")` then pass "
    "`\"$PASS\"` to the program (echo only `${#PASS}`); inspect an item's "
    "structure with `~/.config/droid/hooks/secret-fetch op <item> [--vault V]` "
    "(labels, types, masked values); or use `op run --env-file .env.tpl -- "
    "<cmd>` / `op inject -i tpl -o file`."
)

LITERAL_REASON = (
    "Blocked: secret literal in command. Pass `--secret-string file://path` "
    "or `\"$VAR\"`; build the new JSON with `secret-fetch aws <id> --env-exec "
    "-- python3 rotate.py` reading os.environ."
)

_SEG_SPLIT = re.compile(r";|&&|\|\||\n")
_CAPTURE_RE = re.compile(r"([A-Za-z_]\w*)\s*=\s*(?:\$\(|`)")


def _captures(cmd):
    """Yield (varname, body_start, body_end) for VAR=$( … ) / VAR=` … `."""
    for m in _CAPTURE_RE.finditer(cmd):
        var = m.group(1)
        if cmd[m.end() - 1] == "(":
            depth, i = 1, m.end()
            while i < len(cmd) and depth:
                if cmd[i] == "(":
                    depth += 1
                elif cmd[i] == ")":
                    depth -= 1
                i += 1
            yield var, m.end(), i - 1
        else:
            j = cmd.find("`", m.end())
            yield var, m.end(), j if j != -1 else len(cmd)


def _var_revealed(cmd, var):
    v = re.escape(var)
    if re.search(r"\b(?:echo|printf)\b[^;\n|]*\$(?:\{(?!#)|)" + v + r"\b", cmd):
        return True
    if re.search(r"print\([^)]*(?:\b" + v + r"\b|\{" + v + r"\})", cmd):
        return True
    if re.search(r"os\.environ\[['\"]" + v + r"['\"]\]", cmd):
        return True
    if re.search(r"process\.env\." + v + r"\b", cmd):
        return True
    if re.search(r"\|\s*tee\b", cmd):
        return True
    # cat <<EOF heredoc bodies interpolate $VAR
    if re.search(r"\bcat\s*<<", cmd) and re.search(r"\$\{?" + v + r"\b", cmd):
        return True
    return False


def _captured_ok(seg, needle_re, whole_cmd):
    """True iff every needle_re match in seg sits inside a VAR=$(…) capture and
    no captured variable is echoed/printed/teed anywhere in whole_cmd."""
    caps = list(_captures(seg))
    if not caps:
        return False
    for m in re.finditer(needle_re, seg):
        if not any(start <= m.start() < end for _, start, end in caps):
            return False
    return all(not _var_revealed(whole_cmd, var) for var, _, _ in caps)


# List-form invocation inside python/node subprocess calls:
# ["aws","secretsmanager","get-secret-value", …]
_AWS_LIST_RE = re.compile(
    r"[\"']aws[\"']\s*,\s*[\"']secretsmanager[\"']\s*,\s*[\"']([a-z-]+)[\"']"
)


def _aws_check(cmd):
    for seg in _SEG_SPLIT.split(cmd):
        # List form (subprocess.run(["aws","secretsmanager",…])) is never a
        # silent shell capture — get/list calls are judged directly.
        for lm in _AWS_LIST_RE.finditer(seg):
            sub = lm.group(1)
            if sub in _AWS_GET:
                return AWS_GET_REASON
            if sub in _AWS_PUT and find_secrets(seg):
                return LITERAL_REASON
        m = re.search(r"\baws\s+secretsmanager\s+([a-z-]+)", seg)
        if not m:
            continue
        sub = m.group(1)
        if sub in _AWS_ALLOW:
            continue
        if sub in _AWS_GET:
            if _captured_ok(seg, r"aws\s+secretsmanager\s+(?:get-secret-value|batch-get-secret-value)", cmd):
                continue
            return AWS_GET_REASON
        if sub in _AWS_PUT:
            sm = re.search(
                r"--secret-(?:string|binary)\s*(?:=\s*)?(\"[^\"]*\"|'[^']*'|\S+)", seg
            )
            if sm:
                val = sm.group(1).strip("'\"")
                if not (val.startswith("$") or val.startswith("file://")
                        or val.startswith("fileb://")):
                    return LITERAL_REASON
                if val.startswith("$"):
                    continue
            if find_secrets(seg):
                return LITERAL_REASON
    return None


def _op_check(cmd):
    for seg in _SEG_SPLIT.split(cmd):
        m = re.search(r"\bop\s+([a-z]+)(?:\s+([a-z]+))?", seg)
        if not m:
            continue
        sub, sub2 = m.group(1), m.group(2) or ""
        if sub in ("whoami", "signin", "account", "vault", "run", "completion"):
            continue
        if sub == "inject":
            if re.search(r"(?:-o\b|--out-file\b)", seg):
                continue
            if _captured_ok(seg, r"op\s+inject", cmd):
                continue
            return OP_REASON
        if sub == "document" and sub2 == "get":
            if re.search(r"(?:-o\b|--out-file\b)", seg):
                continue
            if _captured_ok(seg, r"op\s+document\s+get", cmd):
                continue
            return OP_REASON
        if sub == "item":
            if sub2 == "list":
                continue
            if sub2 in ("create", "edit"):
                # literal values like password=hunter2 on the CLI
                lm = re.search(
                    r"\b(?:password|secret|token|credential)\w*=(\"[^\"]*\"|'[^']*'|[^\s]+)",
                    seg, re.I,
                )
                if lm and not lm.group(1).strip("'\"").startswith("$"):
                    return LITERAL_REASON
                continue
            if sub2 == "get":
                # --fields with only non-secret fields is safe to print.
                fms = re.findall(
                    r"--fields\s*(?:=\s*)?(\"[^\"]*\"|'[^']*'|[^\s\"')]+)", seg
                )
                if fms:
                    safe = {"username", "email", "url", "website",
                            "label=username", "label=email", "label=url"}
                    fields = [f.strip().strip("'\"")
                              for grp in fms for f in grp.split(",")]
                    if fields and all(f in safe for f in fields):
                        continue
                if _captured_ok(seg, r"op\s+item\s+get", cmd):
                    continue
                return OP_REASON
            continue
        if sub == "read":
            if _captured_ok(seg, r"op\s+read", cmd):
                continue
            return OP_REASON
    return None


def check_secret_cli(cmd):
    """Dedicated AWS Secrets Manager / 1Password op checker.
    Returns a block reason string, or None."""
    return _aws_check(cmd) or _op_check(cmd)