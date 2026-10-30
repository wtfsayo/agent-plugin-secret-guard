# secret-guard — credential leak prevention for AI agents

> A [Agent Plugins](https://agent-plugins.org) plugin — PreToolUse + PostToolUse hooks + masked-secret helpers that stop AI coding agents from accidentally leaking API keys, passwords, database URLs, and vault contents into chat, commits, files, and command output.

`secret-guard` is a **CLI-agent plugin**: it hooks into agent runtimes via their native extension surfaces (PreToolUse / PostToolUse / `hooks.json` / `settings.json` / `tool.execute.before`) and adds a single enforcement core — one Python hook + thin adapters per client.

Works with **Factory Droid**, **Devin CLI**, **Claude Code**, **opencode**, **Grok CLI**, **Cursor**, **Codex CLI**, and **omp** (oh-my-pi). One `secret_guard.py` core + thin adapters per client.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](scripts/secret_guard.py)

---

## Why

AI agents leak secrets all the time: `cat .env` to debug, `aws secretsmanager get-secret-value` to verify config, `echo $TOKEN` mid-flow, or PostToolUse output forwarding an entire `:password@` URI. Once a value hits the transcript, it ships to your LLM provider, your logs, your teammates' sessions.

`secret-guard` stops it at the hook boundary — not after the fact.

- **PreToolUse blocks** — `cat .env`, `op item get --reveal`, `aws secretsmanager get-secret-value`, `gh auth token`, `kubectl get secret -o yaml`, `security find-generic-password`, `echo $PASSWORD`, plus literal secret-shaped strings in tool arguments or file writes.
- **PostToolUse warns** — if a prior tool's output already leaked something, flag it so the next step doesn't repeat/forward it.
- **Masked helpers** — `secret-fetch` (1Password + AWS Secrets Manager structured/masked reads) and `redacted-cat` (print file contents with values blanked).

## Supported agents

| Agent | Wiring | Coverage |
|---|---|---|
| **Factory Droid** | `com.factory.droid` extension | full Pre + PostToolUse |
| **Devin CLI** | `com.devin.hooks` extension | full Pre + PostToolUse (`exec`, `edit`) |
| **Claude Code** | `.claude-plugin/plugin.json` plugin (hooks from `com.anthropic.claude`), or settings.json merge via `install.sh claude` | Pre: every tool (`Bash`, `Read`, `Grep`, `Write`/`Edit`/`MultiEdit`/`NotebookEdit`, plus a literal-secret scan of all other tool args). Post: `Bash`/`Read`/`Grep`/`WebFetch`/`WebSearch`/`Task`/`Agent`/`mcp__*` |
| **opencode** / **opencode2** | `ai.opencode` TS plugin | `tool.execute.before` blocks; `tool.execute.after` appends the leak warning to the tool output |
| **Grok CLI** | `~/.grok/hooks/secret-guard.json` | `Bash`/`run_terminal_command`/`Shell`/`Read`/`Write`/`Edit`/`MultiEdit` |
| **Cursor** | `~/.cursor/hooks.json` via `cursor_adapter.py` | `preToolUse`, `postToolUse`, `beforeShellExecution`, `beforeReadFile`, `beforeMCPExecution` |
| **Codex CLI** | `~/.codex/hooks.json` | `Bash`/`apply_patch`/`Edit`/`Write`/`MultiEdit`/`Read`/`mcp__*` |
| **omp** (oh-my-pi) | `~/.omp/agent/hooks/pre/secret-guard.ts` factory → `tool_call`/`tool_result` | `bash`/`read`/`write`/`edit`/`ast_edit`/`memory_edit` + literal-secret scan on all tool args |
| Other Agent Plugins clients | `skills/secret-guard/SKILL.md` | behavioral contract (no enforcement) |

## Install

```bash
git clone https://github.com/wtfsayo/agent-plugin-secret-guard.git
cd agent-plugin-secret-guard

./install.sh            # → ~/.config/droid/hooks    (Factory Droid)
./install.sh devin      # → ~/.config/devin/hooks    (Devin CLI)
./install.sh claude     # → ~/.claude/hooks           (Claude Code)
./install.sh opencode   # → ~/.config/opencode/plugin(opencode)
./install.sh grok       # → ~/.grok/hooks             (Grok CLI)
./install.sh cursor     # → ~/.cursor/hooks           (Cursor)
./install.sh codex      # → ~/.codex/hooks            (Codex CLI)
./install.sh omp        # → ~/.omp/agent/hooks       (omp / oh-my-pi)
./install.sh /abs/path  # custom dir (copies scripts; wire the hooks yourself)
```

Each install copies `scripts/` + `tests/` into the target's hooks dir and writes the minimal config that client's loader expects — `hooks.json`, a settings.json merge, or a single-file hook manifest. A merge refuses to touch a config file it cannot parse (it prints the snippet to add by hand and exits non-zero) and keeps the previous file as `<file>.bak`. End user approval is required before the agent's loader will run them on tools that support trust-review (Codex prompts once).

### Claude Code plugin

The repo is also a Claude Code plugin: `.claude-plugin/plugin.json` registers the PreToolUse + PostToolUse hooks from `extensions/com.anthropic.claude/hooks.settings.json`, which run `scripts/secret_guard.py` from the plugin directory, and `bin/` puts `secret-fetch` and `redacted-cat` on the Bash tool's PATH. Use this instead of `./install.sh claude` (not both, or every tool call is checked twice):

```bash
claude --plugin-dir /path/to/agent-plugin-secret-guard   # load for one session
# or, inside Claude Code, install from a marketplace that lists this repo:
# /plugin install secret-guard@<marketplace>
```

## What it catches

| Source | Patterns |
|---|---|
| Vendor tokens | `sk-`, `sk-ant-`, `ghp_/gho_/ghu_/ghs_/ghr_`, `github_pat_`, `xox[abprs]-`, `AKIA|ASIA`, `AIza`, `glpat-`, `npm_`, `pypi-`, `hf_`, `sk/pk/rk_(live|test)_`, `whsec_`, `SG.`, `AC`, `sgp_|sgph_`, `vercel_`, `npm_`, telegram bots, discord, JWT-supabase, private-key PEM blocks |
| Database URIs | `postgres|postgresql|mysql|mongodb(+srv)?|redis|amqp://` with an embedded `user:pass@` segment |
| Generic assignments | `*_API_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `BEARER_TOKEN`, `*_PRIVATE_KEY` (16+ char value) |
| Sensitive paths | `.env` (except `.env.example`/`.sample`/`.template`), `~/.ssh/` (except `config`/`known_hosts`), `~/.aws/credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.zsh_history`, `~/.bash_history`, `~/.python_history`, `~/.docker/config`, `~/.config/gh/hosts.yml`, `*.credentials.json`, `*.secrets.*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `keypair`, `wallet` |
| Sensitive CLIs | `op item … --reveal`, `gh auth token`, `security find-*-password`, `aws secretsmanager get-secret-value` / `ssm get-parameter --with-decryption`, `aws configure get`, `aws sts get-session-token`, `gcloud auth print-*-token`, `vercel env`, `railway variables`, `fly secrets`, `heroku config`, `vault read/kv get`, `doppler secrets`, `kubectl get secrets -o yaml/json`, `docker inspect/exec env`, `solana config get`, `solana-keygen`, plus `cat|head|tail|grep|rg|xxd|strings` of any sensitive path |

The curated list has 26 high-confidence and 2 medium-confidence rules. On top of that, 213 gitleaks rules run (221 synced from gitleaks, 8 quarantined for false positives on ordinary code); each runs only when one of its gitleaks keywords appears in the text. Detect what leaks, refuse it, instruct the agent to use a masked helper instead.

## How it works

**PreToolUse** — emits `permissionDecision: deny` (or exits `2`) before the tool runs. The agent sees a `Blocked:` reason that names a rescue helper (`redacted-cat` for file reads, `secret-fetch` for vault stores, `op run`/`inject` for 1Password flows, `environment-variable` for literals). A Read is judged on the lines it will return (`offset`/`limit`), and a blocked Read lists the offending line numbers so the agent can read around them. A Grep is blocked when it would print lines (`output_mode: content` or `-A/-B/-C`) from a sensitive path or glob.

**PostToolUse** — scans the first 256 KB of tool output for the same patterns and emits `additionalContext` (a system-message warning) so the next step doesn't quote the leak. Edit/Write responses are skipped: they echo file content the model did not read.

**Failure policy** — a security hook that times out lets the tool run, so the guard keeps its own 5 s scan budget. PreToolUse fails closed: a scan over budget or an internal error denies the call with a way forward, and the Claude Code hook sets `"onFailure": "block"` (Cursor: `failClosed: true`) so a crash or missing `python3` blocks too. PostToolUse fails open (the output already exists) and warns when it could not finish. Tracebacks go to `secret_guard.log` in `$CLAUDE_PLUGIN_DATA`, or `~/.cache/secret-guard/` for other clients.

**Tool-name adapters** — each client calls its tools differently (`Execute`, `Bash`, `Shell`, `run_terminal_command`, `exec`, `apply_patch`, `edit`, `fs_write`, `str_replace_editor`). `_tool_family()` maps them to `shell`/`read`/`write`/`grep`, so the same rules fire once per family, not once per name; any other tool gets the literal-secret scan on its arguments.

## Repo structure

```
plugin.json
├── .claude-plugin/plugin.json   (Claude Code plugin manifest)
├── bin/                         (secret-fetch, redacted-cat wrappers on the Claude Code PATH)
├── extensions/
│   ├── com.factory.droid/hooks.json
│   ├── com.devin.hooks/hooks.json
│   ├── com.anthropic.claude/hooks.settings.json
│   ├── ai.opencode/plugin/secret-guard.ts
│   ├── ai.xai.grok/…
│   ├── io.cursor/hooks.json + scripts/cursor_adapter.py
│   └── ai.openai.codex/hooks.json
├── skills/secret-guard/SKILL.md
├── scripts/
│   ├── secret_guard.py
│   ├── secret_patterns.py
│   ├── gitleaks_patterns.py (generated by sync_gitleaks.py)
│   ├── sync_gitleaks.py
│   ├── secret-fetch
│   ├── redacted-cat
│   └── cursor_adapter.py
├── install.sh
└── tests/test_secret_guard.py
```

## Customizing for your org

Add company-specific secret prefixes to `scripts/secret_patterns.py` `HIGH_CONFIDENCE` — one `(name, regex)` tuple per pattern. Anything that leaked before the guard existed is fixable via `redacted-cat` (print with secrets masked).

`scripts/gitleaks_patterns.py` is generated; change `scripts/sync_gitleaks.py` instead. It pins a gitleaks release (`GITLEAKS_REF`) and rewrites its RE2 regexes for Python's backtracking engine:

```bash
python3 scripts/sync_gitleaks.py                # fetch the pinned gitleaks.toml and regenerate
python3 scripts/sync_gitleaks.py --toml FILE    # regenerate offline from a local copy
python3 scripts/sync_gitleaks.py --check        # exit 1 if the committed file is stale
```

## Verifying

```bash
python3 -m unittest discover -s tests
```

Targeted real-world coverage checks (CI-friendly):

- `cat .env` → exit 2 + `permissionDecision: deny`
- `aws secretsmanager get-secret-value` → deny (captured into `SECRET=$(...)` is allowed)
- `op item get x --fields password` → deny (`--fields username` is allowed)
- `env | cut -d= -f1` → allowed (names only, not values)
- `Read .env` → deny
- `Grep` with `output_mode: content` on `.env` → deny (`files_with_matches` is allowed)
- Write a `sk-proj-…` literal → deny

## Disable

```bash
export SECRET_GUARD=off           # every client
export DROID_SECRET_GUARD=off     # legacy name, still honored
export DEVIN_SECRET_GUARD=off     # legacy name, still honored
```

For SKILL.md-only installs (clients without a hook surface), the behavioral contract applies but can't be disabled by env — it's agent instructions, not enforced code.

## License

MIT — see [LICENSE](LICENSE). `scripts/gitleaks_patterns.py` contains rules derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, Copyright (c) 2019 Zachary Rice); the notice is in the file header.
