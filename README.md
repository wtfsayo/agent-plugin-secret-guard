# agent-plugin-secret-guard

An [Agent Plugins](https://agent-plugins.org) plugin that keeps secret values — API keys, passwords, bearer tokens, webhook signing secrets, connection strings, vault contents — out of agent sessions.

It does this three ways:

1. **PreToolUse hooks** — blocks commands that would print secrets (`cat .env`, `op item get --reveal`, `aws secretsmanager get-secret-value`, `gh auth token`, `kubectl get secret -o yaml`, `security find-generic-password`, `echo $PASSWORD`, plus literal secret-shaped strings in command input or file writes).
2. **PostToolUse hooks** — warns when a previous tool's output leaked a secret-shaped value so the next step doesn't repeat/forward it.
3. **Masked helpers** — `secret-fetch` (1Password + AWS Secrets Manager structure/masked reads) and `redacted-cat` (print file contents with values blanked) so you can inspect credentials without leaking the bytes.

## Contents

```
plugin.json
├── extensions/
│   ├── com.factory.droid/hooks.json   # Factory Droid hooks (PreToolUse/PostToolUse)
│   └── com.devin.hooks/hooks.json     # Devin CLI hooks (same contract)
├── skills/secret-guard/SKILL.md       # behavioral instructions when hooks aren't available
├── scripts/
│   ├── secret_guard.py                # the Pre/PostToolUse hook itself
│   ├── secret_patterns.py             # regex bank: GitHub/Slack/AWS/Google/OpenAI/Anthropic/Stripe/SendGrid/…
│   │                                    plus PopPay- and Cross-Switch-specific prefixes (pp_sk_*, CS_*,
│   │                                    paywall_secret_key=, URL-embedded credentials)
│   ├── secret-fetch                   # `op item` + `aws secretsmanager` masked inspector
│   └── redacted-cat                   # file printer that replaces secrets with <redacted:…>
├── install.sh                         # installs scripts + optional hooks.json into a config dir
└── tests/test_secret_guard.py         # pattern coverage checks
```

## Install

```bash
git clone git@github.com:wtfsayo/agent-plugin-secret-guard.git
cd agent-plugin-secret-guard
./install.sh            # targets ~/.config/droid/hooks
./install.sh devin      # targets ~/.config/devin/hooks
./install.sh /abs/path  # custom config dir
```

`install.sh` drops the scripts + tests into the hooks dir and writes a `hooks.json` next to it if you don't have one already. Hook wiring lives in `extensions/com.factory.droid/hooks.json` / `extensions/com.devin.hooks/hooks.json` and references the plugin's `scripts/` dir via `${plugin.dir}` so loaders that support the Agent Plugins client-extension hook contract can wire it without `install.sh`.

## What it catches

| Source | Patterns |
|---|---|
| Vendor tokens | `sk-`, `sk-ant-`, `ghp|gho|ghu|ghs|ghr_`, `github_pat_`, `xox[abprs]-`, `AKIA|ASIA`, `AIza`, `glpat-`, `npm_`, `pypi-`, `hf_`, `sk/pk/rk_(live|test)_`, `whsec_`, `SG.`, `AC`, telegram, vercel_, discord, JWT-looking supabase, private-key blocks |
| PopPay / Cross-Switch | `pp_sk_(sbx|live)_*`, `pp_(sbx|live)_key_*`, `CS_[A-Za-z0-9_-]+` (APICaller-derived), `paywall_secret_key=` |
| DB URIs | `postgres|mysql|mongodb|redis|amqp` URIs with an embedded `user:pass@` segment |
| Generic | `*_API_KEY=*`, `*_SECRET=*`, `*_TOKEN=*`, `*_PASSWORD=*`, `bearer_token=` (with entropy filter) |
| Sensitive files | `.env` (not `.env.example/sample/template/test`), `~/.ssh/*` sans `config`/`known_hosts`, `~/.aws/credentials`, `~/.netrc`, `~/.zsh_history`, `~/.bash_history`, `~/.git-credentials`, `*.credentials.json`, `*.secrets.*`, `id_rsa`/`id_ed25519` private keys |
| Sensitive CLIs | `op item … --reveal`, `gh auth token`, `security find-generic-password`, `aws secretsmanager get-secret-value` / `ssm get-parameter --with-decryption`, `aws configure get`, `aws sts get-session-token`, `gcloud auth print-*-token`, `vercel env`, `railway variables`, `fly secrets`, `heroku config`, `vault read`, `doppler secrets`, `kubectl … secret -o yaml`, `solana config get`, `docker … env`, `cat|head|grep` of files above |

The blocking behavior:

- **PreToolUse** — emits `permissionDecision: deny` JSON (or exits non-zero) before the command runs. The agent sees a "Blocked:" reason telling it which helper to use instead.
- **PostToolUse** — scans output for the same patterns and emits a warning ("previous tool output contained N secret-like value(s)") so the next step doesn't quote them back.

## Customizing for your org

Add org-specific prefixes to `scripts/secret_patterns.py` in `HIGH_CONFIDENCE` — one line per `(name, regex)` tuple. The ones already there (`poppay_api_key`, `cross_switch_caller`, `poppay_key`, `paywall_secret`, `generic_url_password`) are examples you can seed from. For anything that slipped before the guard existed, `redacted-cat` is the escape hatch.

## Disable

`export DROID_SECRET_GUARD=off` (or `DEVIN_SECRET_GUARD=off` for the older guard install) bypasses the hook. See `skills/secret-guard/SKILL.md` — the behavioral contract applies even without hooks.
