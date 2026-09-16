---
name: secret-guard
description: Keep secret values out of agent sessions. Applies whenever the agent handles credentials — API keys, passwords, tokens, connection strings, webhook signing secrets, 1Password/AWS-secrets-manager/cloud vault retrieval, or any file that may contain secrets (.env, credentials.json, ~/.ssh, ~/.aws, ~/.netrc, ~/.zshrc/history, MCP config).
---

# Secret Guard

The single goal: **never let a secret value land in chat, files, commit messages, logs, or downstream tool calls.** Usernames and identifiers are fine; the credential bytes are not.

## Core rule

Secrets may be *retrieved*, *used*, and *stored* — but never *printed*. Always move them as opaque references: environment variables, `op://` pointers, `secret-fetch` masked reads, or direct piping into a tool that consumes them without echo.

## What "printing" includes

- `cat`, `head`, `tail`, `jq`, `python3 -c`, `node -e`, `grep`, `awk` output that contains a secret value
- `op item get … --reveal`, `op item get … --fields password`, `aws secretsmanager get-secret-value`, `gh auth token`, `security find-generic-password`, `vault read`, `doppler secrets`, `kubectl get secret -o yaml`, `vercel env pull`, `railway variables`, `fly secrets list`, `heroku config`
- `echo "$PASS"`, `printenv $KEY`, `env` with no `cut -d= -f1`
- `Read`/`Edit`/`Create` of files known to contain secrets, or `Edit` `new_str` carrying a literal secret
- Browser automation that evaluates or screenshot-reveals a password/secret
- Connection strings that embed a password between the `://` and `@` delimiters — database URIs, AMQP/Redis URLs, proxies — count the whole embedded credential

## What to do instead

### Inspect a credential store without leaking

```bash
~/.config/{droid,devin}/hooks/secret-fetch op   <item_id> [--vault V]   # labels, types, masked values
~/.config/{droid,devin}/hooks/secret-fetch aws  <secret-id> [--keys|--len|--hash|--masked-json|--shape KEY|--env-exec -- CMD]
~/.config/{droid,devin}/hooks/redacted-cat     <file> [-n START,END]     # file content with secrets masked
```

### Pull a value without printing it

```bash
PASS=$(op read "op://Vault/Item/field")              # never echo it
some-cli --password "$PASS"                          # pass through, don't display
echo "len=${#PASS} first3=${PASS:0:3}"               # describe, don't reveal
USER=$(op read "op://Vault/Item/username")           # usernames are fine to print
```

For 1Password specifically, `op item get --fields username` and `op item list` (titles only) are safe to print. The danger is any command that prints `password`, `credential`, `token`, `secret`, or `--reveal`.

### Inspect a file that might contain secrets

```bash
# Don't: cat .env / Read backend/.env / grep KEY .env / jq . .mcp.json
# Do:
~/.config/droid/hooks/redacted-cat .env
~/.config/droid/hooks/redacted-cat ~/.zshrc | grep -i openai
env | cut -d= -f1 | grep -i key                      # names only
```

### Get a secret into a script

```bash
~/.config/droid/hooks/secret-fetch aws my/secret --env-exec -- python3 script.py
op run --env-file ./env.tpl -- ./script              # injects op://refs as env vars
```

`env.tpl` looks like `API_KEY=op://Vault/Item/field` — no plaintext anywhere.

## In code diffs and artifacts

- Commit-message bodies shouldn't contain secret values.
- Don't write secrets into READMEs, tests, fixtures, screenshots, or screenshots-equivalent evidence captures.
- In test outputs / HAR captures / webhook payloads, redact `Authorization`, `X-*-Key`, `password`, `secret`, `token`, `apikey` fields before printing.
- For `.env.tpl` / `.env.example` files, placeholder strings like `<redacted>` or `your-key-here` only.

## Sanitization checklist before responding to the user

Before any final answer that reports on values retrieved earlier:

1. Scan the message for secret-shaped strings: `*_key=`, `password=`, `secret=`, `token=`, `Authorization:`, `Bearer `, `sk-_`, `pp_sk_`, `xox-`, `ghp_`, `AIza`, `AKIA`, `whsec_`, `-----BEGIN`, or URL segments carrying a `user:pass@` credential.
2. If a literal value slipped out in an earlier tool result, do NOT restate it — refer to it by variable name, `'<redacted>'`, or "the secret we stored earlier."
3. If a value is printed length/prefix only, say so (`stored len=54, first3=whs…`; never the whole first N/last N where N>6).

## Escape hatches

`DROID_SECRET_GUARD=off` or `DEVIN_SECRET_GUARD=off` in the environment disables the pre/post-use guards without changing this skill's instructions. Do not set this quietly; if you need an unredacted read, surface the reason to the user first.
