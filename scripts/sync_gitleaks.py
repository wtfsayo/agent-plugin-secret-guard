#!/usr/bin/env python3
"""Re-generate gitleaks_patterns.py from upstream gitleaks.toml.

Run from the plugin root:
    python3 scripts/sync_gitleaks.py
Fetches https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
and writes scripts/gitleaks_patterns.py. Marks rules that need Python-incompatible
syntax as skipped (Python's `re` can't express Go's mid-string `(?i)` or `\z`).
"""
from __future__ import annotations

import re
import sys
import tomllib
import urllib.request
from pathlib import Path

TOML_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
OUT = Path(__file__).resolve().parent / "gitleaks_patterns.py"


def normalize(pat: str) -> tuple[str, bool]:
    """Return (python_regex, needs_ignorecase).

    Gitleaks uses Go-flavored regexes. Python's `re` forbids mid-string global
    flags like `(?i)` and Go's `\z` anchor; hoist `(?i)` to the front and
    drop `\\z` → `\\Z`.
    """
    needs_i = "(?i)" in pat or "(?-i:" in pat
    pat = re.sub(r"\(\?i\)", "", pat)
    pat = re.sub(r"\(\?-i:([^)]*)\)", r"\1", pat)
    pat = pat.replace("\\z", "\\Z")
    return pat, needs_i


def main() -> int:
    raw = urllib.request.urlopen(TOML_URL, timeout=30).read()
    data = tomllib.loads(raw.decode())
    rules = data.get("rules", [])

    out, skipped = [], []
    for r in rules:
        rid, rx = r.get("id", ""), r.get("regex", "")
        if not rx:
            continue
        pat, needs_i = normalize(rx)
        body = ("(?i)" if needs_i else "") + pat
        try:
            re.compile(body)
        except re.error as e:
            skipped.append((rid, str(e)[:120]))
            continue
        out.append((rid, body))

    lines = [
        '"""Auto-generated from gitleaks.toml — regenerate with scripts/sync_gitleaks.py."""',
        "",
        "GITLEAKS_PATTERNS = [",
    ]
    for rid, pat in out:
        lines.append(f"    ({rid!r}, {pat!r}),")
    lines.append("]")
    if skipped:
        lines.extend(["", "GITLEAKS_SKIPPED = ["])
        for rid, err in skipped:
            lines.append(f"    ({rid!r}, {err!r}),")
        lines.append("]")
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {len(out)} rules to {OUT} (skipped {len(skipped)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
