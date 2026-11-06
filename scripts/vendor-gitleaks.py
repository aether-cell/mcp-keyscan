#!/usr/bin/env python3
"""Regenerate rules/gitleaks.json from rules/gitleaks.toml (maintainers only).

Update the rules:
  curl -sL -o rules/gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/<commit>/config/gitleaks.toml
  python3 scripts/vendor-gitleaks.py <commit>

The JSON keeps gitleaks' regexes verbatim; src/rules.js adapts RE2 syntax to JavaScript at load time.
"""
import json, sys, tomllib, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
src = tomllib.loads((root / "rules" / "gitleaks.toml").read_text())
out = {
    "source": "https://github.com/gitleaks/gitleaks/blob/%s/config/gitleaks.toml" % (sys.argv[1] if len(sys.argv) > 1 else "master"),
    "license": "MIT (see rules/LICENSE-gitleaks)",
    "allowlist": {k: v for k, v in src.get("allowlist", {}).items() if k in ("regexes", "stopwords")},
    "rules": [
        {k: r[k] for k in ("id", "regex", "secretGroup", "entropy", "keywords", "path", "allowlists") if k in r}
        for r in src["rules"] if "regex" in r
    ],
}
(root / "rules" / "gitleaks.json").write_text(json.dumps(out, indent=1) + "\n")
print(len(out["rules"]), "rules")
