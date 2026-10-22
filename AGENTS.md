# AGENTS.md: mcp-keyscan

Guidance for AI coding agents using or changing this repo.

## Using the tool
- Run `mcp-keyscan scan --json` (or `python -m mcp_keyscan scan --json`) and read `findings[]`.
- Each finding has `file`, `client`, `server`, `key` (location inside the server entry), `provider`,
  `severity` (`high`/`medium`/`low`), `rule`, `preview` (redacted) and `line`.
- Exit code 1 means findings; that is the expected result on a dirty config, not a crash.
- `mcp-keyscan fix --dry-run --json` gives `replace_with`, `env_var`, `note` and a `mintcall` command per finding.
- Never try to recover or print the real value. If a fix needs the value, ask the user to move it themselves
  (environment variable, OS keychain, or a broker such as mintcall: https://github.com/aether-cell/mintcall),
  and to rotate the key.

## Layout
- `mcp_keyscan/detect.py`: provider regexes, placeholder filter, entropy, `redact()`. Pure functions.
- `mcp_keyscan/locations.py`: per-client, per-platform config paths and the directory walker.
- `mcp_keyscan/scanner.py`: JSON/JSONC/TOML parsing, server-entry walking, line-based fallback for YAML and .env.
- `mcp_keyscan/cli.py`: argparse CLI, table/JSON output, `fix --dry-run` plan.
- `tests/`: unittest suite; fixtures under `tests/fixtures` contain FAKE keys only.

## Rules for changes
- Standard library only; keep Python 3.10 compatible.
- No output path may contain a secret value. Everything user-visible goes through `detect.redact()`;
  `tests/test_keyscan.py` asserts that no fixture secret (or more than its first 4 chars) is ever printed.
- New fixture keys must be fake and contain `FAKE`.
- Run `python -m unittest discover -s tests` before committing.
- v0 has no write mode; `fix` must stay read-only.
