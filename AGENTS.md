# AGENTS.md: mcp-keyscan

Guidance for AI coding agents using or changing this repo.

## Using the tool
- Run `npx --yes github:aether-cell/mcp-keyscan --json` and read `findings[]`, or add it as an MCP server
  (`npx -y github:aether-cell/mcp-keyscan --mcp`) and call the `scan_secrets` tool.
- Each finding has `severity` (`high`/`medium`), `kind` (`config`/`log`/`history`), `client`, `file` (home shown as `~`),
  `line`, `server`, `key` (field inside the server entry), `provider`, `rule`, `preview` (redacted) and a one-line `fix`.
- Exit code 1 means findings; that is the expected result on a dirty machine, not a crash.
- Never try to recover or print the real value. Ask the user to move it out of the file (environment variable,
  OS keychain or a credential broker) and to rotate the key.
- The plain-text report (default output, or `--out FILE`) is redacted and safe to share. It ends with `scanned with npx mcp-keyscan`.

## Layout
- `bin/mcp-keyscan.js`: CLI (argument parsing, output).
- `src/rules.js`: loads vendored gitleaks rules (`rules/gitleaks.json`) and adapts RE2 syntax to JS.
- `src/detect.js`: gitleaks matching, the single key-name heuristic, placeholder filter, entropy, `redact()`.
- `src/locations.js`: per-client, per-platform config / log / history paths and directory walkers.
- `src/scan.js`: reads files, maps findings to MCP servers and fields, builds the fix line.
- `src/mcp.js`: stdio MCP server (`--mcp`), one read-only tool `scan_secrets` returning the redacted report.
- `src/report.js`: the only place output is built, from an allow-list of fields (value only as `redact(value)`).
- `test/`: `node --test`; fixtures under `test/fixtures` contain fake keys only.

## Rules for changes
- Zero runtime dependencies. No network modules, no telemetry (a test checks this).
- No output path may contain a secret value. `test/keyscan.test.js` fails if any fixture secret,
  or any 6-character piece of one, appears in stdout, stderr, the report file or JSON.
- Detection comes from gitleaks. Do not add provider regexes; update `rules/` with `scripts/vendor-gitleaks.py`.
- New fixture keys must be fake. Add them to `SECRETS` in the test.
- Run `npm test` before committing. mcp-keyscan never writes to scanned files.
