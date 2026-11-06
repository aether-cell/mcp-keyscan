# mcp-keyscan

**Never prints a secret value.** Every key it finds is shown only as a redacted preview (first 4 characters + length), in the terminal, in the JSON and in the shareable report. A test in this repo fails the build if any fixture secret appears in stdout, stderr, the report file or the JSON.

`mcp-keyscan` finds plaintext API keys in your AI-agent and MCP client configs, **agent logs and transcripts, and shell history**, then gives you a redacted report you can paste into an issue, a chat or a post, with a one-line fix per finding.

```bash
npx github:aether-cell/mcp-keyscan
```

Local only: no network calls, no telemetry, zero dependencies. Node 18+. Apache-2.0.

## Why

- Setup guides tell you to paste keys straight into `env`, `headers` or `args`. Those files get synced, shared, committed, and read by agents.
- Agents then copy the same keys into their logs and transcripts (`~/.claude/projects/*.jsonl`, `~/.codex/sessions`, Cline tasks…), and `claude mcp add -e KEY=…` / `export KEY=…` leave them in shell history.
- Most scanners stop at the config file and print the secret back to you. mcp-keyscan checks all three places and never prints the value, so the report itself is safe to share.

## Usage

```bash
npx github:aether-cell/mcp-keyscan                        # known agent configs + logs + shell history + current project
npx github:aether-cell/mcp-keyscan path/to/repo           # walk a directory instead (add --global for the per-user locations too)
npx github:aether-cell/mcp-keyscan --out keyscan.md       # also save the shareable report
npx github:aether-cell/mcp-keyscan --json                 # machine-readable, still redacted
npx github:aether-cell/mcp-keyscan --min-severity high    # only provider-specific hits
npx github:aether-cell/mcp-keyscan --no-logs --no-history # configs only
npx github:aether-cell/mcp-keyscan --list-locations       # which paths it checks on this machine
npx github:aether-cell/mcp-keyscan --mcp                  # stdio MCP server, tool: scan_secrets
```

Exit code: `0` = clean, `1` = findings (at or above `--min-severity`), `2` = usage error. Works as a CI gate:

```yaml
- run: npx --yes github:aether-cell/mcp-keyscan . --min-severity medium
```

## Use it from an agent (MCP server)

`--mcp` runs mcp-keyscan as a stdio MCP server with one read-only tool, `scan_secrets`, so an agent can check its own machine. The tool returns the same redacted report (or redacted JSON), so the agent never sees a value either.

```json
{
  "mcpServers": {
    "keyscan": { "command": "npx", "args": ["-y", "github:aether-cell/mcp-keyscan", "--mcp"] }
  }
}
```

Tool arguments (all optional): `paths`, `include_logs`, `include_history`, `min_severity`, `format` (`text` | `json`).

## Sample report

Fixture keys below are fake. Home paths are shown as `~`, so the report does not reveal your user name.

```
# mcp-keyscan report (v1.0.0)

Scanned 10 files on this machine: 7 agent/MCP configs, 1 agent log, 2 shell histories. Nothing left this machine.
Found 4 plaintext secrets: 4 high, 0 medium, 0 low.
Values are redacted (first 4 characters + length). This report is safe to share.

1. [HIGH] .cursor/mcp.json:7 (Cursor, server github · env.GITHUB_PERSONAL_ACCESS_TOKEN)
   github-pat · github · ghp_…(40 chars)
   fix: rotate this github key, then replace the value with "${env:GITHUB_PERSONAL_ACCESS_TOKEN}" and export GITHUB_PERSONAL_ACCESS_TOKEN outside the file (or use a keychain/broker)

2. [HIGH] .mcp.json:5 (Claude Code / portable, server stripe · args[2])
   stripe-access-token · stripe · sk_l…(28 chars)
   fix: rotate this stripe key, then replace the value with "${STRIPE_API_KEY}" and export STRIPE_API_KEY outside the file (or use a keychain/broker)

3. [HIGH] ~/.bash_history:4 (shell)
   curl-auth-header · github · ghp_…(40 chars)
   fix: rotate this github key, then delete line 4 from ~/.bash_history; pass keys via env or a prompt, not on the command line

4. [HIGH] ~/.claude/projects/-work-demo/session.jsonl:2 (Claude Code)
   stripe-access-token · stripe · sk_l…(32 chars)
   fix: rotate this stripe key, then delete or scrub ~/.claude/projects/-work-demo/session.jsonl; the agent wrote it to disk in clear

scanned with npx mcp-keyscan
```

## What it scans

Per-user locations (Linux `~/.config`, macOS `~/Library/Application Support`, Windows `%APPDATA%`), plus project files in the current directory:

| Source | Files |
|---|---|
| Claude Desktop | `<appdata>/Claude/claude_desktop_config.json`; logs in `<appdata>/Claude/logs`, `~/Library/Logs/Claude` |
| Claude Code | `~/.claude.json`, `~/.claude/settings*.json`, project `.mcp.json`, `.claude/settings*.json`; transcripts `~/.claude/projects/**/*.jsonl`, `~/.claude/history.jsonl`, shell snapshots |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json`, `<appdata>/Cursor/logs` |
| VS Code | `<appdata>/Code/User/mcp.json`, `settings.json`, project `.vscode/mcp.json`, `.vscode/settings.json`, `<appdata>/Code/logs` |
| Windsurf / Devin Desktop | `~/.codeium/windsurf/mcp_config.json`, `~/.config/devin/mcp_config.json`, logs |
| Zed | `~/.config/zed/settings.json`, `<appdata>/Zed/settings.json`, Zed logs |
| Continue | `~/.continue/config.yaml`, `config.json`, `.env`, `mcpServers/*`, `sessions/`, `logs/` |
| Cline / Roo / Kilo Code | `globalStorage/…/cline_mcp_settings.json`, `mcp_settings.json`, task histories under `globalStorage/…/tasks`, `~/.cline/data/settings/` |
| Gemini CLI | `~/.gemini/settings.json`, `~/.gemini/.env`, `~/.gemini/tmp` (chats, logs) |
| Codex | `~/.codex/config.toml` (`[mcp_servers.*]`), `~/.codex/sessions`, `history.jsonl`, `log/` |
| Others | opencode, Goose, Kiro, LM Studio, Amazon Q, Copilot CLI, Aider (`.aider.chat.history.md`, `.aider.input.history`), `.env*` |
| Shell history | `$HISTFILE`, `~/.bash_history`, `~/.zsh_history`, fish, PowerShell PSReadLine, Python/Node/psql/MySQL/SQLite REPL history |

`PATH` mode walks the directory (skipping `.git`, `node_modules`, virtualenvs, build dirs) and picks up MCP configs, `.env*` and history files by name. Log files over 50 MB are skipped and listed.

## What it detects

- **The [gitleaks](https://github.com/gitleaks/gitleaks) rule set**, vendored unchanged in `rules/gitleaks.json` (221 rules, MIT, see `rules/LICENSE-gitleaks`): provider keys (Anthropic, OpenAI, GitHub, AWS, Stripe, Slack, Hugging Face, GCP, …), private keys, JWTs, `curl -H "Authorization: …"` and gitleaks' generic API-key rule, with gitleaks' keywords, entropy thresholds and allowlists. No home-grown regex farm.
- **One key-name heuristic** on top, because agent configs are mostly `NAME=value`: a sensitive name (`*_API_KEY`, `*TOKEN*`, `*SECRET*`, `PASSWORD`, `--api-key VALUE`, `?token=`) with a secret-looking value (letters + digits, ≥ 12 chars, entropy ≥ 3), plus credentials in URLs (`postgres://user:pass@`). These are reported as `medium`.
- **Ignored:** `${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%`, `{{…}}`, `<…>`, `op://…` and similar references, and placeholders (`your-api-key-here`, `xxxx`, `changeme`, `…EXAMPLE`).
- In MCP JSON/JSONC configs each finding names the server and the field (`env.X`, `headers.Authorization`, `args[2]`); TOML findings name the `[mcp_servers.*]` table.

Severity: `high` = a gitleaks provider rule; `medium` = gitleaks' generic rule or the key-name heuristic. In logs and transcripts the generic rule is skipped (too noisy there); provider rules and the heuristic still run.

## Fixing findings

Every finding has a one-line `fix`: the env-var reference your client understands (`${env:VAR}` for Cursor / VS Code, `${VAR}` for Claude Code `.mcp.json`), which line to delete from your history, or which log to scrub. Always rotate a key that was found: it was on disk in clear. mcp-keyscan never edits files.

## Limitations

- YAML and TOML are scanned line by line, not parsed.
- Detection is regex + heuristic. Expect some false positives at `medium` (use `--min-severity high`) and misses for unusual formats.
- Secrets in OS keychains, browser storage or client databases (SQLite) are out of scope.
- Paths follow each client's docs as of 2026-11; clients move files between releases. Pass a `PATH` for anything else, and open an issue with the location.
- Large transcript folders take a while (it reads every line locally); `--no-logs` skips them.

## Development

```bash
npm test     # node --test, no dependencies
```

All keys in `test/fixtures` are fake. To update the vendored gitleaks rules, see `scripts/vendor-gitleaks.py`.

v0.1.0 (Python) is tagged as `v0.1.0`; v1 is a Node rewrite so `npx` works with no install.

## License

Apache-2.0. Copyright aether-cell contributors. Vendored gitleaks rules: MIT, Copyright (c) 2019 Zachary Rice.
