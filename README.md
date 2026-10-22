# mcp-keyscan

**Find plaintext API keys in your AI-agent / MCP client configs, without ever printing them.**

MCP configs (`claude_desktop_config.json`, `~/.cursor/mcp.json`, `.vscode/mcp.json`, …) tend to collect
real keys in `env`, `headers` and `args`. `mcp-keyscan` finds them, shows only a redacted preview
(first 4 characters + length), and tells you what to put there instead.

Python 3.10+, standard library only, Apache-2.0.

## Why

- Plaintext keys in MCP configs are common: setup guides tell you to paste the key straight into `env` or
  `headers`, and those files get synced, shared, committed and read by agents.
- Values are never printed or sent anywhere: output shows only a redacted preview.
- No network calls and no dependencies: it only reads local files.

## 30-second usage

```bash
pip install git+https://github.com/aether-cell/mcp-keyscan   # or: pip install -e .  from a checkout
mcp-keyscan scan                 # known client config locations + the current project
mcp-keyscan scan path/to/repo    # recursive scan of a directory (add --global to include user configs)
mcp-keyscan scan --json          # machine-readable
mcp-keyscan fix --dry-run        # what to replace each finding with (never writes files)
```

Exit code: `0` = clean, `1` = findings (at or above `--min-severity`), `2` = usage error. Drop it into CI:

```yaml
- run: pipx run --spec git+https://github.com/aether-cell/mcp-keyscan mcp-keyscan scan . --min-severity medium
```

Sample output (fixture keys are fake):

```
SEVERITY  FILE                     SERVER            KEY                        PROVIDER   PREVIEW
--------  -----------------------  ----------------  -------------------------  ---------  ---------------
HIGH      .cursor/mcp.json:7       github            env.GITHUB_PERSONAL_ACCE…  github     ghp_…(40 chars)
HIGH      .cursor/mcp.json:15      remote-anthropic  headers.Authorization      anthropic  sk-a…(46 chars)
HIGH      .mcp.json:5              stripe            args[2](api-key)           stripe     sk_l…(28 chars)
MEDIUM    .vscode/mcp.json:10      aws               env.AWS_SECRET_ACCESS_KEY  aws        FAKE…(40 chars)
```

## What it scans

Default `scan` (no PATH) checks these per-user locations (Linux `~/.config`, macOS
`~/Library/Application Support`, Windows `%APPDATA%`), plus project files in the current directory:

| Client | Files |
|---|---|
| Claude Desktop | `<appdata>/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json` (incl. per-project `mcpServers`), `~/.claude/settings*.json`, project `.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` |
| VS Code | `<appdata>/Code/User/mcp.json`, `settings.json` (`mcp` key), project `.vscode/mcp.json`, `.vscode/settings.json` |
| Windsurf / Devin Desktop | `~/.codeium/windsurf/mcp_config.json`, `~/.config/devin/mcp_config.json` |
| Zed | `~/.config/zed/settings.json` (`context_servers`), `<appdata>/Zed/settings.json` |
| Continue | `~/.continue/config.yaml`, `config.json`, `.continue/mcpServers/*.yaml/json` |
| Cline / Roo Code | VS Code (and Cursor/Windsurf) `globalStorage/…/cline_mcp_settings.json`, `mcp_settings.json`, `~/.cline/data/settings/cline_mcp_settings.json` |
| Also | Gemini CLI `~/.gemini/settings.json`, Codex `~/.codex/config.toml`, LM Studio, Amazon Q, Copilot `mcp-config.json`, `.env*` |

`scan PATH` walks the directory (skipping `.git`, `node_modules`, virtualenvs) and picks up any `mcp.json`,
`.mcp.json`, `mcp_config.json`, `.env*` and the client files above.

## What it detects

- Values in `env`, `headers` and `args` of every `mcpServers` / `servers` / `context_servers` entry
  (`--api-key VALUE`, `--api-key=VALUE`, `"Header: value"` args, credentials in URLs and `?token=` query strings).
- Provider formats: OpenAI `sk-`, Anthropic `sk-ant-`, GitHub `ghp_` / `gho_` / `github_pat_`, AWS `AKIA`/`ASIA`,
  Google `AIza`, Slack `xox?-` and webhooks, Stripe `sk_live_` / `rk_live_` (`sk_test_` as low), Hugging Face `hf_`,
  PEM private keys.
- Generic: a sensitive key name (`*_API_KEY`, `*TOKEN*`, `*SECRET*`, `PASSWORD`, …) with a secret-looking value
  (medium), or a high-entropy string in `env`/`headers` (low).
- Ignored: `${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%`, `{{…}}`, `<…>`, `op://…` and similar references,
  and obvious placeholders (`your-api-key-here`, `xxxx`, `changeme`, `…EXAMPLE`).

**Secret values are never printed** in table, JSON or fix output: only the first 4 characters and the length
(values of 8 characters or less show no characters at all).

## Fixing findings

`mcp-keyscan fix --dry-run` prints, per finding, the env-var reference your client understands
(`${env:VAR}` for Cursor / VS Code, `${VAR}` for Claude Code `.mcp.json`), a reminder to rotate the key,
and the equivalent [mintcall](https://github.com/aether-cell/mintcall) command. mintcall is an open-source
local per-call credential broker: the config holds no key, and a loopback proxy injects it per call.

```
[1] HIGH .cursor/mcp.json:7  server=github  env.GITHUB_PERSONAL_ACCESS_TOKEN
    current : ghp_…(40 chars) (redacted)
    replace : "GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_PERSONAL_ACCESS_TOKEN}"
    mintcall: mintcall add-credential github-personal-access-token --recipient https://api.github.com --header Authorization --format "Bearer {secret}"
```

v0 has no write mode. Edit the files yourself, then rotate every key that was found.

## Limitations (v0)

- YAML (Continue) is scanned line by line, not parsed; TOML (Codex) is parsed on Python 3.11+ and line-scanned on 3.10.
- Generic detection is heuristic. Expect some false positives at `low` (use `--min-severity medium`) and misses
  for unusual formats.
- Only scans files on disk. Secrets in OS keychains, shell history or client databases are out of scope.
- Paths follow each client's docs as of 2026-10. Clients move files between releases; use `scan PATH` for anything else.

## Development

```bash
python -m unittest discover -s tests      # or: pytest
```

All keys in `tests/fixtures` are fake and only shaped like real ones (they contain `FAKE`).

## License

Apache-2.0. Copyright aether-cell contributors.
