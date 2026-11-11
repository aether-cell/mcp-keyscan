# Changelog

## 1.1.0 - 2026-11-11

### Fixed
- In JSON configs, scan each unescaped string value as well as the raw line. A key inside a JSON-escaped header (for example `\"x-api-key: …\"` or `\"Authorization: Bearer …\"` in a Claude Code `permissions.allow` entry) is now reported as a high-severity provider finding at `permissions.allow[0]`, instead of a medium `sensitive-key-name` hit whose value includes a trailing backslash and cannot be located.
- Accept `)` as a terminator for Anthropic API keys (`anthropic-api-key` and `anthropic-admin-api-key` only) so a bare `sk-ant-…` at the end of a `Bash(...)` allow rule is detected. This is a wrapper in our code; `rules/gitleaks.json` is unchanged, and no other rule is broadened.

### Changed
- Findings in Claude Code settings `permissions.*` sections now advise rotating the key and removing that allow/deny/ask entry, not replacing the value with an MCP env-var reference. The entry is the saved command; substituting `${VAR}` there is the wrong fix.
- `npm test` now runs `node --test test/*.js`, because Node 24 no longer treats a directory argument as a test glob.
