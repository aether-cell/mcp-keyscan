'use strict';
// Where agents keep configs, logs and shell history, per client and platform.
// Paths follow each client's docs as of 2026-11. Anything missing can still be
// scanned with `npx github:aether-cell/mcp-keyscan PATH`.
const fs = require('fs');
const os = require('os');
const path = require('path');

function appDirs(home, env, platform) {
  if (platform === 'darwin') return [path.join(home, 'Library', 'Application Support')];
  if (platform === 'win32') return [env.APPDATA || path.join(home, 'AppData', 'Roaming')];
  return [env.XDG_CONFIG_HOME || path.join(home, '.config')];
}

// kind: 'config' | 'log' | 'history'. Log entries are directories or files; directories are walked.
function globalLocations({ home = os.homedir(), env = process.env, platform = process.platform } = {}) {
  const locs = [];
  const add = (kind, client, p) => locs.push({ kind, client, path: p });
  const j = path.join;
  const xdg = env.XDG_CONFIG_HOME || j(home, '.config');
  const xdgData = env.XDG_DATA_HOME || j(home, '.local', 'share');
  const xdgState = env.XDG_STATE_HOME || j(home, '.local', 'state');
  const localAppData = env.LOCALAPPDATA || j(home, 'AppData', 'Local');

  for (const root of appDirs(home, env, platform)) {
    add('config', 'Claude Desktop', j(root, 'Claude', 'claude_desktop_config.json'));
    add('config', 'Claude Desktop', j(root, 'Claude-3p', 'claude_desktop_config.json'));
    add('log', 'Claude Desktop', j(root, 'Claude', 'logs'));
    for (const code of ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf', 'Kiro', 'Trae']) {
      const user = j(root, code, 'User');
      if (['Code', 'Code - Insiders', 'VSCodium'].includes(code)) {
        add('config', 'VS Code', j(user, 'mcp.json'));
        add('config', 'VS Code', j(user, 'settings.json'));
      }
      const gs = j(user, 'globalStorage');
      add('config', 'Cline', j(gs, 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
      add('config', 'Roo Code', j(gs, 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'));
      add('config', 'Kilo Code', j(gs, 'kilocode.kilo-code', 'settings', 'mcp_settings.json'));
      add('log', 'Cline', j(gs, 'saoudrizwan.claude-dev', 'tasks'));
      add('log', 'Roo Code', j(gs, 'rooveterinaryinc.roo-cline', 'tasks'));
      add('log', code, j(root, code, 'logs'));
    }
    add('config', 'Zed', j(root, 'Zed', 'settings.json'));
    if (platform === 'win32') add('config', 'Windsurf / Devin Desktop', j(root, 'devin', 'mcp_config.json'));
  }
  if (platform === 'darwin') {
    add('log', 'Claude Desktop', j(home, 'Library', 'Logs', 'Claude'));
    add('log', 'Zed', j(home, 'Library', 'Logs', 'Zed'));
  }

  // Claude Code
  add('config', 'Claude Code', j(home, '.claude.json'));
  add('config', 'Claude Code', j(home, '.claude', 'settings.json'));
  add('config', 'Claude Code', j(home, '.claude', 'settings.local.json'));
  add('config', 'Claude Desktop', j(home, '.claude', 'claude_desktop_config.json'));
  add('log', 'Claude Code', j(home, '.claude', 'projects'));
  add('log', 'Claude Code', j(home, '.claude', 'history.jsonl'));
  add('log', 'Claude Code', j(home, '.claude', 'shell-snapshots'));
  // Cursor
  add('config', 'Cursor', j(home, '.cursor', 'mcp.json'));
  // Windsurf / Devin Desktop
  add('config', 'Windsurf', j(home, '.codeium', 'windsurf', 'mcp_config.json'));
  add('config', 'Windsurf / Devin Desktop', j(xdg, 'devin', 'mcp_config.json'));
  // Zed
  add('config', 'Zed', j(xdg, 'zed', 'settings.json'));
  add('log', 'Zed', j(xdgData, 'zed', 'logs'));
  if (platform === 'win32') add('config', 'Zed', j(localAppData, 'Zed', 'settings.json'));
  // Continue
  add('config', 'Continue', j(home, '.continue', 'config.yaml'));
  add('config', 'Continue', j(home, '.continue', 'config.json'));
  add('config', 'Continue', j(home, '.continue', '.env'));
  const mcpDir = j(home, '.continue', 'mcpServers');
  try {
    for (const f of fs.readdirSync(mcpDir).sort()) {
      if (/\.(ya?ml|json)$/i.test(f)) add('config', 'Continue', j(mcpDir, f));
    }
  } catch (e) { /* not installed */ }
  add('log', 'Continue', j(home, '.continue', 'sessions'));
  add('log', 'Continue', j(home, '.continue', 'logs'));
  // Cline CLI
  if (env.CLINE_MCP_SETTINGS_PATH) add('config', 'Cline', env.CLINE_MCP_SETTINGS_PATH.replace(/^~(?=$|[/\\])/, home));
  add('config', 'Cline', j(home, '.cline', 'data', 'settings', 'cline_mcp_settings.json'));
  // Gemini CLI
  add('config', 'Gemini CLI', j(home, '.gemini', 'settings.json'));
  add('config', 'Gemini CLI', j(home, '.gemini', '.env'));
  add('log', 'Gemini CLI', j(home, '.gemini', 'tmp'));
  // Codex
  add('config', 'Codex', j(home, '.codex', 'config.toml'));
  add('log', 'Codex', j(home, '.codex', 'sessions'));
  add('log', 'Codex', j(home, '.codex', 'history.jsonl'));
  add('log', 'Codex', j(home, '.codex', 'log'));
  // Others
  add('config', 'opencode', j(xdg, 'opencode', 'opencode.json'));
  add('config', 'opencode', j(xdg, 'opencode', 'opencode.jsonc'));
  add('log', 'opencode', j(xdgData, 'opencode', 'log'));
  add('config', 'Goose', j(xdg, 'goose', 'config.yaml'));
  add('log', 'Goose', j(xdgState, 'goose', 'logs'));
  add('config', 'Kiro', j(home, '.kiro', 'settings', 'mcp.json'));
  add('config', 'LM Studio', j(home, '.lmstudio', 'mcp.json'));
  add('config', 'Amazon Q', j(home, '.aws', 'amazonq', 'mcp.json'));
  add('config', 'Amazon Q', j(home, '.aws', 'amazonq', 'default.json'));
  add('config', 'Copilot', j(home, '.copilot', 'mcp-config.json'));
  add('log', 'Copilot', j(home, '.copilot', 'logs'));
  add('config', 'Aider', j(home, '.aider.conf.yml'));
  add('log', 'Aider', j(home, '.aider.chat.history.md'));
  add('log', 'Aider', j(home, '.aider.input.history'));

  // Shell and REPL history
  if (env.HISTFILE) add('history', 'shell', env.HISTFILE.replace(/^~(?=$|[/\\])/, home));
  for (const f of ['.bash_history', '.zsh_history', '.zhistory', '.histfile', '.sh_history',
    '.python_history', '.node_repl_history', '.psql_history', '.mysql_history', '.sqlite_history', '.irb_history']) {
    add('history', 'shell', j(home, f));
  }
  add('history', 'fish', j(xdgData, 'fish', 'fish_history'));
  add('history', 'PowerShell', j(xdgData, 'powershell', 'PSReadLine', 'ConsoleHost_history.txt'));
  if (platform === 'win32') {
    add('history', 'PowerShell', j(env.APPDATA || j(home, 'AppData', 'Roaming'), 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt'));
  }

  const seen = new Set();
  return locs.filter((l) => (seen.has(l.path) ? false : (seen.add(l.path), true)));
}

// Project-relative files checked in the current directory by default.
const PROJECT_FILES = [
  ['config', 'Claude Code / portable', '.mcp.json'],
  ['config', 'Cursor', '.cursor/mcp.json'],
  ['config', 'VS Code', '.vscode/mcp.json'],
  ['config', 'VS Code', '.vscode/settings.json'],
  ['config', 'Roo Code', '.roo/mcp.json'],
  ['config', 'Kiro', '.kiro/settings/mcp.json'],
  ['config', 'Gemini CLI', '.gemini/settings.json'],
  ['config', 'Codex', '.codex/config.toml'],
  ['config', 'Amazon Q', '.amazonq/mcp.json'],
  ['config', 'Amazon Q', '.amazonq/default.json'],
  ['config', 'Claude Code', '.claude/settings.json'],
  ['config', 'Claude Code', '.claude/settings.local.json'],
  ['config', 'opencode', 'opencode.json'],
  ['config', 'opencode', 'opencode.jsonc'],
  ['config', 'Generic', 'mcp.json'],
  ['config', 'dotenv', '.env'],
  ['config', 'dotenv', '.env.local'],
  ['config', 'dotenv', '.env.development'],
  ['config', 'dotenv', '.env.production'],
  ['log', 'Aider', '.aider.chat.history.md'],
  ['log', 'Aider', '.aider.input.history'],
];

const CONFIG_NAMES = new Set(['mcp.json', '.mcp.json', 'mcp_config.json', 'mcp-config.json', 'claude_desktop_config.json',
  'cline_mcp_settings.json', 'mcp_settings.json', '.claude.json', 'opencode.json', 'opencode.jsonc']);
const SETTINGS_PARENTS = new Set(['.vscode', '.gemini', '.claude', 'zed', 'Zed', 'User']);
const HISTORY_NAMES = new Set(['.bash_history', '.zsh_history', '.zhistory', '.histfile', '.sh_history', 'fish_history',
  'ConsoleHost_history.txt', '.python_history', '.node_repl_history', '.psql_history', '.mysql_history',
  '.aider.input.history', '.aider.chat.history.md']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', '.tox', '.mypy_cache', '.pytest_cache',
  'dist', 'build', '.cache', 'site-packages', '.npm', '.cargo', '.next', 'target']);

const isDotenv = (name) => name === '.env' || name.startsWith('.env.') || name.endsWith('.env');

// Classify a file found while walking a user-given PATH. Returns { kind, client } or null.
function classify(p) {
  const name = path.basename(p);
  const parent = path.basename(path.dirname(p));
  if (HISTORY_NAMES.has(name)) return { kind: name.startsWith('.aider') ? 'log' : 'history', client: clientFor(p) };
  if (CONFIG_NAMES.has(name)) return { kind: 'config', client: clientFor(p) };
  if ((name === 'settings.json' || name === 'settings.local.json') && SETTINGS_PARENTS.has(parent)) return { kind: 'config', client: clientFor(p) };
  if (parent === 'mcpServers' && path.basename(path.dirname(path.dirname(p))) === '.continue' && /\.(ya?ml|json)$/i.test(name)) return { kind: 'config', client: 'Continue' };
  if (parent === '.continue' && /^config\.(ya?ml|json)$/.test(name)) return { kind: 'config', client: 'Continue' };
  if (parent === '.codex' && name === 'config.toml') return { kind: 'config', client: 'Codex' };
  if (isDotenv(name) && !/\.(example|sample|template|dist)$/i.test(name)) return { kind: 'config', client: 'dotenv' };
  return null;
}

function clientFor(p) {
  const s = p.split(path.sep).join('/');
  const rules = [
    ['claude_desktop_config.json', 'Claude Desktop'], ['/.claude.json', 'Claude Code'], ['/.claude/', 'Claude Code'],
    ['/.cursor/', 'Cursor'], ['/.vscode/', 'VS Code'], ['windsurf', 'Windsurf'], ['/devin/', 'Windsurf / Devin Desktop'],
    ['/zed/', 'Zed'], ['/Zed/', 'Zed'], ['/.continue/', 'Continue'], ['cline_mcp_settings', 'Cline'], ['roo-cline', 'Roo Code'],
    ['/.roo/', 'Roo Code'], ['/.gemini/', 'Gemini CLI'], ['/.codex/', 'Codex'], ['amazonq/', 'Amazon Q'], ['/.kiro/', 'Kiro'],
    ['/.lmstudio/', 'LM Studio'], ['/User/mcp.json', 'VS Code'], ['/User/settings.json', 'VS Code'], ['/.copilot/', 'Copilot'],
    ['opencode', 'opencode'], ['.aider', 'Aider'], ['fish_history', 'fish'], ['ConsoleHost_history', 'PowerShell'], ['_history', 'shell'],
  ];
  if (s.endsWith('/.mcp.json') || s === '.mcp.json') return 'Claude Code / portable';
  for (const [needle, client] of rules) if (s.includes(needle)) return client;
  if (isDotenv(path.basename(p))) return 'dotenv';
  return 'Generic';
}

const LOG_EXT = /\.(jsonl|json|log|txt|md|ndjson|sh)$|_history$|\.history$/i;

// Yield files under a log location (file or directory).
function* walkLog(root, { maxFiles = 20000, maxDepth = 8 } = {}) {
  let st;
  try { st = fs.statSync(root); } catch (e) { return; }
  if (st.isFile()) { yield root; return; }
  if (!st.isDirectory()) return;
  let count = 0;
  const stack = [[root, 0]];
  while (stack.length) {
    const [dir, depth] = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (depth < maxDepth && !SKIP_DIRS.has(e.name)) stack.push([p, depth + 1]); continue; }
      if (!e.isFile() || !LOG_EXT.test(e.name)) continue;
      if (++count > maxFiles) return;
      yield p;
    }
  }
}

// Yield { kind, client, path } for candidate files under a user-given PATH.
function* walkPath(root) {
  let st;
  try { st = fs.statSync(root); } catch (e) { return; }
  if (st.isFile()) {
    yield { ...(classify(root) || { kind: 'config', client: clientFor(root) }), path: root };
    return;
  }
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); continue; }
      if (!e.isFile()) continue;
      const c = classify(p);
      if (c) yield { ...c, path: p };
    }
  }
}

module.exports = { globalLocations, PROJECT_FILES, classify, clientFor, walkLog, walkPath, isDotenv };
