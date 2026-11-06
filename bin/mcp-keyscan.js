#!/usr/bin/env node
'use strict';
// mcp-keyscan: find plaintext secrets in local AI-agent / MCP configs, agent logs and
// shell history. Local only: no network calls, no telemetry. Never prints a secret value.
const fs = require('fs');
const path = require('path');
const { scan } = require('../src/scan');
const { textReport, jsonReport } = require('../src/report');
const { globalLocations } = require('../src/locations');
const { version } = require('../package.json');

const HELP = `mcp-keyscan ${version}: find plaintext API keys in AI-agent / MCP configs, agent logs and shell history.
Never prints a secret value. Local only: no network, no telemetry.

Usage:
  npx github:aether-cell/mcp-keyscan [PATH...] [options]

With no PATH, scans known per-user agent/MCP client configs (Claude Desktop/Code, Cursor, VS Code,
Windsurf, Zed, Continue, Cline, Roo, Gemini CLI, Codex, opencode, Goose, Kiro, ...), their logs and
transcripts, shell history, and the project files in the current directory.
With PATH, walks those files/directories instead (add --global to include the per-user locations).

Options:
  --out FILE            also write the redacted, shareable report to FILE
  --json                machine-readable JSON (still redacted)
  --min-severity LEVEL  low | medium | high (default: low); filters findings and the exit code
  --no-logs             skip agent logs and transcripts
  --no-history          skip shell history
  --global              with PATH: also scan the per-user locations
  --list-locations      print the per-user paths that would be checked, then exit
  -v, --version         print version
  -h, --help            show this help

Exit codes: 0 = no findings, 1 = findings, 2 = usage error.`;

function parse(argv) {
  const o = { paths: [], json: false, out: null, minSeverity: 'low', logs: true, history: true, global: false };
  const args = argv.slice();
  if (args[0] === 'scan') args.shift(); // v0 compatibility
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const val = () => { const v = args[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '--json') o.json = true;
    else if (a === '--out') o.out = val();
    else if (a.startsWith('--out=')) o.out = a.slice(6);
    else if (a === '--min-severity') o.minSeverity = val();
    else if (a.startsWith('--min-severity=')) o.minSeverity = a.slice(15);
    else if (a === '--no-logs') o.logs = false;
    else if (a === '--no-history') o.history = false;
    else if (a === '--global') o.global = true;
    else if (a === '--list-locations') o.list = true;
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else o.paths.push(a);
  }
  if (!['low', 'medium', 'high'].includes(o.minSeverity)) throw new Error('--min-severity must be low, medium or high');
  return o;
}

function main() {
  let o;
  try { o = parse(process.argv.slice(2)); } catch (e) {
    process.stderr.write(`mcp-keyscan: ${e.message}\n\n${HELP}\n`);
    return 2;
  }
  if (o.help) { process.stdout.write(HELP + '\n'); return 0; }
  if (o.version) { process.stdout.write(version + '\n'); return 0; }
  if (o.list) {
    for (const l of globalLocations()) process.stdout.write(`${l.kind.padEnd(8)} ${l.client.padEnd(26)} ${l.path}${fs.existsSync(l.path) ? '  (present)' : ''}\n`);
    return 0;
  }
  o.onStart = ({ logs, logBytes }) => {
    if (logBytes > 100 * 1024 * 1024) {
      process.stderr.write(`mcp-keyscan: reading ${logs} agent log files (${Math.round(logBytes / 1048576)} MB) locally; this can take a minute (--no-logs to skip)\n`);
    }
  };
  const result = scan(o);
  const report = textReport(result, { version });
  process.stdout.write(o.json ? jsonReport(result, { version }) : report);
  if (o.out) {
    fs.writeFileSync(path.resolve(o.out), report, { mode: 0o600 });
    process.stderr.write(`report written to ${o.out}\n`);
  }
  return result.findings.length ? 1 : 0;
}

process.exitCode = main();
