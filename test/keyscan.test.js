'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { redact, scanLine, isPlaceholder } = require('../src/detect');
const { loadRules } = require('../src/rules');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'mcp-keyscan.js');
const FIX = path.join(__dirname, 'fixtures');
// The agent-transcript fixture is written at test time, with its Stripe-shaped fake key
// assembled from pieces, so the repo itself never contains a string that push protection
// would treat as a live key.
const LOG_KEY = ['sk', 'live', 'FAKElog0fake1FAKE2fake3x'].join('_');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-fixture-home-'));
fs.cpSync(path.join(FIX, 'home'), HOME, { recursive: true });
fs.mkdirSync(path.join(HOME, '.claude', 'projects', '-work-demo'), { recursive: true });
fs.writeFileSync(path.join(HOME, '.claude', 'projects', '-work-demo', 'session.jsonl'), [
  JSON.stringify({ type: 'user', message: { content: 'hi' } }),
  JSON.stringify({ type: 'tool_result', content: `STRIPE_SECRET_KEY=${LOG_KEY}\nOK` }),
  JSON.stringify({ type: 'assistant', message: { content: 'Set it with ${STRIPE_SECRET_KEY}' } }),
].join('\n') + '\n');
const PROJECT = path.join(FIX, 'project');

// Every fake secret planted in the fixtures. None may ever appear in output.
const SECRETS = [
  'sk-ant-api03-TESTSECRETVALUE000000000000000',
  'ghp_FAKEhist0000aaaaBBBBccccDDDDeeee2222',
  'BSAFAKEzsh12345FAKEzsh678',
  LOG_KEY,
  'tvly-FAKEcodex1234FAKEcodex5678',
  'BSAFAKEfake12345FAKEfake678',
  'ghp_FAKE0000aaaaBBBBccccDDDDeeeeFFFF1111',
  'sk-proj-FAKEfake1234FAKEfake5678FAKEfake90ab',
  'sk-ant-api03-FAKEfakeFAKEfakeFAKEfakeFAKE-test',
  'FAKEsecretQ9w8e7r6t5y4u3i2o1pFAKEsecret0',
  'xoxb-FAKE000000-FAKE000000-fakeFAKEfake',
  'ntn_FAKE1a2b3c4d5e6f7g8h9i0jFAKE',
  'sk-ant-api03-FAKEdotenvFAKEdotenvFAKEdotenv-zz',
  'FAKEz9Y8x7W6v5U4t3S2r1Q0',
  'sk_live_FAKE0fake1FAKE2fake3',
  'hf_FAKE0fakeFAKE1fakeFAKE2fakeFAKE3fa',
  'FAKEq8Zr2LmX9vT4pK7wN3sB6yH1',
  'AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123',
  'FAKEpassw0rd99',
];

function run(args, { cwd = PROJECT, home = HOME } = {}) {
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
  return spawnSync(process.execPath, [BIN, ...args], { cwd, env, encoding: 'utf8' });
}

// A leak is the full value or any 6-char window of it beyond the 4-char preview.
function assertNoLeak(text, label) {
  for (const s of SECRETS) {
    assert.ok(!text.includes(s), `${label} contains a full fixture secret`);
    for (let i = 1; i + 6 <= s.length; i++) {
      const w = s.slice(i, i + 6);
      if (/^[A-Za-z0-9]{6}$/.test(w) && /\d/.test(w) && /[a-z]/i.test(w) && !/^FAKE/.test(w)) {
        assert.ok(!text.includes(w), `${label} contains part of a fixture secret`);
      }
    }
  }
}

test('fixture secrets are really in the fixtures', () => {
  const all = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); e.isDirectory() ? walk(p) : all.push(fs.readFileSync(p, 'utf8')); } };
  walk(FIX);
  walk(HOME);
  const blob = all.join('\n');
  for (const s of SECRETS) assert.ok(blob.includes(s), `missing fixture secret ${s.slice(0, 4)}`);
});

test('redact shows only first 4 chars and length', () => {
  assert.strictEqual(redact('sk-ant-api03-TESTSECRETVALUE000000000000000'), 'sk-a…(43 chars)');
  assert.strictEqual(redact('short123'), '****(8 chars)');
  assert.strictEqual(redact('abc'), '****(3 chars)');
});

test('gitleaks rule set loads and compiles completely', () => {
  const { rules, skipped } = loadRules();
  assert.ok(rules.length >= 200, `only ${rules.length} rules`);
  assert.deepStrictEqual(skipped, []);
});

test('placeholders and references are ignored', () => {
  for (const v of ['${OPENAI_API_KEY}', '${env:X}', '${input:tok}', '$TOKEN', '%TOKEN%', '{{ token }}', '<your key>',
    'op://vault/item/field', 'your-api-key-here', 'xxxxxxxxxxxx', 'changeme']) assert.ok(isPlaceholder(v), v);
  assert.deepStrictEqual(scanLine('"OPENAI_API_KEY": "${env:OPENAI_API_KEY}", "BRAVE_API_KEY": "your-api-key-here"'), []);
});

test('full scan: never prints a secret in stdout, stderr, report file or JSON', () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-')), 'report.md');
  const r = run(['--out', out]);
  assert.strictEqual(r.status, 1, r.stderr);
  const j = run(['--json']);
  assert.strictEqual(j.status, 1, j.stderr);
  const report = fs.readFileSync(out, 'utf8');
  for (const [label, text] of [['stdout', r.stdout], ['stderr', r.stderr], ['report', report], ['json', j.stdout], ['json stderr', j.stderr]]) {
    assertNoLeak(text, label);
  }
  // shareable report ends with the footer line
  assert.strictEqual(r.stdout.trimEnd().split('\n').pop(), 'scanned with npx mcp-keyscan');
  assert.strictEqual(report.trimEnd().split('\n').pop(), 'scanned with npx mcp-keyscan');
  // planted Anthropic key in shell history is found, redacted
  assert.match(r.stdout, /~\/\.bash_history:2 .*\n.*sk-a…\(43 chars\)/);
  const data = JSON.parse(j.stdout);
  assert.strictEqual(data.footer, 'scanned with npx mcp-keyscan');
  for (const f of data.findings) {
    assert.ok(!('value' in f));
    assert.ok(f.fix && !f.fix.includes('\n'), 'one-line fix per finding');
  }
  const kinds = new Set(data.findings.map((f) => f.kind));
  assert.ok(kinds.has('config') && kinds.has('history') && kinds.has('log'), [...kinds].join(','));
  assert.match(r.stdout, /~\/\.claude\/projects\/-work-demo\/session\.jsonl:2 /);
  // home paths are shown as ~ so the report does not reveal the user name
  assert.ok(!r.stdout.includes(HOME));
});

test('project findings cover the main MCP config shapes', () => {
  const data = JSON.parse(run(['--json', '.']).stdout);
  const got = new Set(data.findings.map((f) => `${f.file}|${f.server || ''}`));
  for (const want of ['.cursor/mcp.json|github', '.cursor/mcp.json|openai-tools', '.cursor/mcp.json|remote-anthropic',
    '.vscode/mcp.json|aws', '.vscode/settings.json|slack', '.mcp.json|stripe', '.mcp.json|hf', '.mcp.json|gemini', '.mcp.json|db',
    '.env|', '.continue/mcpServers/notion.yaml|']) {
    assert.ok(got.has(want), `missing ${want}`);
  }
  assert.ok(!data.findings.some((f) => f.server === 'safe-one' || f.server === 'ref-only'));
});

test('clean config exits 0', () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-home-'));
  const r = run(['.'], { cwd: path.join(FIX, 'clean'), home: empty });
  assert.strictEqual(r.status, 0, r.stdout);
  assert.match(r.stdout, /No plaintext secrets found\.\n\nscanned with npx mcp-keyscan\n$/);
});

test('--no-history and --no-logs skip those sources', () => {
  const data = JSON.parse(run(['--json', '--no-history', '--no-logs']).stdout);
  assert.ok(!data.findings.some((f) => f.kind === 'history' || f.kind === 'log'));
});

test('usage errors exit 2', () => {
  assert.strictEqual(run(['--min-severity', 'nope']).status, 2);
  assert.strictEqual(run(['--bogus']).status, 2);
});

test('no network or telemetry code in the runtime', () => {
  for (const dir of ['src', 'bin']) {
    for (const f of fs.readdirSync(path.join(ROOT, dir))) {
      const src = fs.readFileSync(path.join(ROOT, dir, f), 'utf8');
      assert.ok(!/require\(['"](?:node:)?(?:https?|http2|net|dgram|dns|tls|child_process)['"]\)/.test(src), `${f} imports a network module`);
      assert.ok(!/\bfetch\(|XMLHttpRequest|WebSocket/.test(src), `${f} uses fetch`);
    }
  }
  const pkg = require('../package.json');
  assert.ok(!pkg.dependencies || Object.keys(pkg.dependencies).length === 0, 'zero runtime dependencies');
  assert.ok(pkg.bin && pkg.bin['mcp-keyscan'], 'bin entry');
});
