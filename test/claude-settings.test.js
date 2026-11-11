'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { scanLine } = require('../src/detect');
const { loadRules } = require('../src/rules');
const { scan } = require('../src/scan');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'mcp-keyscan.js');

// Assemble provider-shaped fakes at runtime so the repo never contains a
// full string that push protection would treat as a live key.
const ANT = ['sk-ant-api03-', ('FAKE' + 'a1b2c3d4'.repeat(12)).slice(0, 93), 'AA'].join('');
const GHP = ['ghp_', 'FAKE1111bbbbCCCCddddEEEEffffAAAA', '2222'].join('');
assert.strictEqual(ANT.length, 108);
assert.strictEqual(GHP.length, 40);

const SECRETS = [ANT, GHP];

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

function writeSettings(file, allow) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const doc = { permissions: { allow } };
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
}

function findByValue(findings, value) {
  return findings.find((f) => f.value === value || (f.value && f.value.includes(value)));
}

test('vendored gitleaks.json is unchanged; only our wrapper accepts ) for Anthropic keys', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(ROOT, 'rules', 'gitleaks.json'), 'utf8'));
  const vendored = Object.fromEntries(raw.rules.filter((r) => r.id.startsWith('anthropic')).map((r) => [r.id, r.regex]));
  assert.ok(vendored['anthropic-api-key']);
  assert.ok(vendored['anthropic-admin-api-key']);
  for (const [id, re] of Object.entries(vendored)) {
    assert.match(re, /\[\\x60'"\\s;\]/, `${id} vendored terminator`);
    assert.doesNotMatch(re, /\[\\x60'"\\s;\)\]/, `${id} must not be edited in gitleaks.json`);
  }
  const { rules, skipped } = loadRules();
  assert.deepStrictEqual(skipped, []);
  for (const id of ['anthropic-api-key', 'anthropic-admin-api-key']) {
    const r = rules.find((x) => x.id === id);
    assert.ok(r, id);
    assert.match(r.regex.source, /\[\\x60'"\\s;\)\]/, `${id} wrapper adds )`);
  }
  const pat = rules.find((r) => r.id === 'github-pat');
  const vendoredPat = raw.rules.find((r) => r.id === 'github-pat').regex;
  // Other rules are compiled, not broadened. The github-pat pattern has no terminator class.
  assert.ok(pat.regex.source.includes('ghp_'));
  assert.ok(vendoredPat.startsWith('ghp_') || vendoredPat.includes('ghp_'));
  assert.strictEqual(pat.regex.source.includes('[\\x60\'"\\s;)]'), false);
});

test('scanLine: bare Anthropic key before ) is high; escaped header still needs the unescaped leaf', () => {
  const bare = `Bash(${ANT})`;
  const bareHits = scanLine(bare, 'settings.local.json', 'config');
  assert.ok(bareHits.some((h) => h.rule === 'anthropic-api-key' && h.severity === 'high' && h.value === ANT), JSON.stringify(bareHits.map((h) => h.rule)));

  const rawEscaped = `      "Bash(curl -H \\"x-api-key: ${ANT}\\")" `;
  const rawHits = scanLine(rawEscaped, 'settings.local.json', 'config');
  const rawAnt = rawHits.find((h) => h.value && h.value.includes(ANT));
  assert.ok(rawAnt, 'raw escaped line should still produce some hit');
  assert.notStrictEqual(rawAnt.rule, 'anthropic-api-key');

  const leaf = `Bash(curl -H "x-api-key: ${ANT}")`;
  const leafHits = scanLine(leaf, 'settings.local.json', 'config');
  assert.ok(leafHits.some((h) => h.rule === 'anthropic-api-key' && h.severity === 'high' && h.value === ANT));
});

test('Claude Code settings: detection cases, locate(), permissions fix, no leaks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-claude-cases-'));
  const file = path.join(dir, '.claude', 'settings.local.json');
  writeSettings(file, [
    `Bash(curl -H 'x-api-key: ${ANT}')`,
    `Bash(curl -H "x-api-key: ${ANT}")`,
    `Bash(curl -H "Authorization: Bearer ${ANT}")`,
    `Bash(${ANT})`,
    `Bash(export ANTHROPIC_API_KEY=${ANT})`,
    `Bash(git push https://x-access-token:${GHP}@github.com/example/repo.git)`,
  ]);

  const result = scan({ paths: [file], history: false, logs: false, cwd: dir, home: dir });
  const findings = result.findings;
  const ants = findings.filter((f) => f.value === ANT);
  const ghps = findings.filter((f) => f.value === GHP);

  // Six allow entries: five Anthropic shapes + one ghp. Same key may appear
  // in several entries; each entry should still be a high provider hit at
  // permissions.allow[i], never a trailing-backslash medium miss.
  assert.ok(ants.length >= 5, `expected >=5 anthropic hits, got ${ants.length}: ${ants.map((f) => f.key + ':' + f.rule).join(',')}`);
  assert.strictEqual(ghps.length, 1, 'one ghp_ hit');

  for (const f of [...ants, ...ghps]) {
    assert.strictEqual(f.severity, 'high', `${f.key} ${f.rule}`);
    assert.strictEqual(f.section, 'permissions');
    assert.match(f.key, /^permissions\.allow\[\d+\]$/);
    assert.match(f.client, /Claude Code/);
    assert.match(f.fix, /remove the entry from permissions\.allow/);
    assert.ok(!f.fix.includes('${'), `permissions fix should not suggest MCP env interpolation: ${f.fix}`);
    assert.ok(!f.value.endsWith('\\'), 'must not keep a trailing backslash on the secret');
  }
  assert.ok(ants.every((f) => f.rule === 'anthropic-api-key'));
  assert.strictEqual(ghps[0].rule, 'github-pat');
  assert.strictEqual(ghps[0].provider, 'github');

  // The escaped double-quoted header and Bearer entries are the ones v1.0
  // mis-located; they must now point at their allow[] index, not the header name.
  const labels = new Map(JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow.map((v, i) => [v, i]));
  for (const [leaf, i] of labels) {
    const want = leaf.includes(GHP) ? GHP : ANT;
    const hits = findings.filter((f) => f.value === want && f.key === `permissions.allow[${i}]`);
    assert.ok(hits.length >= 1, `missing locate for allow[${i}]`);
  }
});

test('all four Claude Code settings paths are scanned', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-claude-home-'));
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-claude-cwd-'));
  const files = [
    [path.join(home, '.claude', 'settings.json'), `Bash(curl -H 'x-api-key: ${ANT}')`, 'single-quoted'],
    [path.join(home, '.claude', 'settings.local.json'), `Bash(curl -H "x-api-key: ${ANT}")`, 'escaped-header'],
    [path.join(cwd, '.claude', 'settings.json'), `Bash(curl -H "Authorization: Bearer ${ANT}")`, 'bearer'],
    [path.join(cwd, '.claude', 'settings.local.json'), `Bash(${ANT})`, 'bare-paren'],
  ];
  for (const [file, allow] of files) writeSettings(file, [allow]);

  const result = scan({ paths: [], history: false, logs: false, cwd, home });
  const ants = result.findings.filter((f) => f.value === ANT && f.rule === 'anthropic-api-key' && f.severity === 'high');
  const got = new Set(ants.map((f) => f.file));
  const want = new Set([
    '~/.claude/settings.json',
    '~/.claude/settings.local.json',
    '.claude/settings.json',
    '.claude/settings.local.json',
  ]);
  for (const w of want) assert.ok(got.has(w), `missing path ${w}; got ${[...got].join(',')}`);
  for (const f of ants) {
    assert.strictEqual(f.key, 'permissions.allow[0]');
    assert.match(f.fix, /remove the entry from permissions\.allow/);
  }
});

test('CLI report for permissions findings is redacted and uses the permissions fix', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-claude-cli-home-'));
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-claude-cli-cwd-'));
  writeSettings(path.join(cwd, '.claude', 'settings.local.json'), [
    `Bash(curl -H "x-api-key: ${ANT}")`,
    `Bash(export ANTHROPIC_API_KEY=${ANT})`,
    `Bash(git push https://x-access-token:${GHP}@github.com/example/repo.git)`,
  ]);
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
  const r = spawnSync(process.execPath, [BIN, '--json', '--no-history', '--no-logs'], { cwd, env, encoding: 'utf8' });
  assert.strictEqual(r.status, 1, r.stderr);
  assertNoLeak(r.stdout, 'cli stdout');
  assertNoLeak(r.stderr, 'cli stderr');
  const data = JSON.parse(r.stdout);
  assert.ok(data.findings.length >= 3);
  for (const f of data.findings) {
    assert.ok(!('value' in f));
    assert.match(f.key, /^permissions\.allow\[\d+\]$/);
    assert.match(f.fix, /remove the entry from permissions\.allow/);
    assert.strictEqual(f.severity, 'high');
  }
  assert.ok(data.findings.some((f) => f.rule === 'anthropic-api-key' && f.preview.startsWith('sk-a')));
  assert.ok(data.findings.some((f) => f.rule === 'github-pat' && f.preview.startsWith('ghp_')));
});
