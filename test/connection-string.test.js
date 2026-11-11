'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { scanLine } = require('../src/detect');
const { scan } = require('../src/scan');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'mcp-keyscan.js');
const PASS = ['FAKE', 'dbP4ss99'].join('');

function hitsFor(line) {
  return scanLine(line, 'demo.txt', 'config');
}

function connHits(line) {
  return hitsFor(line).filter((h) => h.rule === 'connection-string-password');
}

test('connection-string-password: listed schemes are high; other URL creds stay medium', () => {
  const schemes = [
    'postgres', 'postgresql', 'mysql', 'mariadb',
    'mongodb', 'mongodb+srv', 'redis', 'rediss',
    'amqp', 'amqps', 'mssql', 'sqlserver',
  ];
  for (const scheme of schemes) {
    const hits = connHits(`${scheme}://admin:${PASS}@db.invalid/app`);
    assert.strictEqual(hits.length, 1, scheme);
    assert.strictEqual(hits[0].severity, 'high');
    assert.strictEqual(hits[0].value, PASS);
  }
  // empty user (common redis://:pass@host form)
  const redis = connHits(`redis://:${PASS}@db.invalid:6379`);
  assert.strictEqual(redis.length, 1);
  assert.strictEqual(redis[0].provider, 'redis');

  const generic = hitsFor(`https://user:${PASS}@example.invalid/`);
  assert.ok(generic.some((h) => h.rule === 'url-credentials' && h.severity === 'medium' && h.value === PASS));
  assert.ok(!generic.some((h) => h.rule === 'connection-string-password'));
});

test('connection-string-password: placeholders are ignored', () => {
  for (const pw of ['password', 'pass', 'changeme', '${DB_PASSWORD}', '$DB_PASSWORD', '<password>', '***', 'xxx', '']) {
    const url = pw === '' ? 'postgres://user:@db.invalid/app' : `postgres://user:${pw}@db.invalid/app`;
    const hits = connHits(url);
    assert.deepStrictEqual(hits, [], pw || '(empty)');
  }
});

test('psql in Claude Code Bash(...) allow entry, including escaped quotes', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-conn-home-'));
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscan-conn-cwd-'));
  const file = path.join(cwd, '.claude', 'settings.local.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // Pretty-printed JSON so the second entry is a JSON-escaped double-quoted URL
  // inside the allow string (the same shape as an escaped header).
  const doc = {
    permissions: {
      allow: [
        `Bash(psql postgres://admin:${PASS}@db.invalid:5432/app)`,
        `Bash(psql "postgres://admin:${PASS}@db.invalid:5432/app")`,
        'Bash(psql postgres://user:password@db.invalid:5432/app)',
        'Bash(psql postgres://user:${DB_PASSWORD}@db.invalid:5432/app)',
      ],
    },
  };
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');

  const result = scan({ paths: [file], history: false, logs: false, cwd, home });
  const hits = result.findings.filter((f) => f.rule === 'connection-string-password');
  assert.strictEqual(hits.length, 2, JSON.stringify(result.findings.map((f) => ({ rule: f.rule, key: f.key, sev: f.severity }))));
  for (const f of hits) {
    assert.strictEqual(f.severity, 'high');
    assert.strictEqual(f.value, PASS);
    assert.strictEqual(f.section, 'permissions');
    assert.match(f.key, /^permissions\.allow\[[01]\]$/);
    assert.match(f.fix, /remove the entry from permissions\.allow/);
    assert.ok(!f.fix.includes('${'), f.fix);
  }
  assert.ok(!result.findings.some((f) => f.key === 'permissions.allow[2]' || f.key === 'permissions.allow[3]'));

  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
  const r = spawnSync(process.execPath, [BIN, '--json', '--no-history', '--no-logs', file], { cwd, env, encoding: 'utf8' });
  assert.strictEqual(r.status, 1, r.stderr);
  assert.ok(!r.stdout.includes(PASS) && !r.stderr.includes(PASS), 'CLI leaked the fixture password');
  const data = JSON.parse(r.stdout);
  assert.ok(data.findings.every((f) => !('value' in f)));
  assert.ok(data.findings.some((f) => f.rule === 'connection-string-password' && f.preview.startsWith('FAKE')));
});
