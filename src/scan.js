'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanLine, SEVERITY_ORDER } = require('./detect');
const { globalLocations, PROJECT_FILES, walkLog, walkPath } = require('./locations');

const MAX_BYTES = 50 * 1024 * 1024;
const SERVER_KEYS = new Set(['mcpServers', 'servers', 'context_servers', 'mcp_servers']);

// Strip // and /* */ comments and trailing commas (JSONC), outside strings.
function stripJsonc(text) {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += text[++i] || ''; } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') out += '\n'; i++; } i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function jsonLeaves(text) {
  let data;
  try { data = JSON.parse(stripJsonc(text)); } catch (e) { return null; }
  const leaves = [];
  const walk = (v, p) => {
    if (typeof v === 'string') leaves.push({ path: p, value: v });
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, p.concat(i)));
    else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], p.concat(k));
  };
  walk(data, []);
  return leaves;
}

// Where inside an MCP config the value sits: server name and "env.NAME" / "headers.X" / "args[2]".
function locate(leaves, value, hint = {}) {
  if (!leaves) return {};
  const matches = leaves.filter((l) => l.value.includes(value));
  if (!matches.length) return {};
  let leaf = matches[0];
  if (hint.leaf && hint.leaf.value && hint.leaf.value.includes(value)) leaf = hint.leaf;
  else if (hint.lines && hint.line != null) {
    const onLine = matches.filter((l) => lineIndexForValue(hint.lines, l.value) === hint.line);
    if (onLine.length) leaf = onLine[0];
  }
  const p = leaf.path;
  let idx = -1;
  for (let i = p.length - 2; i >= 0; i--) if (SERVER_KEYS.has(p[i]) || (p[i] === 'mcp' && p[i + 1] === 'servers')) { idx = i; break; }
  if (idx >= 0 && p[idx] === 'mcp') idx++;
  const permIdx = p.indexOf('permissions');
  if (permIdx >= 0) {
    const rest = p.slice(permIdx);
    const key = rest.map((s, i) => (typeof s === 'number' ? `[${s}]` : (i ? '.' : '') + s)).join('');
    const leafKey = typeof p[p.length - 1] === 'string' ? p[p.length - 1] : null;
    return { server: idx >= 0 ? String(p[idx + 1]) : undefined, key, leafKey, section: 'permissions' };
  }
  const rest = idx >= 0 ? p.slice(idx + 2) : p.slice(-2);
  const key = rest.map((s, i) => (typeof s === 'number' ? `[${s}]` : (i ? '.' : '') + s)).join('');
  const leafKey = typeof p[p.length - 1] === 'string' ? p[p.length - 1] : null;
  return { server: idx >= 0 ? String(p[idx + 1]) : undefined, key, leafKey, section: rest[0] };
}

function tomlServer(lines, lineIdx) {
  for (let i = lineIdx; i >= 0; i--) {
    const m = /^\s*\[\s*mcp_servers\.("?)([^".\]]+)\1/.exec(lines[i]);
    if (m) return m[2];
    if (/^\s*\[/.test(lines[i])) return undefined;
  }
  return undefined;
}

function envName(f) {
  const cand = f.section === 'env' ? f.leafKey : f.section ? null : f.keyName;
  const vague = /^(?:token|auth|authorization|secret|password|api[_-]?key|key|access[_-]?token)$/i;
  if (cand && /^[A-Za-z_][A-Za-z0-9_]*$/.test(cand) && !vague.test(cand)) return cand.toUpperCase();
  const prov = f.provider && f.provider !== 'generic' && f.provider !== 'url' ? f.provider : (f.server || 'SERVICE');
  if (prov === 'huggingface') return 'HF_TOKEN';
  return `${String(prov).toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_API_KEY`;
}

function fixFor(f) {
  const prov = f.provider && f.provider !== 'generic' ? `${f.provider} ` : '';
  if (f.kind === 'history') {
    return `rotate this ${prov}key, then delete line ${f.line} from ${f.display}; pass keys via env or a prompt, not on the command line`;
  }
  if (f.kind === 'log') {
    return `rotate this ${prov}key, then delete or scrub ${f.display}; the agent wrote it to disk in clear`;
  }
  if (f.rule === 'url-credentials') {
    const name = `${String(f.server || 'SERVICE').toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_PASSWORD`;
    return `rotate this password, then take it out of the URL and pass it as \${${name}} (or the client's password env var)`;
  }
  if (f.client === 'dotenv') {
    return `rotate this ${prov}key if this file was ever committed, synced or shared; keep it in .gitignore and out of agent context`;
  }
  if (f.section === 'permissions' && /Claude Code/.test(f.client || '')) {
    const bucket = typeof f.key === 'string' && /^permissions\.[A-Za-z0-9_]+/.test(f.key)
      ? f.key.replace(/\[\d+\]$/, '')
      : 'permissions.allow';
    return `rotate this ${prov}key, then remove the entry from ${bucket}`;
  }
  const name = envName(f);
  const ref = /Claude Code|portable/.test(f.client) ? `\${${name}}` : /Cursor|VS Code/.test(f.client) ? `\${env:${name}}` : `\${${name}}`;
  if (f.section === 'headers') return `rotate this ${prov}key, then set the header to "Bearer ${ref}" and export ${name} outside the file`;
  return `rotate this ${prov}key, then replace the value with "${ref}" and export ${name} outside the file (or use a keychain/broker)`;
}

function displayPath(p, cwd, home) {
  const abs = path.resolve(p);
  const rel = path.relative(cwd, abs);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel.split(path.sep).join('/');
  if (home && (abs === home || abs.startsWith(home + path.sep))) return '~/' + path.relative(home, abs).split(path.sep).join('/');
  return abs.split(path.sep).join('/');
}

function lineIndexForValue(lines, value) {
  const escaped = JSON.stringify(value).slice(1, -1);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes(value) || line.includes(escaped)) return i;
  }
  return 0;
}

function findingScore(f) {
  const located = f.key && /(?:\ballow\b|\bdeny\b|\bask\b|permissions\.|env\.|headers\.|args\[)/.test(String(f.key)) ? 2 : (f.section ? 1 : 0);
  const specific = (f.rule === 'sensitive-key-name' || f.rule === 'generic-api-key') ? 0 : 1;
  return (SEVERITY_ORDER[f.severity] || 0) * 10 + located + specific;
}

function sameSecret(a, b) {
  if (a.file !== b.file || a.line !== b.line) return false;
  return a.value === b.value || a.value.includes(b.value) || b.value.includes(a.value);
}

// Prefer the higher-severity, correctly-located finding when a raw line and
// an unescaped leaf both hit the same secret (e.g. KEY vs KEY\).
function mergeFindings(findings) {
  const kept = [];
  const ranked = findings.slice().sort((a, b) => findingScore(b) - findingScore(a));
  for (const f of ranked) {
    if (kept.some((k) => sameSecret(k, f))) continue;
    kept.push(f);
  }
  return kept;
}

function scanFile(target, ctx) {
  let st;
  try { st = fs.statSync(target.path); } catch (e) { return null; }
  if (!st.isFile()) return null;
  if (st.size > MAX_BYTES) { ctx.skipped.push({ path: target.path, reason: 'larger than 50 MB' }); return null; }
  let text;
  try { text = fs.readFileSync(target.path, 'utf8'); } catch (e) { ctx.skipped.push({ path: target.path, reason: 'unreadable' }); return null; }
  if (text.includes('\u0000')) return []; // binary
  const display = displayPath(target.path, ctx.cwd, ctx.home);
  const isJson = target.kind === 'config' && /\.jsonc?$/i.test(target.path);
  const leaves = isJson ? jsonLeaves(text) : null;
  const lines = text.split(/\r?\n/);
  const findings = [];
  const addHit = (hit, lineIdx, fromLeaf) => {
    const where = isJson ? locate(leaves, hit.value, { leaf: fromLeaf, line: lineIdx, lines }) : {};
    if (!where.server && /\.toml$/i.test(target.path)) where.server = tomlServer(lines, lineIdx);
    const f = {
      kind: target.kind, client: target.client, file: display, line: lineIdx + 1, display: `${display}`,
      server: where.server, key: where.key || hit.keyName, section: where.section, leafKey: where.leafKey,
      keyName: hit.keyName, rule: hit.rule, provider: hit.provider, severity: hit.severity, value: hit.value,
    };
    f.fix = fixFor(f);
    findings.push(f);
  };
  lines.forEach((line, i) => {
    if (!line) return;
    for (const hit of scanLine(line, display, target.kind)) addHit(hit, i);
  });
  // Also scan unescaped JSON string leaves. A key inside a JSON-escaped
  // header (\"x-api-key: KEY\") is otherwise only seen with a trailing
  // backslash, which downgrades the hit and breaks locate().
  if (leaves) {
    for (const leaf of leaves) {
      if (!leaf.value) continue;
      const lineIdx = lineIndexForValue(lines, leaf.value);
      for (const hit of scanLine(leaf.value, display, target.kind)) addHit(hit, lineIdx, leaf);
    }
  }
  return mergeFindings(findings);
}

function buildTargets(opts) {
  const targets = [];
  const add = (t) => { if (!targets.some((x) => path.resolve(x.path) === path.resolve(t.path))) targets.push(t); };
  const useGlobal = !opts.paths.length || opts.global;
  if (useGlobal) {
    for (const loc of globalLocations({ home: opts.home, env: opts.env, platform: opts.platform })) {
      if (loc.kind === 'history' && !opts.history) continue;
      if (loc.kind === 'log') {
        if (!opts.logs) continue;
        for (const p of walkLog(loc.path)) add({ ...loc, path: p });
        continue;
      }
      add(loc);
    }
    if (!opts.paths.length) {
      for (const [kind, client, rel] of PROJECT_FILES) {
        if (kind === 'log' && !opts.logs) continue;
        add({ kind, client, path: path.join(opts.cwd, rel) });
      }
    }
  }
  for (const p of opts.paths) for (const t of walkPath(path.resolve(opts.cwd, p))) add(t);
  return targets;
}

function scan(opts) {
  const o = {
    paths: [], global: false, history: true, logs: true, minSeverity: 'low',
    cwd: process.cwd(), home: os.homedir(), env: process.env, platform: process.platform, ...opts,
  };
  o.home = path.resolve(o.home);
  const ctx = { cwd: path.resolve(o.cwd), home: o.home, skipped: [] };
  const targets = buildTargets(o);
  if (typeof o.onStart === 'function') {
    let bytes = 0;
    let logs = 0;
    for (const t of targets) {
      if (t.kind !== 'log') continue;
      logs++;
      try { bytes += fs.statSync(t.path).size; } catch (e) { /* gone */ }
    }
    o.onStart({ files: targets.length, logs, logBytes: bytes });
  }
  const scanned = [];
  let findings = [];
  for (const t of targets) {
    const res = scanFile(t, ctx);
    if (res === null) continue;
    scanned.push({ kind: t.kind, client: t.client, file: displayPath(t.path, ctx.cwd, ctx.home) });
    findings.push(...res);
  }
  const min = SEVERITY_ORDER[o.minSeverity] || 1;
  findings = findings.filter((f) => SEVERITY_ORDER[f.severity] >= min);
  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  return { scanned, findings, skipped: ctx.skipped.map((s) => ({ ...s, path: displayPath(s.path, ctx.cwd, ctx.home) })) };
}

module.exports = { scan, stripJsonc, displayPath };
