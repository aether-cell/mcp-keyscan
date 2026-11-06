'use strict';
// Secret detection. Pure functions, no I/O.
// Primary detector: the vendored gitleaks rule set (see src/rules.js).
// Supplement: ONE key-name heuristic for config assignments
// (e.g. "ANTHROPIC_API_KEY": "..."), because gitleaks' provider rules are
// strict about exact key lengths and agent configs are mostly NAME=value.
//
// A Hit's `value` is the secret itself. It must only ever be passed to redact().
const { loadRules } = require('./rules');

const SEVERITY_ORDER = { low: 1, medium: 2, high: 3 };
const CHUNK = 65536;

function entropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// Never show the value: first 4 chars + length; values of 8 chars or less show nothing.
function redact(value) {
  const v = String(value);
  const n = Array.from(v).length;
  if (n <= 8) return `****(${n} chars)`;
  return `${Array.from(v).slice(0, 4).join('')}…(${n} chars)`;
}

const REFERENCE = [
  /^\$\{[^}]*\}$/, /^\$[A-Za-z_][A-Za-z0-9_]*$/, /^%[A-Za-z_][A-Za-z0-9_]*%$/, /^\{\{.*\}\}$/,
  /^<[^>]*>$/, /^(?:op|vault|keychain|secret|env|bws|doppler|infisical|gcpsm|awssm|azkv):\/\//i,
];
const PLACEHOLDER = /your[-_ ]?(?:api[-_ ]?)?(?:key|token|secret)|xxxx|changeme|change[-_]me|placeholder|redacted|example|dummy|insert[-_ ]|replace[-_ ]?me|\*{4,}|^(.)\1+$/i;

function isPlaceholder(value) {
  const v = String(value).trim().replace(/^["'`]|["'`]$/g, '');
  if (!v) return true;
  if (REFERENCE.some((r) => r.test(v))) return true;
  if (/\$\{[^}]+\}|\$\([^)]+\)/.test(v)) return true; // contains a ${VAR} / $(cmd) reference
  return PLACEHOLDER.test(v);
}

function allowed(allow, secret, match, line) {
  const s = secret.toLowerCase();
  if (allow.stopwords && allow.stopwords.some((w) => s.includes(w))) return true;
  const target = allow.target === 'match' ? match : allow.target === 'line' ? line : secret;
  return (allow.regexes || []).some((r) => r.test(target));
}

function pickSecret(m, group) {
  if (group && m[group] !== undefined) return m[group];
  for (let i = 1; i < m.length; i++) if (m[i]) return m[i];
  return m[0];
}

const PROVIDER_HINT = /^([a-z0-9]+)-/;

function severityFor(ruleId) {
  if (ruleId === 'generic-api-key') return 'medium';
  return 'high';
}

function providerFor(ruleId) {
  if (ruleId.startsWith('generic')) return 'generic';
  const m = PROVIDER_HINT.exec(ruleId);
  return m ? m[1] : ruleId;
}

// Keyword prefilter (as in gitleaks): find every rule keyword present in the line in one pass.
let kwIndex = null;
function keywordsIn(lower) {
  if (!kwIndex) {
    const all = [...new Set(loadRules().rules.flatMap((r) => r.keywords))].sort((a, b) => b.length - a.length);
    const byFirst = new Map();
    for (const k of all) { if (!byFirst.has(k[0])) byFirst.set(k[0], []); byFirst.get(k[0]).push(k); }
    const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    kwIndex = { re: new RegExp(all.map(esc).join('|'), 'g'), byFirst };
  }
  const found = new Set();
  const { re, byFirst } = kwIndex;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(lower)) !== null) {
    for (const k of byFirst.get(lower[m.index]) || []) if (lower.startsWith(k, m.index)) found.add(k);
    re.lastIndex = m.index + 1;
  }
  return found;
}

function gitleaksLine(line, filePath, kind) {
  const { rules, globalAllow } = loadRules();
  const present = keywordsIn(line.toLowerCase());
  const out = [];
  for (const rule of rules) {
    if (rule.keywords.length && !rule.keywords.some((k) => present.has(k))) continue;
    if (rule.path && filePath && !rule.path.test(filePath)) continue;
    if (kind === 'log' && rule.id === 'generic-api-key') continue;
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(line)) !== null) {
      if (m[0] === '') { rule.regex.lastIndex++; continue; }
      const secret = pickSecret(m, rule.secretGroup);
      if (!secret) continue;
      if (rule.entropy && entropy(secret) < rule.entropy) continue;
      if (globalAllow.regexes.some((r) => r.test(secret))) continue;
      if (rule.allowlists.some((a) => allowed(a, secret, m[0], line))) continue;
      if (isPlaceholder(secret)) continue;
      const prov = providerFor(rule.id);
      out.push({ rule: rule.id, provider: ['generic', 'curl'].includes(prov) ? providerFromName('', secret) : prov, severity: severityFor(rule.id), value: secret, source: 'gitleaks' });
    }
  }
  return out;
}

// Key-name heuristic: NAME=value, "NAME": "value", NAME: value, --name value / --name=value,
// "Authorization: Bearer value", scheme://user:password@host.
const SENSITIVE_NAME = '[A-Za-z0-9_.-]{0,40}?(?:api[_-]?key|apikey|token|secret|passw(?:or)?d|credential|auth|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]{0,40}';
const SENSITIVE_QUICK = /api[_-]?key|apikey|token|secret|passw|credential|auth|private[_-]?key|access[_-]?key|:\/\/[^\s/]*:[^\s/]*@/i;
const ASSIGN = new RegExp(
  `(?:^|[\\s{,;"'?&])["']?(${SENSITIVE_NAME})["']?\\s*(?:=|:)\\s*["']?(?:Bearer\\s+|Basic\\s+|token\\s+)?([^\\s"',;}]{12,})`, 'gi');
const FLAG = new RegExp(`--(${SENSITIVE_NAME})(?:=|["',\\s]+)["']?([^\\s"',\\]]{12,})`, 'gi');
const URL_CRED = /[a-z][a-z0-9+.-]*:\/\/[^\s:@/"']+:([^\s@/"']{6,})@/gi;
const NON_SECRET_NAME = /(?:_id|_url|_uri|_path|_file|_dir|_name|_type|_host|_port|_region|_endpoint|_version|_env|_mode|_level|_count|_size|_ttl|_timeout|_expires?(?:_at)?|max_tokens?|_tokens?_limit|tokenizer)$/i;

function looksSecret(v) {
  if (v.length < 12) return false;
  if (/^(?:https?|file|wss?):\/\//i.test(v)) return false;
  if (/^[\d.:-]+$/.test(v)) return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return false; // UUID ids
  if (/^[a-z]+(?:[-_.][a-z0-9]+)*$/.test(v) && !/\d/.test(v)) return false; // plain words
  if (!/[A-Za-z]/.test(v) || !/\d/.test(v)) return false;
  return entropy(v) >= 3.0;
}

function heuristicLine(line) {
  const out = [];
  if (!SENSITIVE_QUICK.test(line)) return out;
  for (const rx of [ASSIGN, FLAG]) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(line)) !== null) {
      const name = m[1];
      const value = m[2].replace(/[)\]>]+$/, '');
      if (NON_SECRET_NAME.test(name) || isPlaceholder(value) || !looksSecret(value)) continue;
      out.push({ rule: 'sensitive-key-name', provider: providerFromName(name, value), severity: 'medium', value, keyName: name, source: 'heuristic' });
    }
  }
  URL_CRED.lastIndex = 0;
  let m;
  while ((m = URL_CRED.exec(line)) !== null) {
    if (isPlaceholder(m[1])) continue;
    out.push({ rule: 'url-credentials', provider: 'url', severity: 'medium', value: m[1], source: 'heuristic' });
  }
  return out;
}

const NAME_PROVIDERS = ['anthropic', 'openai', 'github', 'gitlab', 'aws', 'google', 'gemini', 'slack', 'stripe',
  'notion', 'brave', 'linear', 'supabase', 'huggingface', 'hf', 'azure', 'perplexity', 'groq', 'mistral',
  'tavily', 'exa', 'firecrawl', 'cloudflare', 'vercel', 'sentry', 'postgres', 'database', 'jira', 'atlassian'];
// Label only (not detection): well-known value prefixes -> provider.
const VALUE_PREFIXES = [['sk-ant-', 'anthropic'], ['sk-', 'openai'], ['ghp_', 'github'], ['gho_', 'github'], ['ghu_', 'github'],
  ['ghs_', 'github'], ['github_pat_', 'github'], ['glpat-', 'gitlab'], ['AIza', 'google'], ['xox', 'slack'], ['hf_', 'huggingface'],
  ['ntn_', 'notion'], ['secret_', 'notion'], ['lin_api_', 'linear'], ['sk_live_', 'stripe'], ['rk_live_', 'stripe'], ['AKIA', 'aws'],
  ['pplx-', 'perplexity'], ['gsk_', 'groq'], ['tvly-', 'tavily'], ['fc-', 'firecrawl'], ['BSA', 'brave'], ['sbp_', 'supabase']];
function providerFromName(name, value) {
  const n = String(name || '').toLowerCase();
  const byName = NAME_PROVIDERS.find((p) => n.includes(p));
  if (byName) return byName;
  const pre = VALUE_PREFIXES.find(([pfx]) => String(value || '').startsWith(pfx));
  return pre ? pre[1] : 'generic';
}

// Scan one line of text. Returns Hits; overlapping hits for the same value are merged
// (gitleaks provider rules win over generic ones and the heuristic).
function scanLine(line, filePath, kind) {
  const parts = [];
  if (line.length <= CHUNK) parts.push(line);
  else for (let i = 0; i < line.length; i += CHUNK - 1024) parts.push(line.slice(i, i + CHUNK));
  const hits = [];
  for (const part of parts) hits.push(...gitleaksLine(part, filePath, kind), ...heuristicLine(part));
  const rank = (h) => (h.source === 'gitleaks' && h.rule !== 'generic-api-key' ? 0 : h.source === 'gitleaks' ? 1 : 2);
  hits.sort((a, b) => rank(a) - rank(b));
  const kept = [];
  for (const h of hits) {
    if (kept.some((k) => k.value.includes(h.value) || h.value.includes(k.value))) continue;
    kept.push(h);
  }
  return kept;
}

module.exports = { scanLine, redact, entropy, isPlaceholder, SEVERITY_ORDER, providerFromName };
