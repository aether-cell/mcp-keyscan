'use strict';
// Loads the vendored gitleaks rule set (rules/gitleaks.json, MIT) and adapts
// Go RE2 syntax to JavaScript RegExp. No network access, no rule invention.
const fs = require('fs');
const path = require('path');

const RULES_FILE = path.join(__dirname, '..', 'rules', 'gitleaks.json');

// Convert one RE2 pattern to { source, flags }. JavaScript (Node 18-22) has no
// inline modifiers, so (?i) anywhere makes the whole regex case-insensitive and
// (?-i:...) groups become plain groups. This is slightly looser than gitleaks,
// never stricter, so no gitleaks hit is lost.
function toJs(re2) {
  let src = re2;
  let flags = '';
  const lead = /^\(\?([imsU]+)\)/.exec(src);
  if (lead) {
    src = src.slice(lead[0].length);
    if (lead[1].includes('i')) flags += 'i';
    if (lead[1].includes('s')) flags += 's';
    if (lead[1].includes('m')) flags += 'm';
  }
  if (/\(\?[a-z]*i[a-z]*[:)]/.test(src) && !flags.includes('i')) flags += 'i';
  if (/\(\?[a-z]*s[a-z]*:/.test(src) && !flags.includes('s')) flags += 's';
  src = src
    .replace(/\(\?-?[imsU]+(?:-[imsU]+)?:/g, '(?:')
    .replace(/\(\?-?[imsU]+\)/g, '')
    .replace(/\(\?P</g, '(?<')
    .replace(/\\z/g, '$')
    .replace(/\\A/g, '^');
  return { source: src, flags };
}

function compile(re2, extra = '') {
  const { source, flags } = toJs(re2);
  return new RegExp(source, Array.from(new Set((flags + extra).split(''))).join(''));
}

let cached = null;

function loadRules() {
  if (cached) return cached;
  const data = JSON.parse(fs.readFileSync(RULES_FILE, 'utf8'));
  const rules = [];
  const skipped = [];
  for (const r of data.rules) {
    try {
      rules.push({
        id: r.id,
        regex: compile(r.regex, 'g'),
        secretGroup: r.secretGroup || 0,
        entropy: r.entropy || 0,
        keywords: (r.keywords || []).map((k) => k.toLowerCase()),
        path: r.path ? compile(r.path) : null,
        allowlists: (r.allowlists || []).map((a) => ({
          target: a.regexTarget || 'secret',
          regexes: (a.regexes || []).map((x) => compile(x)),
          stopwords: (a.stopwords || []).map((s) => s.toLowerCase()),
          condition: a.condition || 'OR',
        })),
      });
    } catch (e) {
      skipped.push(r.id);
    }
  }
  const globalAllow = {
    regexes: ((data.allowlist && data.allowlist.regexes) || []).flatMap((x) => {
      try { return [compile(x)]; } catch (e) { return []; }
    }),
    stopwords: ((data.allowlist && data.allowlist.stopwords) || []).map((s) => s.toLowerCase()),
  };
  cached = { rules, skipped, globalAllow, source: data.source };
  return cached;
}

module.exports = { loadRules, toJs };
