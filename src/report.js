'use strict';
// Everything user-visible is built here from an allow-list of fields.
// The raw value never leaves this module except as redact(value).
const { redact } = require('./detect');

const FOOTER = 'scanned with npx mcp-keyscan';

function publicFinding(f) {
  return {
    severity: f.severity, kind: f.kind, client: f.client, file: f.file, line: f.line,
    server: f.server || null, key: f.key || null, provider: f.provider, rule: f.rule,
    preview: redact(f.value), fix: f.fix,
  };
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function counts(findings) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function textReport(result, { version }) {
  const findings = result.findings.map(publicFinding);
  const kinds = { config: 0, log: 0, history: 0 };
  for (const s of result.scanned) kinds[s.kind] = (kinds[s.kind] || 0) + 1;
  const c = counts(findings);
  const L = [];
  L.push(`# mcp-keyscan report (v${version})`);
  L.push('');
  L.push(`Scanned ${result.scanned.length} file${result.scanned.length === 1 ? '' : 's'} on this machine: ${plural(kinds.config, 'agent/MCP config')}, ${plural(kinds.log, 'agent log')}, ${plural(kinds.history, 'shell history', 'shell histories')}. Nothing left this machine.`);
  if (!findings.length) {
    L.push('');
    L.push('No plaintext secrets found.');
  } else {
    L.push(`Found ${findings.length} plaintext secret${findings.length === 1 ? '' : 's'}: ${c.high} high, ${c.medium} medium, ${c.low} low.`);
    L.push('Values are redacted (first 4 characters + length). This report is safe to share.');
    findings.forEach((f, i) => {
      const where = [f.server && `server ${f.server}`, f.key].filter(Boolean).join(' · ');
      L.push('');
      L.push(`${i + 1}. [${f.severity.toUpperCase()}] ${f.file}:${f.line} (${f.client}${where ? `, ${where}` : ''})`);
      L.push(`   ${f.rule} · ${f.provider} · ${f.preview}`);
      L.push(`   fix: ${f.fix}`);
    });
  }
  if (result.skipped.length) {
    L.push('');
    L.push(`Skipped ${result.skipped.length} file(s): ${result.skipped.slice(0, 5).map((s) => `${s.path} (${s.reason})`).join(', ')}${result.skipped.length > 5 ? ', …' : ''}`);
  }
  L.push('');
  L.push(FOOTER);
  return L.join('\n') + '\n';
}

function jsonReport(result, { version }) {
  const findings = result.findings.map(publicFinding);
  return JSON.stringify({
    tool: 'mcp-keyscan', version, summary: { scanned: result.scanned.length, findings: findings.length, ...counts(findings) },
    findings, scanned: result.scanned, skipped: result.skipped, footer: FOOTER,
  }, null, 2) + '\n';
}

module.exports = { textReport, jsonReport, publicFinding, FOOTER };
