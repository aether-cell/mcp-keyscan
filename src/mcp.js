'use strict';
// Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0), zero dependencies.
// One tool: scan_secrets. It returns only the redacted report / redacted JSON,
// so the calling agent never sees a secret value either.
const readline = require('readline');
const { scan } = require('./scan');
const { textReport, jsonReport } = require('./report');

const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const TOOL = {
  name: 'scan_secrets',
  title: 'Scan for plaintext secrets (redacted)',
  description: 'Scan this machine\'s AI-agent / MCP client configs, agent logs and transcripts, and shell history for plaintext API keys. '
    + 'Returns a redacted, shareable report (first 4 characters + length per secret, never the value) with a one-line fix per finding. '
    + 'Local only; reads files, never writes or sends anything.',
  inputSchema: {
    type: 'object',
    properties: {
      paths: { type: 'array', items: { type: 'string' }, description: 'Files or directories to walk instead of the default per-user locations.' },
      include_logs: { type: 'boolean', description: 'Scan agent logs and transcripts (default true).' },
      include_history: { type: 'boolean', description: 'Scan shell history (default true).' },
      min_severity: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Minimum severity to report (default low).' },
      format: { type: 'string', enum: ['text', 'json'], description: 'text = shareable report (default), json = redacted findings.' },
    },
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

function serve({ version, input = process.stdin, output = process.stdout }) {
  const send = (msg) => output.write(JSON.stringify(msg) + '\n');
  const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
  const fail = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

  const handle = (msg) => {
    const { id, method, params = {} } = msg;
    const isRequest = id !== undefined && id !== null;
    switch (method) {
      case 'initialize': {
        const asked = params.protocolVersion;
        return reply(id, {
          protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'mcp-keyscan', title: 'mcp-keyscan', version },
          instructions: 'Call scan_secrets to find plaintext API keys on this machine. Output is always redacted; never ask the user to paste a key.',
        });
      }
      case 'ping': return reply(id, {});
      case 'tools/list': return reply(id, { tools: [TOOL] });
      case 'tools/call': {
        if (params.name !== TOOL.name) return fail(id, -32602, `unknown tool ${params.name}`);
        const a = params.arguments || {};
        try {
          const result = scan({
            paths: Array.isArray(a.paths) ? a.paths.map(String) : [],
            logs: a.include_logs !== false,
            history: a.include_history !== false,
            minSeverity: ['low', 'medium', 'high'].includes(a.min_severity) ? a.min_severity : 'low',
          });
          const text = a.format === 'json' ? jsonReport(result, { version }) : textReport(result, { version });
          return reply(id, { content: [{ type: 'text', text }], isError: false });
        } catch (e) {
          return reply(id, { content: [{ type: 'text', text: `scan failed: ${e.message}` }], isError: true });
        }
      }
      default:
        if (isRequest) return fail(id, -32601, `method not found: ${method}`);
        return undefined; // notifications (initialized, cancelled, ...) need no answer
    }
  };

  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch (e) { return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
    for (const m of Array.isArray(msg) ? msg : [msg]) handle(m);
  });
  return rl;
}

module.exports = { serve, TOOL };
