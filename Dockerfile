# Runs mcp-keyscan as a stdio MCP server (tool: scan_secrets).
# Zero dependencies; read-only, local-only, no network calls.
# To scan your machine, mount the paths read-only, e.g.:
#   docker run -i --rm -v "$HOME:/host:ro" -e HOME=/host mcp-keyscan
FROM node:20-alpine
WORKDIR /app
COPY package.json LICENSE NOTICE README.md AGENTS.md llms.txt ./
COPY bin ./bin
COPY src ./src
COPY rules ./rules
USER node
ENTRYPOINT ["node", "bin/mcp-keyscan.js", "--mcp"]
