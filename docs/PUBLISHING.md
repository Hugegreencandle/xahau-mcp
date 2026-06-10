# Publishing checklist

## 1. npm registry (one-time account auth, then per release)

`package.json` already carries the `mcpName` field the MCP Registry validates against
(`io.github.hugegreencandle/xahau-mcp`) — it **must** be present in the published tarball,
so always publish to npm *after* any `mcpName`/version bump.

```bash
npm login          # one-time
npm publish        # name `xahau-mcp` is unscoped and free
```

Verify: https://www.npmjs.com/package/xahau-mcp

## 2. Official MCP Registry (after npm publish)

Metadata lives in [`server.json`](../server.json) at the repo root. The registry only hosts
metadata — it verifies the npm package's `mcpName` matches.

```bash
brew install mcp-publisher          # one-time
mcp-publisher login github          # one-time, device-code flow (authorizes io.github.hugegreencandle/*)
mcp-publisher publish               # reads ./server.json
```

Verify: `curl "https://registry.modelcontextprotocol.io/v0/servers?search=xahau"`

## Per-release routine

1. Bump `version` in `package.json` **and** in `server.json` (top-level + `packages[0].version`).
2. `npm publish`
3. `mcp-publisher publish`

## Directories that index automatically (no action)

- **Glama** — indexes public GitHub repos; claim the listing at https://glama.ai/mcp/servers if desired.
- **PulseMCP** — crawls the official registry; appears after step 2.
- **awesome-mcp-servers** — PR-based (Finance & Fintech section).
