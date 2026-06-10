# Publishing checklist

Distribution is GitHub-only — no npm-registry account required.

## Per-release routine

1. Bump `version` in `package.json`, `manifest.json`, and `server.json` (top-level + `packages[0].version`).
2. Build + pack the MCPB bundle (one-click installable in Claude Desktop):

   ```bash
   npm ci && npm run build
   npm prune --omit=dev                       # bundle only runtime deps
   npx @anthropic-ai/mcpb pack . xahau-mcp-<version>.mcpb
   npm install                                # restore dev deps
   ```

3. Cut the GitHub release and attach the bundle:

   ```bash
   gh release create v<version> xahau-mcp-<version>.mcpb --title "..." --notes "..."
   ```

4. Update `server.json` `packages[0]`:
   - `identifier`: the release asset download URL
   - `fileSha256`: `shasum -a 256 xahau-mcp-<version>.mcpb`

5. Publish metadata to the official MCP Registry:

   ```bash
   brew install mcp-publisher          # one-time
   mcp-publisher login github          # one-time, device-code flow (authorizes io.github.hugegreencandle/*)
   mcp-publisher publish               # reads ./server.json
   ```

   Verify: `curl "https://registry.modelcontextprotocol.io/v0/servers?search=xahau"`

## Notes

- The MCP Registry hosts metadata only; it fetches the release asset and checks `fileSha256`.
- `package.json` keeps `mcpName: io.github.hugegreencandle/xahau-mcp` — harmless now, and required in the
  published tarball if an npm-registry publish ever happens later (npm is optional: it would add
  `npx xahau-mcp` convenience + public download stats, nothing else).
- Direct GitHub install for humans stays: `npm install -g github:Hugegreencandle/xahau-mcp`.

## Directories that index automatically (no action)

- **Glama** — indexes public GitHub repos; claim the listing at https://glama.ai/mcp/servers if desired.
- **PulseMCP** — crawls the official registry; appears after step 5.
- **awesome-mcp-servers** — PR-based (Finance & Fintech section); PR #7794 opened 2026-06-11.
