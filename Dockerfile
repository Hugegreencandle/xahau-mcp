# Two images from one file:
#   docker build -t xahau-mcp .                      -> stdio MCP server (default; Glama introspection)
#   docker build --target http -t xahau-mcp-http .   -> the HTTP shim (browsers / Xaman / web tools)
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
COPY data ./data
RUN npm ci --ignore-scripts && npm run build

# Shared production runtime (deps + dist + data, non-root).
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
COPY data ./data
USER node

# HTTP shim — serves untrusted wasm; each hook runs in a memory-capped worker with
# a hard timeout (see src/isolated.ts). Tune at runtime with -e (RL_MAX,
# MAX_INFLIGHT, XAHC_HOOK_TIMEOUT_MS, XAHC_HOOK_MEM_MB, XAHC_SIM_SPACING_MS,
# TRUST_PROXY, XAHAU_RPC_URLS). Run behind a restart policy for defense-in-depth.
FROM runtime AS http
ENV PORT=8787
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["node", "dist/http.js"]

# stdio MCP server (DEFAULT — keep last so a bare `docker build` yields it).
FROM runtime AS stdio
ENTRYPOINT ["node", "dist/index.js"]
