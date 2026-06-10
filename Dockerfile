# Build and run the xahau-mcp stdio server.
# Used by MCP directory inspectors (e.g. Glama) to boot the server for introspection.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
COPY data ./data
RUN npm ci --ignore-scripts && npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
COPY data ./data
ENTRYPOINT ["node", "dist/index.js"]
