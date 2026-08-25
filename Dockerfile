# Multi-stage build for efficient container size
FROM node:26-alpine AS builder

ARG VERSION="unknown"
ARG COMMIT_SHA="unknown"
ARG BUILD_DATE="unknown"

WORKDIR /app

COPY package*.json ./
COPY .npmrc ./

# --ignore-scripts prevents 'prepare' from running before source is copied
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM node:26-alpine AS production

# Pull latest Alpine package fixes (e.g. OpenSSL) even when the base layer is cached
RUN apk -U upgrade --no-cache

RUN addgroup -g 1001 -S abnormal && \
    adduser -S abnormal -u 1001 -G abnormal

WORKDIR /app

COPY package*.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

RUN npm prune --omit=dev && npm cache clean --force

# Remove the npm CLI from the production image (not needed at runtime; clears Trivy CVEs)
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

RUN mkdir -p /app/logs && chown -R abnormal:abnormal /app

USER abnormal

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV MCP_TRANSPORT=http
ENV MCP_HTTP_PORT=8080
ENV MCP_HTTP_HOST=0.0.0.0
# Set to 'gateway' for hosted deployment; 'env' for standalone use
ENV AUTH_MODE=env

VOLUME ["/app/logs"]

CMD ["node", "dist/index.js"]

LABEL maintainer="engineering@wyre.ai"
LABEL version="${VERSION}"
LABEL description="Abnormal Security MCP Server"
LABEL org.opencontainers.image.title="abnormal-mcp"
LABEL org.opencontainers.image.description="MCP server for Abnormal Security — AI-powered threat detection, case management, and email remediation"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${COMMIT_SHA}"
LABEL org.opencontainers.image.source="https://github.com/WYRE-AI/abnormal-mcp"
LABEL org.opencontainers.image.vendor="Wyre Technology"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.modelcontextprotocol.server.name="io.github.WYRE-AI/abnormal-mcp"
