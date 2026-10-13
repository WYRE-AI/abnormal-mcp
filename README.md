# abnormal-mcp

MCP server for [Abnormal Security](https://abnormalsecurity.com/) — AI-powered threat detection, case management, and email remediation.

## Tools

This server uses a decision-tree architecture. Start by calling `abnormal_navigate` to select a domain, then use the domain-specific tools.

### Navigation

| Tool | Description |
|------|-------------|
| `abnormal_navigate` | Navigate to a domain (threats, messages, remediation, abuse, cases) |
| `abnormal_back` | Return to domain selection |

### Threats domain

| Tool | Description |
|------|-------------|
| `abnormal_threats_list` | List detected threat cases (paginated) |
| `abnormal_threats_get` | Get full details of a specific threat by ID |

### Messages domain

| Tool | Description |
|------|-------------|
| `abnormal_messages_list` | List messages within a threat case |
| `abnormal_messages_get` | Get detailed message analysis (headers, URLs, attachments, AI analysis) |

### Remediation domain

| Tool | Description |
|------|-------------|
| `abnormal_remediation_manage` | Trigger or check remediation actions for a message |

### Abuse domain

| Tool | Description |
|------|-------------|
| `abnormal_abuse_list` | List phishing emails reported via the Abuse Mailbox |

### Cases domain

| Tool | Description |
|------|-------------|
| `abnormal_cases_list` | List active security investigation cases |
| `abnormal_cases_get` | Get details of a specific case |

### Interactive Threat Card (MCP Apps)

- `abnormal_threats_get` renders as an interactive threat card in MCP Apps
  hosts (Claude Desktop/web): subject, sender, attack classification,
  remediation status, and the messages in the threat. The card is read-only —
  remediation stays a deliberate, model-mediated action. Plain-JSON behavior
  is unchanged in other hosts. Neutral by default, brandable via
  `window.__BRAND__` injection or `MCP_BRAND_*` env vars (`MCP_BRAND_NAME`,
  `MCP_BRAND_LOGO_URL`, `MCP_BRAND_PRIMARY_COLOR`, `MCP_BRAND_ACCENT_COLOR`,
  `MCP_BRAND_BG`, `MCP_BRAND_TEXT`) — no rebuild needed.

## Authentication

Abnormal Security uses Bearer token authentication. Copy [`.env.example`](.env.example) and set the variables below.

| Variable | Required | Description |
|----------|----------|-------------|
| `ABNORMAL_API_TOKEN` | For stdio and `AUTH_MODE=env` | Abnormal Security API token. Generate it in the Abnormal portal under **Settings > Integrations > API**. |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `AUTH_MODE` | No | `env` (default outside Docker) or `gateway`. The image and Compose service set `gateway`. Gateway mode requires `Authorization: Bearer` on each `/mcp` request and never falls back to `ABNORMAL_API_TOKEN`. |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service secret. Generate one with `openssl rand -hex 32`. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `placeholder`, `your-s2s-secret`, `replace-with-a-real-secret`, and similar example values). Compose will not start without it. Never commit a real value. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` (including `0.0.0.0`) is ignored and the override is logged. A known placeholder secret is still refused. |
| `MCP_HTTP_HOST` | No | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1` when unset. A configured secret honors this value. The container image sets `0.0.0.0`. With no secret, the insecure-dev bypass forces `127.0.0.1`. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |

`/health` stays unauthenticated and does not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### X-Gateway-S2S signing

With `MCP_TRANSPORT=http` and a real `CONDUIT_S2S_SECRET`, every `/mcp` request must include `X-Gateway-S2S`. The header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header returns 401 before the Abnormal token is read.

```bash
TS=$(date +%s)
SIG=$(printf 't=%s' "$TS" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "X-Gateway-S2S: t=${TS},v1=${SIG}" \
  -H "Authorization: Bearer $ABNORMAL_API_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway` that `Authorization` header is required and is the only credential source. `AUTH_MODE=env` still requires a valid `X-Gateway-S2S` header, then uses `ABNORMAL_API_TOKEN` from the environment when the request does not carry `Authorization`.

### Standalone (env mode)

```bash
export ABNORMAL_API_TOKEN=your-api-token
node dist/index.js
```

### Gateway mode

When deployed behind the MCP gateway, set `AUTH_MODE=gateway`. The gateway signs each `/mcp` request with `X-Gateway-S2S` and injects `Authorization: Bearer {token}`. Requests missing that credential header are rejected with 401.

## Running

### stdio (for Claude Desktop)

```bash
npm install
npm run build
node dist/index.js
```

### HTTP Streamable (for hosted/gateway deployment)

HTTP refuses to start until `CONDUIT_S2S_SECRET` is a real secret:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" MCP_TRANSPORT=http AUTH_MODE=gateway node dist/index.js
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` only and logs a warning:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```

### Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass the S2S secret. In gateway mode the API token arrives on each request as `Authorization`; the image does not read `ABNORMAL_API_TOKEN`.

```bash
docker build -t abnormal-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  abnormal-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, sets `AUTH_MODE=gateway`, does not inject `ABNORMAL_API_TOKEN`, and publishes `127.0.0.1:8080:8080`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `ABNORMAL_API_TOKEN`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e ABNORMAL_API_TOKEN=your-api-token \
  -p 127.0.0.1:8080:8080 \
  abnormal-mcp
```

## Development

```bash
npm install
npm run dev          # watch mode
npm test             # run tests
npm run typecheck    # TypeScript type check
npm run build:ui     # rebuild the MCP Apps card bundle (only needed when ui/ changes)
```

## License

Apache-2.0
