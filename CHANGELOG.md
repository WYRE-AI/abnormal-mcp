# 1.0.0 (2026-04-07)


### Bug Fixes

* **ci:** deploy :latest tag, force revision via env var bump ([6bdfc63](https://github.com/WYRE-AI/abnormal-mcp/commit/6bdfc6378848815eb7ebd3981412b8fbf4c9324e))


### Features

* **init:** scaffold Abnormal Security MCP server ([a9df46f](https://github.com/WYRE-AI/abnormal-mcp/commit/a9df46f30e7741963e2c4ffa3f6ef2232cbf323a))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Interactive threat card via MCP Apps (SEP-1865).** `abnormal_threats_get` results now render as an interactive card in MCP Apps hosts (Claude Desktop/web, and other hosts advertising the `io.modelcontextprotocol/ui` extension), instead of a wall of JSON. The card shows the threat's subject, sender, recipient, attack type/strategy/vector, impersonated party, remediation status, and the recent messages in the threat. The card is **read-only** by policy — email-security remediation stays a deliberate, model-mediated action (`abnormal_remediation_manage`), never a one-click card button. Non-App hosts are unaffected: the tool's JSON payload is unchanged apart from a new `_card` field.
  - The renderable tool advertises the UI via `_meta` (`ui/resourceUri`, plus the nested `ui.resourceUri` form) pointing at a new `ui://abnormal/threat-card.html` resource served as `text/html;profile=mcp-app`. The card HTML is a self-contained vite single-file bundle embedded at build time (`src/generated/threat-card-html.ts`, committed), so it serves identically from stdio, Node HTTP, and fs-less runtimes. The server now declares the `resources` capability and answers `resources/list` / `resources/read` (`src/resources.ts`).
  - The card is neutral by default (system fonts, no operator identity, no external fetches) and brandable via `window.__BRAND__` injection or `MCP_BRAND_*` env vars (`MCP_BRAND_NAME`, `MCP_BRAND_LOGO_URL`, `MCP_BRAND_PRIMARY_COLOR`, `MCP_BRAND_ACCENT_COLOR`, `MCP_BRAND_BG`, `MCP_BRAND_TEXT`): at serve time the server replaces the card's BRAND_INJECT marker with an inline, `<`-escaped `window.__BRAND__` script, so self-hosters can theme the card without rebuilding. No brand configured = HTML served unchanged.
  - The card payload builder is best-effort: an unexpected API shape degrades or drops the card without affecting the tool result. 18 new contract tests in `src/__tests__/mcp-apps.test.ts` pin the `_meta` advertisement, the `ui://` resource wire shape, the neutral-default/brand-injection behavior, and the card normalization.

### Security

- Close cross-tenant credential leak: convert HTTP transport from stateful (shared `StreamableHTTPServerTransport` with `sessionIdGenerator: randomUUID()`) to stateless (fresh Server + transport per request, `sessionIdGenerator: undefined`). Replace `process.env.ABNORMAL_API_TOKEN` mutation per request with `AsyncLocalStorage`-based request-scoped credentials via `runWithCredentials()`. Concurrent multi-tenant requests are now fully isolated.
