#!/usr/bin/env node
/**
 * Abnormal Security MCP Server
 *
 * MCP server for Abnormal Security — AI-powered threat detection, case
 * management, and email remediation.
 *
 * All tools are listed upfront so they work with every MCP client, including
 * remote connectors (claude.ai, mcp-remote) that do not support dynamic
 * tool-list changes. A helper `abnormal_navigate` tool provides domain
 * discovery and guidance.
 *
 * Transport:  Set MCP_TRANSPORT=http for HTTP Streamable transport (default: stdio).
 * Auth:       Set AUTH_MODE=gateway for header-based credential injection from
 *             the MCP gateway (gateway injects Authorization: Bearer {token}).
 *             Set AUTH_MODE=env (default) and ABNORMAL_API_TOKEN for standalone use.
 *             Gateway mode never falls back to ABNORMAL_API_TOKEN.
 *
 * HTTP transport refuses to start unless CONDUIT_S2S_SECRET is a real secret.
 * Known placeholders are rejected. MCP_ALLOW_INSECURE_DEV=1 is a local-only
 * escape hatch: it logs a warning, skips X-Gateway-S2S, and listens on
 * 127.0.0.1 only. With a configured secret, MCP_HTTP_HOST is honored.
 * The listen address defaults to 127.0.0.1 when unset.
 * /health stays unauthenticated and does not read credentials.
 * stdio does not use S2S auth.
 *
 * SECURITY: The HTTP transport is STATELESS (sessionIdGenerator: undefined).
 * Each request gets a fresh Server + StreamableHTTPServerTransport that is
 * destroyed on response close. Per-request tenant credentials are carried via
 * AsyncLocalStorage (runWithCredentials) — never via process.env mutation.
 */

import { createServer as createHttpServer, IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

import { threatTools, handleThreatTool } from "./domains/threats.js";
import { messageTools, handleMessageTool } from "./domains/messages.js";
import { remediationTools, handleRemediationTool } from "./domains/remediation.js";
import { abuseTools, handleAbuseTool } from "./domains/abuse.js";
import { caseTools, handleCaseTool } from "./domains/cases.js";
import { registerResourceHandlers } from "./resources.js";
import { runWithCredentials } from "./utils/client.js";
import { logger } from "./utils/logger.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";

const LOOPBACK_HOST = "127.0.0.1";

/**
 * Public example values. A copied placeholder must not verify as a real
 * secret: anyone who can reach /mcp could mint a matching X-Gateway-S2S.
 */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
]);

const MISSING_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
  "Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), " +
  "or set MCP_ALLOW_INSECURE_DEV=1 for local development only.";

const PLACEHOLDER_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
  "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.";

const INSECURE_DEV_WARNING =
  "SECURITY WARNING: CONDUIT_S2S_SECRET is unset and MCP_ALLOW_INSECURE_DEV=1. " +
  "HTTP /mcp is starting with service-to-service authentication DISABLED, bound to 127.0.0.1 only. " +
  "Local development only; do not expose this port.";

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  if (normalized === "localhost" || normalized === "::1") return true;
  const bare = normalized.startsWith("::ffff:") ? normalized.slice("::ffff:".length) : normalized;
  const parts = bare.split(".");
  if (parts.length !== 4) return false;
  if (parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  return parts[0] === "127";
}

function headerString(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.find((item) => item.length > 0);
  return undefined;
}

/** Raw Abnormal API token from Authorization, or undefined when the header is missing or blank. */
function bearerToken(authorization: string | undefined): string | undefined {
  if (!authorization) return undefined;
  const trimmed = authorization.trim();
  if (!trimmed || /^bearer$/i.test(trimmed)) return undefined;
  const token = /^bearer\s+/i.test(trimmed) ? trimmed.replace(/^bearer\s+/i, "").trim() : trimmed;
  return token.length > 0 ? token : undefined;
}

/**
 * Secret for X-Gateway-S2S on /mcp, read at HTTP startup rather than module load.
 * Empty is fail-closed unless MCP_ALLOW_INSECURE_DEV=1, which forces 127.0.0.1.
 * A known placeholder always refuses to start. The secret value is never logged.
 * A configured secret honors MCP_HTTP_HOST; an unset host defaults to 127.0.0.1.
 */
function resolveHttpStartup(): { secret: string; host: string } {
  const raw = (process.env.CONDUIT_S2S_SECRET ?? "").trim();
  if (KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase())) {
    logger.error(PLACEHOLDER_S2S_SECRET_ERROR);
    process.exit(1);
  }

  const configuredHost = (process.env.MCP_HTTP_HOST ?? "").trim();

  if (!raw) {
    if (process.env.MCP_ALLOW_INSECURE_DEV === "1") {
      if (configuredHost !== "" && !isLoopbackHost(configuredHost)) {
        logger.error(
          `WARNING: MCP_HTTP_HOST=${configuredHost} is not a loopback address. ` +
            "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. " +
            `Binding ${LOOPBACK_HOST} only.`,
        );
      }
      logger.error(INSECURE_DEV_WARNING);
      return { secret: "", host: LOOPBACK_HOST };
    }

    logger.error(MISSING_S2S_SECRET_ERROR);
    process.exit(1);
  }

  return { secret: raw, host: configuredHost === "" ? LOOPBACK_HOST : configuredHost };
}

// ── Types ────────────────────────────────────────────────────────────────────

type TransportType = "stdio" | "http";
type AuthMode = "env" | "gateway";
type Domain = "threats" | "messages" | "remediation" | "abuse" | "cases";

// ── Domain registry ──────────────────────────────────────────────────────────

const domainDescriptions: Record<Domain, string> = {
  threats: "Threat detection — list and inspect detected threat cases",
  messages: "Message analysis — list and inspect individual emails within a threat",
  remediation: "Remediation — trigger or check email remediation actions",
  abuse: "Abuse mailbox — list phishing emails reported by users",
  cases: "Security cases — list and inspect analyst investigation cases",
};

function getDomainTools(domain: Domain): Tool[] {
  switch (domain) {
    case "threats":
      return threatTools;
    case "messages":
      return messageTools;
    case "remediation":
      return remediationTools;
    case "abuse":
      return abuseTools;
    case "cases":
      return caseTools;
  }
}

async function dispatchDomainTool(
  domain: Domain,
  name: string,
  args: Record<string, unknown>
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  switch (domain) {
    case "threats":
      return handleThreatTool(name, args);
    case "messages":
      return handleMessageTool(name, args);
    case "remediation":
      return handleRemediationTool(name, args);
    case "abuse":
      return handleAbuseTool(name, args);
    case "cases":
      return handleCaseTool(name, args);
  }
}

// ── Navigation tools ─────────────────────────────────────────────────────────

/**
 * Navigation / discovery tool - helps the LLM find the right tools
 *
 * This is a stateless helper that describes available tools for a domain.
 * All domain tools are always listed in tools/list regardless of navigation
 * state, because many MCP clients (claude.ai connectors, mcp-remote) only
 * fetch the tool list once and do not support notifications/tools/list_changed.
 */
const navigateTool: Tool = {
  name: "abnormal_navigate",
  description:
    "Discover available Abnormal Security tools by domain. Returns tool names and descriptions for the selected domain. All tools are callable at any time — this is a help/discovery aid, not a prerequisite.",
  inputSchema: {
    type: "object",
    properties: {
      domain: {
        type: "string",
        enum: ["threats", "messages", "remediation", "abuse", "cases"],
        description: `The domain to explore:
- threats: ${domainDescriptions.threats}
- messages: ${domainDescriptions.messages}
- remediation: ${domainDescriptions.remediation}
- abuse: ${domainDescriptions.abuse}
- cases: ${domainDescriptions.cases}`,
      },
    },
    required: ["domain"],
  },
};

/**
 * Status tool - shows connection status and available domains
 */
const statusTool: Tool = {
  name: "abnormal_status",
  description: "Show connection status and available domains",
  inputSchema: {
    type: "object",
    properties: {},
  },
};

// ── Tool aggregation ─────────────────────────────────────────────────────────

/**
 * All domain tools, collected once at startup
 */
let allDomainTools: Tool[] | null = null;

/**
 * Load all domain tools (lazy-loaded on first access)
 */
function getAllDomainTools(): Tool[] {
  if (allDomainTools !== null) {
    return allDomainTools;
  }

  const domains: Domain[] = ["threats", "messages", "remediation", "abuse", "cases"];
  const tools: Tool[] = [];

  for (const domain of domains) {
    tools.push(...getDomainTools(domain));
  }

  allDomainTools = tools;
  return tools;
}

// ── MCP server factory ────────────────────────────────────────────────────────

/**
 * Create a fresh MCP Server instance and wire up all request handlers.
 * Called once per HTTP request (stateless mode) or once at startup (stdio).
 */
function createMcpServer(): Server {
  const server = new Server(
    { name: "abnormal-mcp", version: "1.0.0" },
    { capabilities: { tools: {}, resources: {} } }
  );

  // MCP Apps (SEP-1865): serve the ui:// threat-card resource.
  registerResourceHandlers(server);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const domainTools = getAllDomainTools();
    return { tools: [navigateTool, statusTool, ...domainTools] };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      // Handle navigation / discovery helper
      if (name === "abnormal_navigate") {
        const { domain } = args as { domain: Domain };

        const tools = getDomainTools(domain);
        const toolSummary = tools
          .map((t) => `- ${t.name}: ${t.description}`)
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: `${domainDescriptions[domain]}\n\nAvailable tools:\n${toolSummary}\n\nYou can call any of these tools directly.`,
            },
          ],
        };
      }

      if (name === "abnormal_status") {
        const authMode = process.env.AUTH_MODE === "gateway" ? "gateway" : "env";
        const hasToken = process.env.ABNORMAL_API_TOKEN ? "configured" : "NOT CONFIGURED";
        const credStatus = authMode === "gateway"
          ? "Gateway mode (Authorization header)"
          : `Environment mode (${hasToken})`;

        return {
          content: [
            {
              type: "text",
              text: `Abnormal Security MCP Server Status\n\nCredentials: ${credStatus}\nAvailable domains: threats, messages, remediation, abuse, cases\n\nAll tools are available at all times. Use abnormal_navigate to discover tools by domain.`,
            },
          ],
        };
      }

      // Domain tool dispatch
      const toolArgs = (args ?? {}) as Record<string, unknown>;

      if (name.startsWith("abnormal_threats_")) {
        return await dispatchDomainTool("threats", name, toolArgs);
      }
      if (name.startsWith("abnormal_messages_")) {
        return await dispatchDomainTool("messages", name, toolArgs);
      }
      if (name.startsWith("abnormal_remediation_")) {
        return await dispatchDomainTool("remediation", name, toolArgs);
      }
      if (name.startsWith("abnormal_abuse_")) {
        return await dispatchDomainTool("abuse", name, toolArgs);
      }
      if (name.startsWith("abnormal_cases_")) {
        return await dispatchDomainTool("cases", name, toolArgs);
      }

      return {
        content: [
          {
            type: "text",
            text: `Unknown tool: ${name}. Use abnormal_navigate to discover available tools by domain.`,
          },
        ],
        isError: true,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error("Tool call failed", { tool: name, error: message });
      return {
        content: [{ type: "text", text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ── Transports ────────────────────────────────────────────────────────────────

async function startStdioTransport(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Abnormal Security MCP server running on stdio");
}

export async function startHttpTransport(): Promise<HttpServer> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const { secret: s2sSecret, host } = resolveHttpStartup();
  const authMode = (process.env.AUTH_MODE as AuthMode) || "env";
  const isGatewayMode = authMode === "gateway";

  const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );

    // Health check — no auth required, and this handler must not read credentials.
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          transport: "http",
          authMode: isGatewayMode ? "gateway" : "env",
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    // MCP endpoint — STATELESS: fresh server+transport per request
    if (url.pathname === "/mcp") {
      // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1; startup
      // refuses otherwise. A configured secret is always enforced, before any
      // credential extraction.
      if (s2sSecret && !verifyS2sHeader(headerString(req.headers[S2S_HEADER]), s2sSecret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
          })
        );
        return;
      }

      if (isGatewayMode) {
        // Gateway injects Authorization: Bearer {token} on every request.
        // Reject when it is missing. Falling through would resolve
        // ABNORMAL_API_TOKEN from the process environment, which is not
        // request-scoped.
        const apiToken = bearerToken(headerString(req.headers["authorization"]));

        if (!apiToken) {
          logger.error("Gateway mode: missing Authorization header");
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing credentials",
              message: "Gateway mode requires Authorization header (Bearer token)",
              required: ["Authorization"],
            })
          );
          return;
        }

        // SECURITY-CRITICAL: wrap the entire request lifecycle in the
        // per-request ALS context. No process.env mutation — credentials are
        // scoped to this async call chain only.
        const handle = async () => {
          const server = createMcpServer();
          // sessionIdGenerator: undefined → stateless (no session map, no
          // long-lived transport). Each request gets its own server+transport
          // closed on response, keeping it inside the ALS credential context.
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableJsonResponse: true,
          });
          res.on('close', () => { transport.close(); server.close(); });
          await server.connect(transport);
          await transport.handleRequest(req, res);
        };

        await runWithCredentials({ apiToken }, handle);
        return;
      }

      // Non-gateway (env) mode: stateless transport, env creds used by getCredentials()
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => { transport.close(); server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] })
    );
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      logger.info(`Abnormal Security MCP server listening on http://${host}:${port}/mcp`);
      logger.info(`Health check: http://${host}:${port}/health`);
      logger.info(
        `Auth mode: ${isGatewayMode ? "gateway (Authorization header)" : "env (ABNORMAL_API_TOKEN)"}`
      );
      resolve();
    });
  });

  return httpServer;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const transportType =
    (process.env.MCP_TRANSPORT as TransportType) || "stdio";

  if (transportType === "http") {
    const httpServer = await startHttpTransport();
    const shutdown = async () => {
      logger.info("Shutting down Abnormal Security MCP server...");
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    await startStdioTransport();
  }
}

// Vitest imports this module to call startHttpTransport. Skip the CLI
// entrypoint there. `node dist/index.js` still starts stdio or HTTP.
if (process.env.VITEST !== "true") {
  process.on("unhandledRejection", (reason, promise) => {
    logger.error("Unhandled rejection", { promise: String(promise), reason: String(reason) });
    process.exit(1);
  });

  process.on("uncaughtException", (error) => {
    logger.error("Uncaught exception", { error: error.message });
    process.exit(1);
  });

  main().catch((err) => {
    logger.error("Startup failed", { error: (err as Error).message });
    process.exit(1);
  });
}
