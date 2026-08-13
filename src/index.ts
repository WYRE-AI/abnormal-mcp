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
 *
 * SECURITY: The HTTP transport is STATELESS (sessionIdGenerator: undefined).
 * Each request gets a fresh Server + StreamableHTTPServerTransport that is
 * destroyed on response close. Per-request tenant credentials are carried via
 * AsyncLocalStorage (runWithCredentials) — never via process.env mutation.
 */

import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "node:http";
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

// Conduit service-to-service auth (gateway#377 parity). Non-empty =
// enforce X-Gateway-S2S on every /mcp request; empty = disabled, behavior
// exactly as before (dark-by-default until the gateway provisions this
// container's derived subkey). See src/s2s-verify.ts.
const S2S_SECRET = process.env.CONDUIT_S2S_SECRET || "";

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

async function startHttpTransport(): Promise<void> {
  const port = parseInt(process.env.MCP_HTTP_PORT || "8080", 10);
  const host = process.env.MCP_HTTP_HOST || "0.0.0.0";
  const authMode = (process.env.AUTH_MODE as AuthMode) || "env";
  const isGatewayMode = authMode === "gateway";

  const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );

    // Health check — no auth required
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
      if (S2S_SECRET && !verifyS2sHeader(req.headers[S2S_HEADER] as string | undefined, S2S_SECRET)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.",
          })
        );
        return;
      }

      if (isGatewayMode) {
        // Gateway injects Authorization: Bearer {token} directly
        const authorization = req.headers["authorization"] as string | undefined;

        if (!authorization) {
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

        // Strip "Bearer " prefix to get the raw token for the ALS credential store
        const apiToken = authorization.startsWith("Bearer ")
          ? authorization.slice(7)
          : authorization;

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

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      logger.info(`Abnormal Security MCP server listening on http://${host}:${port}/mcp`);
      logger.info(`Health check: http://${host}:${port}/health`);
      logger.info(
        `Auth mode: ${isGatewayMode ? "gateway (Authorization header)" : "env (ABNORMAL_API_TOKEN)"}`
      );
      resolve();
    });
  });

  const shutdown = async () => {
    logger.info("Shutting down Abnormal Security MCP server...");
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const transportType =
    (process.env.MCP_TRANSPORT as TransportType) || "stdio";

  if (transportType === "http") {
    await startHttpTransport();
  } else {
    await startStdioTransport();
  }
}

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
