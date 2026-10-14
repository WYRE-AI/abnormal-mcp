/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholders are refused even with that flag. The flag binds 127.0.0.1
 * only. A configured secret honors MCP_HTTP_HOST. Gateway-mode /mcp requests
 * without Authorization are 401 and must not use ABNORMAL_API_TOKEN.
 */

import { createHmac } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const runWithCredentialsSpy = vi.hoisted(() => vi.fn());

vi.mock("../utils/client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/client.js")>();
  return {
    ...actual,
    runWithCredentials: <T>(creds: { apiToken: string }, fn: () => T): T => {
      runWithCredentialsSpy(creds);
      return actual.runWithCredentials(creds, fn);
    },
  };
});

import { startHttpTransport } from "../index.js";

const S2S_SECRET = "s2s-do-not-log-7f3a";
const ENV_TOKEN = "env-token-must-not-be-used";
const HEADER_TOKEN = "header-token-from-authorization";

const ENV_KEYS = [
  "CONDUIT_S2S_SECRET",
  "MCP_ALLOW_INSECURE_DEV",
  "MCP_HTTP_PORT",
  "MCP_HTTP_HOST",
  "AUTH_MODE",
  "ABNORMAL_API_TOKEN",
  "LOG_LEVEL",
  "MCP_TRANSPORT",
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${hex}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg))).join(" "));
  });
  return {
    text: () => lines.join("\n"),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy() {
  return vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function listen(): Promise<{ port: number; address: string; close: () => Promise<void> }> {
  const server = await startHttpTransport();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === "string") {
    throw new Error("HTTP server did not bind a TCP port");
  }
  return {
    port: bound.port,
    address: bound.address,
    close: () => new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    }),
  };
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...extra,
  };
}

const statusCall = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "abnormal_status", arguments: {} },
});

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server?.listening) continue;
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = "0";
  process.env.MCP_HTTP_HOST = "127.0.0.1";
  process.env.LOG_LEVEL = "info";
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.AUTH_MODE;
  delete process.env.ABNORMAL_API_TOKEN;
  delete process.env.MCP_TRANSPORT;
  runWithCredentialsSpy.mockReset();
});

describe("HTTP startup", () => {
  it("refuses to start when CONDUIT_S2S_SECRET is empty", async () => {
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("Refusing to start HTTP transport");
      expect(text).toContain("CONDUIT_S2S_SECRET is empty");
      expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("still refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "true";
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(logs.text()).toContain("Refusing to start HTTP transport");
      expect(logs.text()).toContain("CONDUIT_S2S_SECRET is empty");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("treats a whitespace-only secret as empty", async () => {
    process.env.CONDUIT_S2S_SECRET = "   ";
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(logs.text()).toContain("CONDUIT_S2S_SECRET is empty");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each([
    "changeme",
    "change-me",
    "example",
    "replace-me",
    "s2s-secret",
    "replace-with-a-real-secret",
    "your-s2s-secret",
    "your-secret",
  ])("refuses known placeholder %s and does not log it", async (placeholder) => {
    process.env.CONDUIT_S2S_SECRET = placeholder;
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      expect(exit).toHaveBeenCalledWith(1);
      const text = logs.text();
      expect(text).toContain("known placeholder");
      expect(text).toContain("openssl rand -hex 32");
      expect(text).not.toContain(placeholder);
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it.each(["placeholder", "secret"])(
    "refuses known placeholder %s without echoing the configured value",
    async (placeholder) => {
      process.env.CONDUIT_S2S_SECRET = placeholder;
      const logs = captureStderr();
      const exit = exitSpy();

      try {
        await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
        const text = logs.text();
        expect(text).toContain("known placeholder");
        expect(text).not.toContain(`CONDUIT_S2S_SECRET=${placeholder}`);
        expect(text).not.toContain(`'${placeholder}'`);
        expect(text).not.toContain(`"${placeholder}"`);
      } finally {
        exit.mockRestore();
        logs.restore();
      }
    },
  );

  it("refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1", async () => {
    process.env.CONDUIT_S2S_SECRET = "  Your-S2S-Secret  ";
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    const logs = captureStderr();
    const exit = exitSpy();

    try {
      await expect(startHttpTransport()).rejects.toThrow("process.exit:1");
      const text = logs.text();
      expect(text).toContain("known placeholder");
      expect(text).not.toContain("Your-S2S-Secret");
      expect(text).not.toContain("SECURITY WARNING");
    } finally {
      exit.mockRestore();
      logs.restore();
    }
  });

  it("allows startup with a warning when MCP_ALLOW_INSECURE_DEV=1", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    delete process.env.MCP_HTTP_HOST;
    process.env.LOG_LEVEL = "error";
    const logs = captureStderr();
    let close: (() => Promise<void>) | undefined;
    try {
      const server = await listen();
      close = server.close;
      expect(server.address).toBe("127.0.0.1");
      const text = logs.text();
      expect(text).toContain("SECURITY WARNING");
      expect(text).toContain("CONDUIT_S2S_SECRET");
      expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
      expect(text).toContain("127.0.0.1");
      expect(text).toContain("DISABLED");
      expect(text).not.toContain(S2S_SECRET);
      expect(text).not.toContain("not a loopback address");
    } finally {
      logs.restore();
      await close?.();
    }
  });

  it("forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is not loopback", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    const exit = exitSpy();
    let close: (() => Promise<void>) | undefined;

    try {
      const server = await listen();
      close = server.close;
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe("127.0.0.1");
      const text = logs.text();
      expect(text).toContain("MCP_HTTP_HOST=0.0.0.0 is not a loopback address");
      expect(text).toContain("Binding 127.0.0.1 only");
      expect(text).toContain("SECURITY WARNING");
      expect(text).not.toContain(S2S_SECRET);
    } finally {
      exit.mockRestore();
      logs.restore();
      await close?.();
    }
  });

  it("forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is localhost", async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = "1";
    process.env.MCP_HTTP_HOST = "localhost";
    const logs = captureStderr();
    let close: (() => Promise<void>) | undefined;
    try {
      const server = await listen();
      close = server.close;
      expect(server.address).toBe("127.0.0.1");
      expect(logs.text()).toContain("SECURITY WARNING");
      expect(logs.text()).not.toContain("not a loopback address");
    } finally {
      logs.restore();
      await close?.();
    }
  });

  it("still binds a non-loopback host when CONDUIT_S2S_SECRET is set", async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = "0.0.0.0";
    const logs = captureStderr();
    const server = await listen();
    try {
      expect(server.address).toBe("0.0.0.0");
      expect(logs.text()).not.toContain("not a loopback address");
      expect(logs.text()).not.toContain(S2S_SECRET);
    } finally {
      logs.restore();
      await server.close();
    }
  });

  it("binds 127.0.0.1 when MCP_HTTP_HOST is unset and a secret is set", async () => {
    delete process.env.MCP_HTTP_HOST;
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    const server = await listen();
    try {
      expect(server.address).toBe("127.0.0.1");
    } finally {
      await server.close();
    }
  });
});

describe("HTTP /mcp authentication", () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.AUTH_MODE = "gateway";
    process.env.ABNORMAL_API_TOKEN = ENV_TOKEN;
    process.env.MCP_HTTP_HOST = "127.0.0.1";
  });

  it("returns 401 when the S2S header is missing or invalid and does not log the secret", async () => {
    const logs = captureStderr();
    const server = await listen();
    try {
      const missing = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({ authorization: `Bearer ${HEADER_TOKEN}` }),
        body: statusCall,
      });
      const invalid = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          authorization: `Bearer ${HEADER_TOKEN}`,
          "x-gateway-s2s": mintS2sHeader("wrong-secret"),
        }),
        body: statusCall,
      });

      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain("X-Gateway-S2S");
      expect(invalid.body).toContain("X-Gateway-S2S");
      expect(missing.body).not.toContain(S2S_SECRET);
      expect(invalid.body).not.toContain(S2S_SECRET);
      expect(missing.body).not.toContain(ENV_TOKEN);
      expect(invalid.body).not.toContain(HEADER_TOKEN);
      expect(logs.text()).not.toContain(S2S_SECRET);
      expect(logs.text()).not.toContain(ENV_TOKEN);
      expect(logs.text()).not.toContain(HEADER_TOKEN);
      expect(runWithCredentialsSpy).not.toHaveBeenCalled();
    } finally {
      logs.restore();
      await server.close();
    }
  });

  it("returns 401 in gateway mode without credential headers and does not use env credentials", async () => {
    const server = await listen();
    try {
      const missing = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({ "x-gateway-s2s": mintS2sHeader(S2S_SECRET) }),
        body: statusCall,
      });
      const blank = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
          authorization: "Bearer",
        }),
        body: statusCall,
      });

      expect(missing.status).toBe(401);
      expect(blank.status).toBe(401);
      expect(missing.body).toContain("Missing credentials");
      expect(missing.body).toContain("Authorization");
      expect(missing.body).not.toContain(ENV_TOKEN);
      expect(missing.body).not.toContain(S2S_SECRET);
      expect(blank.body).not.toContain(ENV_TOKEN);
      expect(runWithCredentialsSpy).not.toHaveBeenCalled();
    } finally {
      await server.close();
    }
  });

  it("accepts a valid S2S header plus Authorization and uses that token", async () => {
    const logs = captureStderr();
    const server = await listen();
    try {
      const response = await sendHttp({
        port: server.port,
        method: "POST",
        path: "/mcp",
        headers: mcpHeaders({
          "x-gateway-s2s": mintS2sHeader(S2S_SECRET),
          authorization: `Bearer ${HEADER_TOKEN}`,
        }),
        body: statusCall,
      });

      expect(response.status).toBe(200);
      expect(response.body).not.toContain(S2S_SECRET);
      expect(response.body).not.toContain(ENV_TOKEN);
      expect(response.body).not.toContain(HEADER_TOKEN);
      const payload = JSON.parse(response.body) as {
        result?: { content?: Array<{ text?: string }> };
      };
      const text = payload.result?.content?.[0]?.text ?? "";
      expect(text).toContain("Gateway mode");
      expect(text).not.toContain(ENV_TOKEN);
      expect(runWithCredentialsSpy).toHaveBeenCalledWith({ apiToken: HEADER_TOKEN });
      expect(logs.text()).not.toContain(S2S_SECRET);
      expect(logs.text()).not.toContain(ENV_TOKEN);
      expect(logs.text()).not.toContain(HEADER_TOKEN);
    } finally {
      logs.restore();
      await server.close();
    }
  });

  it("serves /health without authentication and without reading credentials", async () => {
    const server = await listen();
    try {
      const response = await sendHttp({
        port: server.port,
        method: "GET",
        path: "/health",
      });
      expect(response.status).toBe(200);
      const body = JSON.parse(response.body) as { status?: string; authMode?: string };
      expect(body.status).toBe("ok");
      expect(body.authMode).toBe("gateway");
      expect(response.body).not.toContain(S2S_SECRET);
      expect(response.body).not.toContain(ENV_TOKEN);
      expect(runWithCredentialsSpy).not.toHaveBeenCalled();
    } finally {
      await server.close();
    }
  });
});
