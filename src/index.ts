#!/usr/bin/env node
/**
 * MyAIforOne MCP Server — Exposed via Streamable HTTP
 *
 * Dual-mode auth:
 *  1. Bearer passthrough — client sends Authorization: Bearer <mak_...>
 *  2. OAuth 2.0 Client Credentials — client_secret IS the mak_ key
 *
 * No credentials stored on the server.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { randomBytes } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { registerTools } from "./tools.js";
import { setAuthToken } from "./api-client.js";

const PORT = parseInt(process.env.PORT || "3100");
const SLUG = "myaiforone";
const SERVER_NAME = "MyAIforOne";
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;

// ─── OAuth token store (in-memory, ephemeral) ────────────────────────
const oauthTokens = new Map<string, { apiKey: string; expiresAt: number }>();
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function extractApiKey(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  // OAuth token (mcp_ prefix) → resolve to underlying API key
  if (token.startsWith("mcp_")) {
    const entry = oauthTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) {
      oauthTokens.delete(token);
      return null;
    }
    return entry.apiKey;
  }
  // Raw API key passthrough
  return token;
}

// ─── Express app ─────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// Serve logo
const publicDir = join(import.meta.dirname || ".", "public");
if (existsSync(publicDir)) app.use("/public", express.static(publicDir));

// ─── Root: server info ───────────────────────────────────────────────
app.get("/", (_req, res) => {
  res.json({
    name: SERVER_NAME,
    slug: SLUG,
    version: "1.0.0",
    description: "MyAIforOne Agent Gateway — manage agents, chat, skills, MCPs, and more via MCP tools",
    transport: "Streamable HTTP",
    mcpEndpoint: `${SERVER_BASE_URL}/mcp`,
    auth: {
      type: "dual-mode",
      modes: [
        { mode: "bearer", description: "Send Authorization: Bearer <your-mak-api-key>" },
        { mode: "oauth2-client-credentials", tokenEndpoint: `${SERVER_BASE_URL}/oauth/token`, description: "POST with client_id=myaiforone&client_secret=<your-mak-key>&grant_type=client_credentials" },
      ],
    },
    configTemplate: {
      "claude-code": { mcpServers: { [SLUG]: { url: `${SERVER_BASE_URL}/mcp`, headers: { Authorization: "Bearer YOUR_MAK_KEY" } } } },
      "claude-desktop": { mcpServers: { [SLUG]: { url: `${SERVER_BASE_URL}/mcp`, headers: { Authorization: "Bearer YOUR_MAK_KEY" } } } },
    },
  });
});

// ─── OAuth 2.0 Discovery ─────────────────────────────────────────────
app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: SERVER_BASE_URL,
    token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
    revocation_endpoint: `${SERVER_BASE_URL}/oauth/revoke`,
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    grant_types_supported: ["client_credentials"],
    response_types_supported: [],
  });
});

// ─── OAuth Token Exchange ────────────────────────────────────────────
app.post("/oauth/token", (req, res) => {
  const { client_id, client_secret, grant_type } = req.body;
  if (grant_type !== "client_credentials") {
    res.status(400).json({ error: "unsupported_grant_type" }); return;
  }
  if (client_id !== SLUG) {
    res.status(400).json({ error: "invalid_client", error_description: `client_id must be "${SLUG}"` }); return;
  }
  if (!client_secret) {
    res.status(400).json({ error: "invalid_client", error_description: "client_secret (your API key) is required" }); return;
  }
  const token = `mcp_${randomBytes(32).toString("hex")}`;
  oauthTokens.set(token, { apiKey: client_secret, expiresAt: Date.now() + TOKEN_TTL_MS });
  res.json({ access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL_MS / 1000 });
});

// ─── OAuth Revoke ────────────────────────────────────────────────────
app.post("/oauth/revoke", (req, res) => {
  const { token } = req.body;
  if (token) oauthTokens.delete(token);
  res.json({ ok: true });
});

// ─── MCP Endpoint ────────────────────────────────────────────────────
// Map of session ID → transport
const transports = new Map<string, StreamableHTTPServerTransport>();

app.all("/mcp", async (req, res) => {
  // Auth check
  const apiKey = extractApiKey(req);
  if (!apiKey) {
    res.status(401).json({
      error: "Unauthorized",
      auth_modes: [
        { mode: "bearer", example: "Authorization: Bearer mak_your_key" },
        { mode: "oauth2", tokenEndpoint: `${SERVER_BASE_URL}/oauth/token` },
      ],
    });
    return;
  }

  // Set the auth token for this request's api-client calls
  setAuthToken(apiKey);

  // Check for existing session
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId && transports.has(sessionId)) {
    // Existing session
    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  if (req.method === "GET" || (req.method === "DELETE" && sessionId)) {
    // SSE or session delete on unknown session
    if (sessionId) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
  }

  // New session — create server + transport
  const server = new McpServer({ name: SLUG, version: "1.0.0" });
  registerTools(server);

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomBytes(16).toString("hex") });

  transport.onclose = () => {
    const sid = [...transports.entries()].find(([, t]) => t === transport)?.[0];
    if (sid) transports.delete(sid);
  };

  await server.connect(transport);

  // Store transport by its generated session ID
  await transport.handleRequest(req, res, req.body);

  // After first request, the transport has a session ID
  const newSessionId = res.getHeader("mcp-session-id") as string | undefined;
  if (newSessionId) transports.set(newSessionId, transport);
});

// ─── Start ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ${SERVER_NAME} MCP Server (Streamable HTTP)`);
  console.log(`  ├─ URL:   ${SERVER_BASE_URL}/mcp`);
  console.log(`  ├─ Auth:  Dual-mode (Bearer passthrough + OAuth 2.0)`);
  console.log(`  ├─ Port:  ${PORT}`);
  console.log(`  └─ Slug:  ${SLUG}\n`);
});
