/**
 * MyAIforOne MCP Tools
 * Registers all tools on a given McpServer instance.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as api from "./api-client.js";

export function registerTools(server: McpServer): void {

// ═══════════════════════════════════════════════════════════════════
//  DASHBOARD & HEALTH
// ═══════════════════════════════════════════════════════════════════

server.tool("health_check", "Check if the MyAgent gateway is running", {}, async () => {
  const r = await api.health();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_dashboard", "Get full dashboard: all agents, channels, accounts, uptime", {}, async () => {
  const r = await api.dashboard();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  AGENTS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_agents", "List all agents, optionally filtered by organization", {
  org: z.string().optional().describe("Filter by organization name"),
}, async ({ org }) => {
  const r = await api.listAgents(org);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_agent", "Get detailed info about a specific agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.getAgent(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_agent_instructions", "Get an agent's CLAUDE.md system prompt", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.getAgentInstructions(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_agent", "Create a new agent with full configuration", {
  agentId: z.string().describe("Unique agent ID (lowercase, hyphens)"),
  name: z.string().describe("Display name"),
  alias: z.string().optional().describe("Mention alias (e.g. @myagent)"),
  claudeMd: z.string().describe("System prompt / CLAUDE.md content for this agent"),
  description: z.string().optional().describe("Agent description"),
  workspace: z.string().optional().describe("Working directory path"),
  organization: z.string().optional().describe("Organization name"),
  function: z.string().optional().describe("Org function/department"),
  title: z.string().optional().describe("Org title/role"),
  persistent: z.boolean().optional().describe("Keep conversation history"),
  streaming: z.boolean().optional().describe("Enable streaming responses"),
  advancedMemory: z.boolean().optional().describe("Enable semantic memory"),
  autonomousCapable: z.boolean().optional().describe("Can run autonomous goals"),
  tools: z.array(z.string()).optional().describe("Allowed tools list"),
  skills: z.array(z.string()).optional().describe("Shared skill names"),
  mcps: z.array(z.string()).optional().describe("MCP server names"),
  prompts: z.array(z.string()).optional().describe("Prompt template names"),
  subAgents: z.union([z.array(z.string()), z.literal("*")]).optional().describe("Sub-agents for group agent"),
  claudeAccount: z.string().optional().describe("Claude account name"),
  timeout: z.number().optional().describe("Timeout in ms"),
  heartbeatInstructions: z.string().optional().describe("Custom heartbeat instructions — saved to heartbeat.md. Defines what the agent does during a heartbeat check."),
  agentClass: z.enum(["standard", "platform", "builder"]).optional().describe("Agent class: standard (default), platform (Lab creators), builder (app developer agents)"),
}, async (args) => {
  const body: any = { ...args };
  if (args.organization) {
    body.org = [{ organization: args.organization, function: args.function || "", title: args.title || "", reportsTo: "" }];
    delete body.organization; delete body.function; delete body.title;
  }
  const r = await api.createAgent(body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_agent", "Update an existing agent's configuration", {
  agentId: z.string().describe("Agent ID to update"),
  name: z.string().optional(),
  alias: z.string().optional(),
  description: z.string().optional(),
  workspace: z.string().optional(),
  persistent: z.boolean().optional(),
  streaming: z.boolean().optional(),
  advancedMemory: z.boolean().optional(),
  timeout: z.number().optional(),
  tools: z.array(z.string()).optional(),
  skills: z.array(z.string()).optional(),
  mcps: z.array(z.string()).optional(),
  prompts: z.array(z.string()).optional(),
  claudeAccount: z.string().optional(),
  instructions: z.string().optional().describe("Update CLAUDE.md content"),
  heartbeatInstructions: z.string().optional().describe("Custom heartbeat instructions — saved to heartbeat.md. Defines what the agent does during a heartbeat check."),
  agentClass: z.enum(["standard", "platform", "builder"]).optional().describe("Agent class: standard (default), platform (Lab creators), builder (app developer agents)"),
}, async ({ agentId, ...body }) => {
  const r = await api.updateAgent(agentId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_agent", "Delete an agent (auto-resolves confirmation alias)", {
  agentId: z.string().describe("Agent ID to delete"),
}, async ({ agentId }) => {
  // Server requires confirmAlias — fetch it from the agent's config first
  const agent = await api.getAgent(agentId);
  const alias = agent?.config?.aliases?.[0] || agent?.config?.mentionAliases?.[0] || agentId;
  const r = await api.deleteAgent(agentId, alias);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CHAT
// ═══════════════════════════════════════════════════════════════════

server.tool("send_message", "Send a message to an agent and get the response", {
  agentId: z.string().describe("Agent ID"),
  text: z.string().describe("Message text"),
  accountOverride: z.string().optional().describe("Use a different Claude account"),
}, async ({ agentId, text, accountOverride }) => {
  const r = await api.sendMessage(agentId, text, accountOverride);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delegate_message", "Send a message between agents (inter-agent delegation)", {
  agentId: z.string().describe("Target agent ID"),
  text: z.string().describe("Message text"),
}, async ({ agentId, text }) => {
  const r = await api.delegate(agentId, text);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  SESSIONS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_sessions", "List active conversation sessions for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.listSessions(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("reset_session", "Reset an agent's conversation session", {
  agentId: z.string().describe("Agent ID"),
  senderId: z.string().optional().describe("Specific sender to reset"),
}, async ({ agentId, senderId }) => {
  const r = await api.resetSession(agentId, senderId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MODEL OVERRIDES
// ═══════════════════════════════════════════════════════════════════

server.tool("get_model", "Get the current model override for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.getModel(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("set_model", "Set a model override for an agent (opus, sonnet, haiku, or full model ID)", {
  agentId: z.string().describe("Agent ID"),
  model: z.string().describe("Model: opus, sonnet, haiku, or full ID"),
}, async ({ agentId, model }) => {
  const r = await api.setModel(agentId, model);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("clear_model", "Clear model override, use agent default", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.clearModel(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  COST
// ═══════════════════════════════════════════════════════════════════

server.tool("get_agent_cost", "Get cost breakdown for an agent (today, week, all-time, by day)", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.getAgentCost(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_all_costs", "Get cost summary across ALL agents", {}, async () => {
  const r = await api.getAllCosts();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  SKILLS
// ═══════════════════════════════════════════════════════════════════

server.tool("get_agent_skills", "List all skills available to an agent (shared + org + agent-specific)", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.getAgentSkills(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_org_skills", "List all skills in an organization", {
  orgName: z.string().describe("Organization name"),
}, async ({ orgName }) => {
  const r = await api.getOrgSkills(orgName);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  TASKS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_tasks", "List tasks assigned to an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.listTasks(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_task", "Create a task for an agent", {
  agentId: z.string().describe("Agent ID"),
  title: z.string().describe("Task title"),
  description: z.string().optional(),
  priority: z.enum(["low", "medium", "high", "critical"]).optional(),
  project: z.string().optional(),
}, async ({ agentId, ...body }) => {
  const r = await api.createTask(agentId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_task", "Update a task status or details", {
  agentId: z.string().describe("Agent ID"),
  taskId: z.string().describe("Task ID"),
  status: z.string().optional(),
  title: z.string().optional(),
}, async ({ agentId, taskId, ...body }) => {
  const r = await api.updateTask(agentId, taskId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_task", "Delete a task", {
  agentId: z.string().describe("Agent ID"),
  taskId: z.string().describe("Task ID"),
}, async ({ agentId, taskId }) => {
  const r = await api.deleteTask(agentId, taskId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_all_tasks", "Get all tasks across all agents", {}, async () => {
  const r = await api.allTasks();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  AUTOMATIONS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_automations", "List all goals and crons across all agents", {}, async () => {
  const r = await api.listAutomations();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_goal", "Create an autonomous goal for an agent", {
  agentId: z.string().describe("Agent ID"),
  id: z.string().describe("Goal ID"),
  description: z.string().describe("What the goal does"),
  heartbeat: z.string().describe("Cron expression for schedule"),
  successCriteria: z.string().optional(),
  instructions: z.string().optional(),
}, async ({ agentId, ...body }) => {
  const r = await api.createGoal(agentId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("toggle_goal", "Enable or disable a goal", {
  agentId: z.string(), goalId: z.string(),
}, async ({ agentId, goalId }) => {
  const r = await api.toggleGoal(agentId, goalId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("trigger_goal", "Manually trigger a goal run", {
  agentId: z.string(), goalId: z.string(),
}, async ({ agentId, goalId }) => {
  const r = await api.triggerGoal(agentId, goalId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_cron", "Create a scheduled cron job for an agent", {
  agentId: z.string().describe("Agent ID"),
  schedule: z.string().describe("Cron expression"),
  message: z.string().describe("Message to send on trigger"),
  channel: z.string().describe("Channel name"),
  chatId: z.string().describe("Chat ID"),
  enabled: z.boolean().optional().describe("Start enabled (default true)"),
}, async ({ agentId, ...body }) => {
  const r = await api.createCron(agentId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MCPs
// ═══════════════════════════════════════════════════════════════════

server.tool("list_mcps", "List registered MCP servers", {}, async () => {
  const r = await api.listMcps();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_mcp_catalog", "Get the pre-hosted MCP catalog", {}, async () => {
  const r = await api.mcpCatalog();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CHANNELS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_channels", "List all messaging channels with config and agent routes", {}, async () => {
  const r = await api.listChannels();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_channel", "Update channel settings (sticky routing, enabled)", {
  channelName: z.string().describe("Channel name (slack, telegram, imessage, discord, whatsapp)"),
  enabled: z.boolean().optional(),
  stickyRouting: z.enum(["none", "sticky", "prefix"]).optional(),
  stickyPrefix: z.string().optional(),
  stickyTimeoutMs: z.number().optional(),
}, async ({ channelName, ...body }) => {
  const r = await api.updateChannel(channelName, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("add_agent_route", "Add an agent route to a channel", {
  channelName: z.string().describe("Channel name"),
  agentId: z.string().describe("Agent ID"),
  chatId: z.string().describe("Chat/channel ID"),
  requireMention: z.boolean().optional().describe("Require @mention (default true)"),
  allowFrom: z.array(z.string()).optional().describe("Allowed sender patterns"),
}, async ({ channelName, ...body }) => {
  const r = await api.addAgentRoute(channelName, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ACTIVITY & LOGS
// ═══════════════════════════════════════════════════════════════════

server.tool("get_activity", "Get recent activity feed across all agents", {
  limit: z.number().optional().describe("Max entries (default 100)"),
}, async ({ limit }) => {
  const r = await api.activity(limit);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_agent_logs", "Get paginated conversation logs for an agent", {
  agentId: z.string().describe("Agent ID"),
  limit: z.number().optional().describe("Max entries (default 50)"),
  offset: z.number().optional(),
  search: z.string().optional().describe("Keyword filter"),
}, async ({ agentId, limit, offset, search }) => {
  const r = await api.agentLogs(agentId, limit, offset, search);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MEMORY
// ═══════════════════════════════════════════════════════════════════

server.tool("get_agent_memory", "List memory entries for an agent", {
  agentId: z.string().describe("Agent ID"),
  limit: z.number().optional().describe("Max daily files"),
}, async ({ agentId, limit }) => {
  const r = await api.agentMemory(agentId, limit);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("search_memory", "Search an agent's memory by keyword", {
  agentId: z.string().describe("Agent ID"),
  query: z.string().describe("Search keyword"),
}, async ({ agentId, query }) => {
  const r = await api.searchMemory(agentId, query);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("clear_memory_context", "Clear an agent's context.md file", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.clearMemoryContext(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  PAIRING
// ═══════════════════════════════════════════════════════════════════

server.tool("list_paired_senders", "List paired/authorized senders", {}, async () => {
  const r = await api.listPairing();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("pair_sender", "Manually authorize a sender", {
  senderKey: z.string().describe("Format: channel:senderId"),
}, async ({ senderKey }) => {
  const r = await api.pairSender(senderKey);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CONFIG / ACCOUNTS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_accounts", "List Claude accounts (name → config directory)", {}, async () => {
  const r = await api.listAccounts();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_service_config", "Get service settings (personalAgentsDir, port, logLevel)", {}, async () => {
  const r = await api.getServiceConfig();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_service_config", "Update service settings (restart required)", {
  personalAgentsDir: z.string().optional(),
  webUIPort: z.number().optional(),
  logLevel: z.string().optional(),
  logFile: z.string().optional(),
  pairingCode: z.string().optional(),
  webhookSecret: z.string().optional(),
}, async (body) => {
  const r = await api.updateServiceConfig(body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  APPS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_apps", "List all registered apps", {}, async () => {
  const r = await api.listApps();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_app", "Register a new app", {
  name: z.string().describe("App name"),
  url: z.string().optional(),
  provider: z.string().optional(),
  category: z.string().optional(),
  githubRepo: z.string().optional(),
}, async (body) => {
  const r = await api.createApp(body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  FILES
// ═══════════════════════════════════════════════════════════════════

server.tool("list_agent_files", "List files in an agent's FileStorage", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.listFiles(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  REGISTRY
// ═══════════════════════════════════════════════════════════════════

server.tool("browse_registry", "Browse the marketplace/registry by type", {
  type: z.enum(["skills", "agents", "mcps", "prompts", "apps"]).describe("Registry type"),
}, async ({ type }) => {
  const r = await api.marketplace(type);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL AGENTS
// ═══════════════════════════════════════════════════════════════════

server.tool("recover_agent", "Recover agent from session corruption", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.recoverAgent(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL SESSIONS
// ═══════════════════════════════════════════════════════════════════

server.tool("delete_session", "Delete a specific sender's session", {
  agentId: z.string().describe("Agent ID"),
  senderId: z.string().describe("Sender ID (or 'default')"),
}, async ({ agentId, senderId }) => {
  const r = await api.deleteSession(agentId, senderId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL TASKS
// ═══════════════════════════════════════════════════════════════════

server.tool("get_task_stats", "Get task statistics (counts by status) for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.taskStats(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_project", "Create a project for organizing tasks", {
  agentId: z.string().describe("Agent ID"),
  name: z.string().describe("Project name"),
}, async ({ agentId, name }) => {
  const r = await api.createProject(agentId, name);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL AUTOMATIONS
// ═══════════════════════════════════════════════════════════════════

server.tool("delete_goal", "Delete a goal from an agent", {
  agentId: z.string(), goalId: z.string(),
}, async ({ agentId, goalId }) => {
  const r = await api.deleteGoal(agentId, goalId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_goal_history", "Get run history for a goal", {
  agentId: z.string(), goalId: z.string(),
}, async ({ agentId, goalId }) => {
  const r = await api.goalHistory(agentId, goalId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("toggle_cron", "Enable or disable a cron job", {
  agentId: z.string(), index: z.number().describe("Cron job index"),
}, async ({ agentId, index }) => {
  const r = await api.toggleCron(agentId, index);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("trigger_cron", "Manually trigger a cron job run", {
  agentId: z.string(), index: z.number().describe("Cron job index"),
}, async ({ agentId, index }) => {
  const r = await api.triggerCron(agentId, index);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_cron_history", "Get run history for a cron job", {
  agentId: z.string(), index: z.number().describe("Cron job index"),
}, async ({ agentId, index }) => {
  const r = await api.cronHistory(agentId, index);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_cron", "Delete a cron job", {
  agentId: z.string(), index: z.number().describe("Cron job index"),
}, async ({ agentId, index }) => {
  const r = await api.deleteCron(agentId, index);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MCP KEYS & CONNECTIONS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_mcp_keys", "List MCP API keys for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.listMcpKeys(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("save_mcp_key", "Save an MCP API key for an agent", {
  agentId: z.string(), mcpName: z.string(), envVar: z.string().describe("Environment variable name (e.g. GMAIL_ACCESS_TOKEN)"), value: z.string().describe("Secret value"),
}, async ({ agentId, mcpName, envVar, value }) => {
  const r = await api.saveMcpKey(agentId, mcpName, envVar, value);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_mcp_key", "Delete an MCP API key", {
  agentId: z.string(), mcpName: z.string(),
}, async ({ agentId, mcpName }) => {
  const r = await api.deleteMcpKey(agentId, mcpName);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("list_mcp_connections", "List MCP connections for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.listMcpConnections(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_mcp_connection", "Create an MCP connection instance for an agent", {
  agentId: z.string(), baseMcp: z.string().describe("Base MCP server name from registry"), label: z.string().describe("Human-readable label"), envVar: z.string().describe("Environment variable name"), value: z.string().describe("Secret value"), description: z.string().optional(),
}, async ({ agentId, ...body }) => {
  const r = await api.createMcpConnection(agentId, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_mcp_connection", "Delete an MCP connection", {
  agentId: z.string(), instanceName: z.string(),
}, async ({ agentId, instanceName }) => {
  const r = await api.deleteMcpConnection(agentId, instanceName);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL CHANNELS
// ═══════════════════════════════════════════════════════════════════

server.tool("remove_agent_route", "Remove an agent's route from a channel", {
  channelName: z.string(), agentId: z.string(),
}, async ({ channelName, agentId }) => {
  const r = await api.removeAgentRoute(channelName, agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("add_monitored_chat", "Add a monitored chat ID to a channel", {
  channelName: z.string(), chatId: z.string(),
}, async ({ channelName, chatId }) => {
  const r = await api.addMonitoredChat(channelName, chatId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("remove_monitored_chat", "Remove a monitored chat from a channel", {
  channelName: z.string(), chatId: z.string(),
}, async ({ channelName, chatId }) => {
  const r = await api.removeMonitoredChat(channelName, chatId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_sticky_routing", "Get sticky routing config for all channels", {}, async () => {
  const r = await api.stickyRouting();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL REGISTRY
// ═══════════════════════════════════════════════════════════════════

server.tool("install_registry_item", "Install a skill/MCP/agent from the registry", {
  id: z.string().describe("Registry item ID"),
  type: z.string().describe("Item type: skill, mcp, agent, prompt"),
}, async ({ id, type }) => {
  const r = await api.installMarketplace(id, type);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("assign_to_agent", "Assign a skill or MCP to an agent", {
  agentId: z.string(), itemId: z.string(), type: z.string().describe("skill or mcp"),
}, async ({ agentId, itemId, type }) => {
  const r = await api.assignToAgent(agentId, itemId, type);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("scan_skills", "Scan a directory for unregistered skills", {
  dir: z.string().optional().describe("Directory to scan (default: ~/.claude/commands)"),
}, async ({ dir }) => {
  const r = await api.scanSkills(dir);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_prompt", "Create a new prompt template in the registry", {
  id: z.string(), name: z.string(), content: z.string(),
}, async ({ id, name, content }) => {
  const r = await api.createPrompt(id, name, content);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("create_skill", "Create a skill file and register it. Writes the .md file to the correct location based on scope and adds a registry entry.", {
  id: z.string().describe("Skill ID (snake_case, matches filename)"),
  name: z.string().describe("Human-readable skill name"),
  description: z.string().describe("One-line description of what the skill does and when to use it"),
  content: z.string().describe("The skill body (markdown instructions, everything below the frontmatter)"),
  scope: z.enum(["global", "personal", "org", "agent"]).describe("Where to place the skill: global (~/.claude/commands), personal (personalAgents/skills), org (personalAgents/{orgName}/skills), agent ({agentHome}/skills)"),
  orgName: z.string().optional().describe("Required when scope is 'org' — the organization name"),
  agentId: z.string().optional().describe("Required when scope is 'agent' — the agent ID"),
}, async ({ id, name, description, content, scope, orgName, agentId }) => {
  const r = await api.createSkill(id, name, description, content, scope, orgName, agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("add_mcp_to_registry", "Add an MCP server to the registry", {
  id: z.string(), name: z.string(), mcpType: z.string().describe("'stdio' or 'http'"), url: z.string().optional(), command: z.string().optional(), args: z.array(z.string()).optional(), description: z.string().optional(),
}, async (body) => {
  const r = await api.addMcpToRegistry(body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL APPS
// ═══════════════════════════════════════════════════════════════════

server.tool("update_app", "Update an existing app", {
  id: z.string().describe("App ID"),
  name: z.string().optional(), url: z.string().optional(),
  category: z.string().optional(), status: z.string().optional(),
}, async ({ id, ...body }) => {
  const r = await api.updateApp(id, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_app", "Delete an app", {
  id: z.string().describe("App ID"),
}, async ({ id }) => {
  const r = await api.deleteApp(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("check_app_health", "Check an app's health/status", {
  id: z.string().describe("App ID"),
}, async ({ id }) => {
  const r = await api.checkAppHealth(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL CONFIG
// ═══════════════════════════════════════════════════════════════════

server.tool("add_account", "Add a Claude account (name + config directory path)", {
  name: z.string().describe("Account name"),
  path: z.string().describe("Config directory path (e.g. ~/.claude)"),
}, async ({ name, path }) => {
  const r = await api.addAccount(name, path);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_account", "Remove a Claude account", {
  name: z.string().describe("Account name"),
}, async ({ name }) => {
  const r = await api.deleteAccount(name);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("check_account_status", "Check if a Claude account is authenticated", {
  name: z.string().describe("Account name"),
}, async ({ name }) => {
  const r = await api.accountStatus(name);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("start_account_login", "Start OAuth login flow for a Claude account — returns URL to open", {
  name: z.string().describe("Account name"),
  path: z.string().describe("Config directory path"),
}, async ({ name, path }) => {
  const r = await api.startLogin(name, path);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL PAIRING
// ═══════════════════════════════════════════════════════════════════

server.tool("unpair_sender", "Remove an authorized sender", {
  senderKey: z.string().describe("Format: channel:senderId"),
}, async ({ senderKey }) => {
  const r = await api.unpairSender(senderKey);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  LAB / PLATFORM AGENTS
// ═══════════════════════════════════════════════════════════════════

server.tool("get_platform_agents", "List platform-managed creator agents (used by Lab for creating agents, skills, apps, and prompts)", {}, async () => {
  const r = await api.getPlatformAgents();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL CONFIG — LOGIN
// ═══════════════════════════════════════════════════════════════════

server.tool("submit_login_code", "Submit authentication code for account login", {
  accountName: z.string().describe("Account name"),
  code: z.string().describe("Authentication code from OAuth flow"),
}, async ({ accountName, code }) => {
  const r = await api.submitLoginCode(accountName, code);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MARKETPLACE EXTRAS
// ═══════════════════════════════════════════════════════════════════

server.tool("set_platform_default", "Set a marketplace item as the platform default", {
  type: z.string().describe("Item type (e.g. skill, mcp, prompt)"),
  id: z.string().describe("Item ID to set as default"),
}, async ({ type, id }) => {
  const r = await api.setPlatformDefault(type, id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("import_skills", "Import scanned skills into an agent", {
  agentId: z.string().describe("Agent ID"),
  skills: z.array(z.string()).describe("Array of skill names to import"),
}, async ({ agentId, skills }) => {
  const r = await api.importSkills(agentId, skills);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_prompt_trigger", "Get the current prompt trigger character", {}, async () => {
  const r = await api.getPromptTrigger();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("set_prompt_trigger", "Set the prompt trigger character", {
  trigger: z.string().describe("Trigger character (e.g. / or !)"),
}, async ({ trigger }) => {
  const r = await api.setPromptTrigger(trigger);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CHAT STREAMING
// ═══════════════════════════════════════════════════════════════════

server.tool("get_chat_job_raw", "Get raw output lines from a streaming chat job", {
  jobId: z.string().describe("Job ID from startStream"),
  after: z.number().optional().describe("Line index to start from (for polling)"),
}, async ({ jobId, after }) => {
  const r = await api.getChatJobRaw(jobId, after);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL FILES
// ═══════════════════════════════════════════════════════════════════

server.tool("download_agent_file", "Download a file from an agent's file storage", {
  agentId: z.string().describe("Agent ID"),
  path: z.string().describe("File path within agent storage"),
}, async ({ agentId, path }) => {
  const r = await api.downloadFile(agentId, path);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADDITIONAL DASHBOARD
// ═══════════════════════════════════════════════════════════════════

server.tool("get_agent_registry", "Get the agent registry with delegation keywords", {}, async () => {
  const r = await api.agentRegistry();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════

server.tool("auth_me", "Get current authenticated user info", {}, async () => {
  const r = await api.authMe();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  SETTINGS (API KEY)
// ═══════════════════════════════════════════════════════════════════

server.tool("get_api_key", "Get Anthropic API key status (masked)", {}, async () => {
  const r = await api.getApiKey();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("set_api_key", "Set the organization's Anthropic API key", {
  apiKey: z.string().describe("Anthropic API key (sk-ant-...)"),
}, async ({ apiKey }) => {
  const r = await api.setApiKey(apiKey);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_api_key", "Remove the organization's API key", {}, async () => {
  const r = await api.deleteApiKey();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  ADMIN
// ═══════════════════════════════════════════════════════════════════

server.tool("admin_list_users", "List all users in the organization", {}, async () => {
  const r = await api.adminUsers();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_update_user", "Update a user's role", {
  userId: z.string().describe("User ID"),
  role: z.string().describe("ADMIN or USER"),
}, async ({ userId, role }) => {
  const r = await api.adminUpdateUser(userId, role);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_list_license_keys", "List license keys", {}, async () => {
  const r = await api.adminLicenseKeys();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_create_license_key", "Create a new license key", {
  maxUses: z.number().optional().describe("Maximum registrations (default 10)"),
}, async ({ maxUses }) => {
  const r = await api.adminCreateLicenseKey(maxUses);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_delete_license_key", "Delete a license key", {
  id: z.string().describe("License key ID"),
}, async ({ id }) => {
  const r = await api.adminDeleteLicenseKey(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_list_api_keys", "List programmatic API keys", {}, async () => {
  const r = await api.adminApiKeys();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_create_api_key", "Create a new API key for programmatic access", {
  name: z.string().describe("Key name/label"),
}, async ({ name }) => {
  const r = await api.adminCreateApiKey(name);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_delete_api_key", "Delete an API key", {
  id: z.string().describe("API key ID"),
}, async ({ id }) => {
  const r = await api.adminDeleteApiKey(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("admin_usage", "Get usage stats (message counts, cost totals)", {}, async () => {
  const r = await api.adminUsage();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  UPLOADS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_uploads", "List uploaded files (optionally filtered by agent)", {
  agentId: z.string().optional().describe("Filter by agent ID"),
}, async ({ agentId }) => {
  const r = await api.listUploads(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_upload", "Delete an uploaded file", {
  id: z.string().describe("Upload ID"),
}, async ({ id }) => {
  const r = await api.deleteUpload(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CONNECTED ACCOUNTS
// ═══════════════════════════════════════════════════════════════════

server.tool("list_connected_accounts", "List OAuth connected accounts", {}, async () => {
  const r = await api.listConnectedAccounts();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_connected_account", "Remove a connected account", {
  id: z.string().describe("Account ID"),
}, async ({ id }) => {
  const r = await api.deleteConnectedAccount(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  EXPORT / IMPORT
// ═══════════════════════════════════════════════════════════════════

server.tool("export_item", "Export an agent, skill, prompt, or MCP as JSON", {
  type: z.string().describe("agent | skill | prompt | mcp"),
  id: z.string().describe("Item ID"),
}, async ({ type, id }) => {
  const r = await api.exportItem(type, id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("import_item", "Import an agent, skill, prompt, or MCP from JSON", {
  type: z.string().describe("agent | skill | prompt | mcp"),
  data: z.string().describe("JSON data to import"),
}, async ({ type, data }) => {
  const r = await api.importItem(type, JSON.parse(data));
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  SKILLS CRUD (TOP-LEVEL)
// ═══════════════════════════════════════════════════════════════════

server.tool("list_skills", "List all skills in the organization", {}, async () => {
  const r = await api.listSkills();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_skill", "Update a skill", {
  id: z.string().describe("Skill ID"),
  name: z.string().optional().describe("New name"),
  content: z.string().optional().describe("New content"),
  description: z.string().optional().describe("New description"),
}, async ({ id, ...body }) => {
  const r = await api.updateSkill(id, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_skill", "Delete a skill", {
  id: z.string().describe("Skill ID"),
}, async ({ id }) => {
  const r = await api.deleteSkill(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MCPs CRUD (TOP-LEVEL)
// ═══════════════════════════════════════════════════════════════════

server.tool("create_mcp", "Create a new MCP server config", {
  name: z.string().describe("MCP name"),
  type: z.string().describe("http | stdio"),
  url: z.string().optional().describe("URL for HTTP MCP"),
  command: z.string().optional().describe("Command for stdio MCP"),
}, async ({ name, type, url, command }) => {
  const r = await api.createMcp({ name, type, url, command });
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("update_mcp", "Update an MCP config", {
  id: z.string().describe("MCP ID"),
  name: z.string().optional(),
  url: z.string().optional(),
}, async ({ id, ...body }) => {
  const r = await api.updateMcp(id, body);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("delete_mcp", "Delete an MCP config", {
  id: z.string().describe("MCP ID"),
}, async ({ id }) => {
  const r = await api.deleteMcp(id);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  CHAT EXTRAS
// ═══════════════════════════════════════════════════════════════════

server.tool("start_stream", "Start a streaming chat job (returns jobId)", {
  agentId: z.string().describe("Agent ID"),
  text: z.string().describe("Message text"),
}, async ({ agentId, text }) => {
  const r = await api.startStream(agentId, text);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("stop_chat_job", "Stop a running chat job", {
  jobId: z.string().describe("Job ID"),
}, async ({ jobId }) => {
  const r = await api.stopJob(jobId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("reset_chat", "Reset an agent's chat session", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.resetChat(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("send_webhook", "Send a message via webhook", {
  agentId: z.string().describe("Agent ID"),
  text: z.string().describe("Message text"),
  channel: z.string().optional().describe("Override channel"),
}, async ({ agentId, text, channel }) => {
  const r = await api.sendWebhook(agentId, text, channel);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

// ═══════════════════════════════════════════════════════════════════
//  MISC
// ═══════════════════════════════════════════════════════════════════

server.tool("whoami", "Get agent identity info (name, alias, workspace)", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.whoami(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_changelog", "Get changelog from git history (grouped by date)", {}, async () => {
  const r = await api.changelog();
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("get_heartbeat_history", "Get heartbeat history for an agent", {
  agentId: z.string().describe("Agent ID"),
}, async ({ agentId }) => {
  const r = await api.heartbeatHistory(agentId);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

server.tool("browse_dirs", "List subdirectories of a path (for Lab directory picker)", {
  path: z.string().optional().describe("Directory path (defaults to home)"),
}, async ({ path }) => {
  const r = await api.browseDirs(path);
  return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
});

} // end registerTools
