/**
 * MyAIforOne API Client
 * Wraps all REST API endpoints for use by MCP tools.
 * In HTTP mode, the Bearer token is forwarded from the MCP client.
 */

const BASE_URL = process.env.MYAGENT_API_URL || "http://localhost:4888";

// Thread-local auth token: set per-request by the HTTP transport
let _currentAuthToken: string | undefined;
export function setAuthToken(key: string | undefined) { _currentAuthToken = key; }
export function getAuthToken(): string | undefined { return _currentAuthToken; }

interface RequestOptions {
  method?: string;
  body?: any;
  query?: Record<string, string | number | undefined>;
}

async function api(path: string, opts: RequestOptions = {}): Promise<any> {
  let url = `${BASE_URL}${path}`;
  if (opts.query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== "") params.set(k, String(v));
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: Record<string, string> = {};
  if (opts.body) headers["Content-Type"] = "application/json";
  // Forward the client's API key to the SaaS backend
  if (_currentAuthToken) headers["Authorization"] = `Bearer ${_currentAuthToken}`;

  const res = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });

  const text = await res.text();
  try { return JSON.parse(text); } catch { return text; }
}

// ─── Dashboard & Health ───────────────────────────────────────────
export const health = () => api("/health");
export const dashboard = () => api("/api/dashboard");
export const agentRegistry = () => api("/api/agent-registry");

// ─── Agents ───────────────────────────────────────────────────────
export const listAgents = (org?: string) => api("/api/agents", { query: { org } });
export const getAgent = (id: string) => api(`/api/agents/${id}`);
export const getAgentInstructions = (id: string) => api(`/api/agents/${id}/instructions`);
export const createAgent = (body: any) => api("/api/agents", { method: "POST", body });
export const updateAgent = (id: string, body: any) => api(`/api/agents/${id}`, { method: "PUT", body });
export const deleteAgent = (id: string, confirmAlias: string) =>
  api(`/api/agents/${id}`, { method: "DELETE", body: { confirmAlias } });
export const recoverAgent = (id: string, userText?: string, response?: string) =>
  api(`/api/agents/${id}/recover`, { method: "POST", body: { userText: userText || "Session recovery triggered via MCP tool", response } });

// ─── Chat ─────────────────────────────────────────────────────────
export const sendMessage = (agentId: string, text: string, accountOverride?: string) =>
  api(`/api/chat/${agentId}`, { method: "POST", body: { text, accountOverride } });
export const startStream = (agentId: string, text: string, accountOverride?: string) =>
  api(`/api/chat/${agentId}/stream`, { method: "POST", body: { text, accountOverride } });
export const stopJob = (jobId: string) => api(`/api/chat/jobs/${jobId}/stop`, { method: "POST" });
export const delegate = (agentId: string, text: string) =>
  api("/api/delegate", { method: "POST", body: { agentId, text } });

// ─── Sessions ─────────────────────────────────────────────────────
export const listSessions = (agentId: string) => api(`/api/agents/${agentId}/sessions`);
export const resetSession = (agentId: string, senderId?: string) =>
  api(`/api/agents/${agentId}/sessions/reset`, { method: "POST", body: { senderId } });
export const deleteSession = (agentId: string, senderId: string) =>
  api(`/api/agents/${agentId}/sessions/${senderId}`, { method: "DELETE" });

// ─── Model ────────────────────────────────────────────────────────
export const getModel = (agentId: string) => api(`/api/agents/${agentId}/model`);
export const setModel = (agentId: string, model: string) =>
  api(`/api/agents/${agentId}/model`, { method: "PUT", body: { model } });
export const clearModel = (agentId: string) =>
  api(`/api/agents/${agentId}/model`, { method: "DELETE" });

// ─── Cost ─────────────────────────────────────────────────────────
export const getAgentCost = (agentId: string) => api(`/api/agents/${agentId}/cost`);
export const getAllCosts = () => api("/api/cost/all");

// ─── Skills ───────────────────────────────────────────────────────
export const getAgentSkills = (agentId: string) => api(`/api/agents/${agentId}/skills`);
export const getOrgSkills = (orgName: string) => api(`/api/skills/org/${orgName}`);

// ─── Tasks ────────────────────────────────────────────────────────
export const listTasks = (agentId: string) => api(`/api/agents/${agentId}/tasks`);
export const taskStats = (agentId: string) => api(`/api/agents/${agentId}/tasks/stats`);
export const createTask = (agentId: string, body: any) =>
  api(`/api/agents/${agentId}/tasks`, { method: "POST", body });
export const updateTask = (agentId: string, taskId: string, body: any) =>
  api(`/api/agents/${agentId}/tasks/${taskId}`, { method: "PUT", body });
export const deleteTask = (agentId: string, taskId: string) =>
  api(`/api/agents/${agentId}/tasks/${taskId}`, { method: "DELETE" });
export const allTasks = () => api("/api/tasks/all");

// ─── Automations ──────────────────────────────────────────────────
export const listAutomations = () => api("/api/automations");
export const createGoal = (agentId: string, body: any) =>
  api(`/api/agents/${agentId}/goals`, { method: "POST", body });
export const toggleGoal = (agentId: string, goalId: string) =>
  api(`/api/agents/${agentId}/goals/${goalId}/toggle`, { method: "POST" });
export const triggerGoal = (agentId: string, goalId: string) =>
  api(`/api/agents/${agentId}/goals/${goalId}/trigger`, { method: "POST" });
export const goalHistory = (agentId: string, goalId: string) =>
  api(`/api/agents/${agentId}/goals/${goalId}/history`);
export const deleteGoal = (agentId: string, goalId: string) =>
  api(`/api/agents/${agentId}/goals/${goalId}`, { method: "DELETE" });
export const createCron = (agentId: string, body: any) =>
  api(`/api/agents/${agentId}/cron`, { method: "POST", body });
export const toggleCron = (agentId: string, index: number) =>
  api(`/api/agents/${agentId}/cron/${index}/toggle`, { method: "POST" });
export const triggerCron = (agentId: string, index: number) =>
  api(`/api/agents/${agentId}/cron/${index}/trigger`, { method: "POST" });
export const cronHistory = (agentId: string, index: number) =>
  api(`/api/agents/${agentId}/cron/${index}/history`);
export const deleteCron = (agentId: string, index: number) =>
  api(`/api/agents/${agentId}/cron/${index}`, { method: "DELETE" });

// ─── MCPs ─────────────────────────────────────────────────────────
export const listMcps = () => api("/api/mcps");
export const mcpCatalog = () => api("/api/mcp-catalog");
export const listMcpKeys = (agentId: string) => api(`/api/agents/${agentId}/mcp-keys`);
export const saveMcpKey = (agentId: string, mcpName: string, envVar: string, value: string) =>
  api(`/api/agents/${agentId}/mcp-keys`, { method: "POST", body: { mcpName, envVar, value } });
export const deleteMcpKey = (agentId: string, mcpName: string) =>
  api(`/api/agents/${agentId}/mcp-keys/${mcpName}`, { method: "DELETE" });
export const listMcpConnections = (agentId: string) => api(`/api/agents/${agentId}/mcp-connections`);
export const createMcpConnection = (agentId: string, body: any) =>
  api(`/api/agents/${agentId}/mcp-connections`, { method: "POST", body });
export const deleteMcpConnection = (agentId: string, instanceName: string) =>
  api(`/api/agents/${agentId}/mcp-connections/${instanceName}`, { method: "DELETE" });

// ─── Channels ─────────────────────────────────────────────────────
export const listChannels = () => api("/api/channels");
export const updateChannel = (name: string, body: any) =>
  api(`/api/channels/${name}`, { method: "PUT", body });
export const addAgentRoute = (channelName: string, body: any) =>
  api(`/api/channels/${channelName}/agents`, { method: "POST", body });
export const removeAgentRoute = (channelName: string, agentId: string) =>
  api(`/api/channels/${channelName}/agents/${agentId}`, { method: "DELETE" });
export const stickyRouting = () => api("/api/sticky-routing");

// ─── Registry / Marketplace ───────────────────────────────────────
export const marketplace = (type: string) => api(`/api/marketplace/${type}`);
export const installMarketplace = (id: string, type: string, extra?: Record<string, unknown>) =>
  api("/api/marketplace/install", { method: "POST", body: { id, type, ...extra } });
export const assignToAgent = (agentId: string, itemId: string, type: string) =>
  api("/api/marketplace/assign", { method: "POST", body: { agentIds: [agentId], id: itemId, type } });
export const assignToAgents = (agentIds: string[], itemId: string, type: string) =>
  api("/api/marketplace/assign", { method: "POST", body: { agentIds, id: itemId, type } });

// ─── Apps ─────────────────────────────────────────────────────────
export const listApps = () => api("/api/apps");
export const createApp = (body: any) => api("/api/apps", { method: "POST", body });
export const updateApp = (id: string, body: any) => api(`/api/apps/${id}`, { method: "PUT", body });
export const deleteApp = (id: string) => api(`/api/apps/${id}`, { method: "DELETE" });

// ─── Activity & Logs ──────────────────────────────────────────────
export const activity = (limit?: number) => api("/api/activity", { query: { limit } });
export const agentLogs = (agentId: string, limit?: number, offset?: number, search?: string) =>
  api(`/api/agents/${agentId}/logs`, { query: { limit, offset, search } });

// ─── Memory ───────────────────────────────────────────────────────
export const agentMemory = (agentId: string, limit?: number) =>
  api(`/api/agents/${agentId}/memory`, { query: { limit } });
export const searchMemory = (agentId: string, query: string) =>
  api(`/api/agents/${agentId}/memory/search`, { method: "POST", body: { query } });
export const clearMemoryContext = (agentId: string) =>
  api(`/api/agents/${agentId}/memory/context`, { method: "DELETE" });

// ─── Pairing ──────────────────────────────────────────────────────
export const listPairing = () => api("/api/pairing");
export const pairSender = (senderKey: string) =>
  api("/api/pairing", { method: "POST", body: { senderKey } });
export const unpairSender = (senderKey: string) =>
  api(`/api/pairing/${encodeURIComponent(senderKey)}`, { method: "DELETE" });

// ─── Config ───────────────────────────────────────────────────────
export const listAccounts = () => api("/api/config/accounts");
export const addAccount = (name: string, path: string) =>
  api("/api/config/accounts", { method: "POST", body: { name, path } });
export const deleteAccount = (name: string) =>
  api(`/api/config/accounts/${encodeURIComponent(name)}`, { method: "DELETE" });
export const accountStatus = (name: string) =>
  api(`/api/config/accounts/${encodeURIComponent(name)}/status`);
export const getServiceConfig = () => api("/api/config/service");
export const updateServiceConfig = (body: any) =>
  api("/api/config/service", { method: "PUT", body });

// ─── Files ────────────────────────────────────────────────────────
export const listFiles = (agentId: string) => api(`/api/agents/${agentId}/files`);
export const downloadFile = (agentId: string, path: string) =>
  api(`/api/agents/${agentId}/download`, { query: { path } });

// ─── Additional ──────────────────────────────────────────────────
export const createProject = (agentId: string, name: string) =>
  api(`/api/agents/${agentId}/projects`, { method: "POST", body: { id: name.toLowerCase().replace(/[^a-z0-9]+/g, "-"), name } });
export const addMonitoredChat = (channelName: string, chatId: string) =>
  api(`/api/channels/${channelName}/monitored`, { method: "POST", body: { chatId: Number(chatId) } });
export const removeMonitoredChat = (channelName: string, chatId: string) =>
  api(`/api/channels/${channelName}/monitored`, { method: "DELETE", body: { chatId: Number(chatId) } });
export const scanSkills = (dir?: string) =>
  api("/api/marketplace/scan-skills", { query: { dir } });
export const createPrompt = (id: string, name: string, content: string) =>
  api("/api/marketplace/create-prompt", { method: "POST", body: { id, name, content } });
export const createSkill = (id: string, name: string, description: string, content: string, scope: string, orgName?: string, agentId?: string) =>
  api("/api/skills/create", { method: "POST", body: { id, name, description, content, scope, orgName, agentId } });
export const addMcpToRegistry = (body: any) =>
  api("/api/marketplace/add-mcp", { method: "POST", body });
export const checkAppHealth = (id: string) =>
  api(`/api/apps/${id}/check-health`, { method: "POST" });
export const startLogin = (name: string, path: string) =>
  api("/api/config/accounts/login", { method: "POST", body: { name, path } });

// ─── Login ───────────────────────────────────────────────────────
export const submitLoginCode = (accountName: string, code: string) =>
  api("/api/config/accounts/login/code", { method: "POST", body: { accountName, code } });

// ─── Marketplace Extras ─────────────────────────────────────────
export const setPlatformDefault = (type: string, id: string) =>
  api("/api/marketplace/platform-default", { method: "POST", body: { type, id } });
export const importSkills = (agentId: string, skills: string[]) =>
  api("/api/marketplace/import-skills", { method: "POST", body: { agentId, skills } });
export const getPromptTrigger = () => api("/api/marketplace/prompt-trigger");
export const setPromptTrigger = (trigger: string) =>
  api("/api/marketplace/prompt-trigger", { method: "POST", body: { trigger } });

// ─── Chat Streaming ─────────────────────────────────────────────
export const getChatJobRaw = (jobId: string, after?: number) =>
  api(`/api/chat/jobs/${jobId}/raw`, { query: { after } });

// ─── Lab / Platform Agents ───────────────────────────────────────
export const getPlatformAgents = () => api("/api/platform-agents");
export const browseDirs = (path?: string) => api("/api/browse-dirs", { query: { path } });

// ─── Auth ────────────────────────────────────────────────────────
export const authLogin = (email: string, password: string) =>
  api("/api/auth/login", { method: "POST", body: { email, password } });
export const authRegister = (email: string, password: string, name: string, licenseKey: string) =>
  api("/api/auth/register", { method: "POST", body: { email, password, name, licenseKey } });
export const authLogout = () => api("/api/auth/logout", { method: "POST" });
export const authMe = () => api("/api/auth/me");

// ─── Settings (API Key) ─────────────────────────────────────────
export const getApiKey = () => api("/api/settings/api-key");
export const setApiKey = (apiKey: string) =>
  api("/api/settings/api-key", { method: "PUT", body: { apiKey } });
export const deleteApiKey = () => api("/api/settings/api-key", { method: "DELETE" });

// ─── Admin ───────────────────────────────────────────────────────
export const adminUsers = () => api("/api/admin/users");
export const adminUpdateUser = (id: string, role: string) =>
  api(`/api/admin/users/${id}`, { method: "PUT", body: { role } });
export const adminLicenseKeys = () => api("/api/admin/license-keys");
export const adminCreateLicenseKey = (maxUses?: number) =>
  api("/api/admin/license-keys", { method: "POST", body: { maxUses } });
export const adminDeleteLicenseKey = (id: string) =>
  api(`/api/admin/license-keys/${id}`, { method: "DELETE" });
export const adminApiKeys = () => api("/api/admin/api-keys");
export const adminCreateApiKey = (name: string) =>
  api("/api/admin/api-keys", { method: "POST", body: { name } });
export const adminDeleteApiKey = (id: string) =>
  api(`/api/admin/api-keys/${id}`, { method: "DELETE" });
export const adminUsage = () => api("/api/admin/usage");

// ─── Uploads ─────────────────────────────────────────────────────
export const listUploads = (agentId?: string) => api("/api/uploads", { query: { agentId } });
export const deleteUpload = (id: string) => api(`/api/uploads/${id}`, { method: "DELETE" });

// ─── Connected Accounts ──────────────────────────────────────────
export const listConnectedAccounts = () => api("/api/connected-accounts");
export const createConnectedAccount = (body: any) =>
  api("/api/connected-accounts", { method: "POST", body });
export const deleteConnectedAccount = (id: string) =>
  api(`/api/connected-accounts/${id}`, { method: "DELETE" });

// ─── Export / Import ─────────────────────────────────────────────
export const exportItem = (type: string, id: string) => api(`/api/export/${type}/${id}`);
export const importItem = (type: string, data: any) =>
  api("/api/import", { method: "POST", body: { type, data } });

// ─── Skills CRUD (top-level) ────────────────────────────────────
export const listSkills = () => api("/api/skills");
export const createSkillCrud = (body: any) => api("/api/skills", { method: "POST", body });
export const updateSkill = (id: string, body: any) => api(`/api/skills/${id}`, { method: "PUT", body });
export const deleteSkill = (id: string) => api(`/api/skills/${id}`, { method: "DELETE" });

// ─── MCPs CRUD (top-level) ──────────────────────────────────────
export const createMcp = (body: any) => api("/api/mcps", { method: "POST", body });
export const updateMcp = (id: string, body: any) => api(`/api/mcps/${id}`, { method: "PUT", body });
export const deleteMcp = (id: string) => api(`/api/mcps/${id}`, { method: "DELETE" });

// ─── Chat extras ────────────────────────────────────────────────
export const resetChat = (agentId: string) =>
  api(`/api/chat/${agentId}/reset`, { method: "POST" });
export const sendWebhook = (agentId: string, text: string, channel?: string) =>
  api(`/webhook/${agentId}`, { method: "POST", body: { text, channel } });

// ─── Misc ────────────────────────────────────────────────────────
export const whoami = (agentId: string) => api(`/api/whoami/${agentId}`);
export const changelog = () => api("/api/changelog");
export const heartbeatHistory = (agentId: string) => api(`/api/agents/${agentId}/heartbeat-history`);
