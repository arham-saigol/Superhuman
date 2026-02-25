import Fastify from "fastify";
import cors from "@fastify/cors";
import Redis from "ioredis";
import { ConvexHttpClient } from "convex/browser";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import { enqueueTask, getTaskStatus, setTaskStatus } from "@superhuman/agent";
import { loadEnv, logger, encryptString, resolveConvexConfig } from "@superhuman/core";
import { generateModelResponse, listOpenAIStyleModels, type OpenAIStyleChatCompletionRequest } from "@superhuman/providers";

const env = loadEnv();
const convexConfig = resolveConvexConfig(env);
const app = Fastify({ logger: false });

type RedisClient = {
  ping: () => Promise<string>;
  get: (key: string) => Promise<string | null>;
  set: (key: string, value: string, ...args: Array<string | number>) => Promise<unknown>;
  hset: (key: string, values: Record<string, string | number>) => Promise<number>;
  hgetall: (key: string) => Promise<Record<string, string>>;
  expire: (key: string, seconds: number) => Promise<number>;
  lpush: (key: string, value: string) => Promise<number>;
  rpop: (key: string) => Promise<string | null>;
  zadd: (key: string, score: number, member: string) => Promise<number>;
  zrangebyscore: (key: string, min: number, max: number, ...rest: Array<string | number>) => Promise<string[]>;
  zrem: (key: string, ...members: string[]) => Promise<number>;
  del: (...keys: string[]) => Promise<number>;
};

const redis = new (Redis as unknown as new (url: string, options: { maxRetriesPerRequest: null }) => RedisClient)(
  env.REDIS_URL,
  { maxRetriesPerRequest: null }
);

const AUTH_USER_PREFIX = "superhuman:auth:user:";
const AUTH_SESSION_PREFIX = "superhuman:auth:session:";
const CHAT_STORE_PREFIX = "superhuman:db:chats:";
const FOLDER_STORE_PREFIX = "superhuman:db:folders:";
const CHAT_TASKS_PREFIX = "superhuman:chat:tasks:";
const USER_TASKS_PREFIX = "superhuman:user:tasks:";
const OAUTH_PENDING_PREFIX = "superhuman:oauth:pending:";
const OAUTH_STATUS_PREFIX = "superhuman:oauth:status:";
const OAUTH_OWNER_PREFIX = "superhuman:oauth:owner:";
const ALLOWLIST_CACHE_TTL_MS = 30_000;
const allowlistCache = new Map<string, { allowed: boolean; expiresAt: number }>();

type OAuthProvider = "codex" | "qwen";

type SessionRecord = {
  id: string;
  email: string;
  name: string;
  role: string;
  accessGranted: string;
};

type ChatRecord = {
  id: string;
  user_id: string;
  title: string;
  chat: Record<string, unknown>;
  meta: Record<string, unknown>;
  folder_id: string | null;
  pinned: boolean;
  archived: boolean;
  share_id: string | null;
  tags: Array<{ name: string }>;
  created_at: number;
  updated_at: number;
};

type FolderRecord = {
  id: string;
  user_id: string;
  name: string;
  parent_id: string | null;
  is_expanded: boolean;
  data: Record<string, unknown>;
  meta: Record<string, unknown>;
  items: { chat_ids: string[]; file_ids: string[] };
  created_at: number;
  updated_at: number;
};

function hashPassword(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function bearerToken(authorization?: string): string | null {
  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }
  return authorization.slice(7);
}

async function readSession(token: string) {
  const session = await redis.hgetall(`${AUTH_SESSION_PREFIX}${token}`);
  if (!session || Object.keys(session).length === 0) return null;
  return session;
}

function buildPermissions() {
  return {
    features: {
      channels: false,
      notes: false,
      folders: true,
      web_search: true,
      image_generation: false,
      code_interpreter: false,
      voice_call: false
    },
    workspace: {
      models: false,
      knowledge: false,
      prompts: false,
      tools: true,
      skills: false
    },
    chat: {
      controls: true,
      temporary: true,
      temporary_enforced: false,
      share: false,
      export: false,
      system_prompt: false
    }
  };
}

function buildSessionUser(session: Record<string, string>, token: string) {
  return {
    id: session.id,
    email: session.email,
    name: session.name,
    role: session.role,
    token,
    token_type: "Bearer",
    expires_at: Math.floor((Date.now() + 60 * 60 * 24 * 7 * 1000) / 1000),
    permissions: buildPermissions(),
    profile_image_url: `/api/v1/users/${encodeURIComponent(session.email ?? session.id ?? "user")}/profile/image`,
    access_granted: session.accessGranted === "true"
  };
}

function sessionCookie(token: string | null): string {
  const attrs = ["Path=/", "HttpOnly", "SameSite=Lax"];
  if (env.APP_URL.startsWith("https://")) {
    attrs.push("Secure");
  }

  if (!token) {
    attrs.push("Max-Age=0");
    return `token=; ${attrs.join("; ")}`;
  }

  attrs.push(`Max-Age=${60 * 60 * 24 * 7}`);
  return `token=${token}; ${attrs.join("; ")}`;
}

function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function toUnixSeconds(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }

  // Accept milliseconds from imported payloads and normalize to seconds.
  return value > 10_000_000_000 ? Math.floor(value / 1000) : Math.floor(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function textOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : fallback;
}

function normalizeTags(tags: unknown): Array<{ name: string }> {
  if (!Array.isArray(tags)) {
    return [];
  }

  const out: Array<{ name: string }> = [];
  for (const tag of tags) {
    if (typeof tag === "string" && tag.trim()) {
      out.push({ name: tag.trim() });
    } else if (isRecord(tag) && typeof tag.name === "string" && tag.name.trim()) {
      out.push({ name: tag.name.trim() });
    }
  }

  const deduped = new Map<string, { name: string }>();
  for (const tag of out) {
    deduped.set(tag.name.toLowerCase(), tag);
  }
  return [...deduped.values()];
}

function chatStoreKey(userId: string): string {
  return `${CHAT_STORE_PREFIX}${userId}`;
}

function folderStoreKey(userId: string): string {
  return `${FOLDER_STORE_PREFIX}${userId}`;
}

function chatTasksKey(chatId: string): string {
  return `${CHAT_TASKS_PREFIX}${chatId}`;
}

function userTasksKey(userId: string): string {
  return `${USER_TASKS_PREFIX}${userId}`;
}

async function loadJson<T>(key: string, fallback: T): Promise<T> {
  const raw = await redis.get(key);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function saveJson<T>(key: string, value: T): Promise<void> {
  await redis.set(key, JSON.stringify(value));
}

async function loadChats(userId: string): Promise<ChatRecord[]> {
  const rows = await loadJson<ChatRecord[]>(chatStoreKey(userId), []);
  return rows.sort((a, b) => b.updated_at - a.updated_at);
}

async function saveChats(userId: string, chats: ChatRecord[]): Promise<void> {
  await saveJson(chatStoreKey(userId), chats);
}

async function loadFolders(userId: string): Promise<FolderRecord[]> {
  const rows = await loadJson<FolderRecord[]>(folderStoreKey(userId), []);
  return rows.sort((a, b) => b.updated_at - a.updated_at);
}

async function saveFolders(userId: string, folders: FolderRecord[]): Promise<void> {
  await saveJson(folderStoreKey(userId), folders);
}

function buildChatTitle(chatPayload: Record<string, unknown>, fallback: string): string {
  const direct = textOr(chatPayload.title, "");
  if (direct) {
    return direct;
  }

  const messages = Array.isArray(chatPayload.messages) ? chatPayload.messages : [];
  for (const message of messages) {
    if (isRecord(message) && message.role === "user" && typeof message.content === "string" && message.content.trim()) {
      return message.content.trim().slice(0, 80);
    }
  }

  return fallback;
}

function normalizeChatRecord(userId: string, candidate: Partial<ChatRecord> & { id: string }): ChatRecord {
  const now = nowUnixSeconds();
  return {
    id: candidate.id,
    user_id: userId,
    title: textOr(candidate.title, "New Chat"),
    chat: isRecord(candidate.chat) ? candidate.chat : {},
    meta: isRecord(candidate.meta) ? candidate.meta : {},
    folder_id: typeof candidate.folder_id === "string" ? candidate.folder_id : null,
    pinned: Boolean(candidate.pinned),
    archived: Boolean(candidate.archived),
    share_id: typeof candidate.share_id === "string" ? candidate.share_id : null,
    tags: normalizeTags(candidate.tags),
    created_at: toUnixSeconds(candidate.created_at, now),
    updated_at: toUnixSeconds(candidate.updated_at, now)
  };
}

function normalizeFolderRecord(userId: string, candidate: Partial<FolderRecord> & { id: string }): FolderRecord {
  const now = nowUnixSeconds();
  const items: Record<string, unknown> = isRecord(candidate.items) ? candidate.items : {};
  const chatIds = Array.isArray(items.chat_ids)
    ? items.chat_ids.filter((x: unknown): x is string => typeof x === "string")
    : [];
  const fileIds = Array.isArray(items.file_ids)
    ? items.file_ids.filter((x: unknown): x is string => typeof x === "string")
    : [];

  return {
    id: candidate.id,
    user_id: userId,
    name: textOr(candidate.name, "Folder"),
    parent_id: typeof candidate.parent_id === "string" ? candidate.parent_id : null,
    is_expanded: candidate.is_expanded ?? true,
    data: isRecord(candidate.data) ? candidate.data : {},
    meta: isRecord(candidate.meta) ? candidate.meta : {},
    items: { chat_ids: chatIds, file_ids: fileIds },
    created_at: toUnixSeconds(candidate.created_at, now),
    updated_at: toUnixSeconds(candidate.updated_at, now)
  };
}

type OAuthProviderConfig = {
  provider: OAuthProvider;
  clientId: string;
  clientSecret?: string;
  authorizationUrl: string;
  tokenUrl: string;
  scopes: string[];
};

function isOAuthProvider(value: string): value is OAuthProvider {
  return value === "codex" || value === "qwen";
}

function oauthProviderConfig(provider: OAuthProvider): OAuthProviderConfig | null {
  if (provider === "codex") {
    if (!env.CODEX_OAUTH_CLIENT_ID) {
      return null;
    }
    return {
      provider,
      clientId: env.CODEX_OAUTH_CLIENT_ID,
      clientSecret: env.CODEX_OAUTH_CLIENT_SECRET || undefined,
      authorizationUrl: env.CODEX_OAUTH_AUTH_URL,
      tokenUrl: env.CODEX_OAUTH_TOKEN_URL,
      scopes: env.CODEX_OAUTH_SCOPES.split(/\s+/).filter(Boolean)
    };
  }

  if (!env.QWEN_OAUTH_CLIENT_ID) {
    return null;
  }
  return {
    provider,
    clientId: env.QWEN_OAUTH_CLIENT_ID,
    clientSecret: env.QWEN_OAUTH_CLIENT_SECRET || undefined,
    authorizationUrl: env.QWEN_OAUTH_AUTH_URL,
    tokenUrl: env.QWEN_OAUTH_TOKEN_URL,
    scopes: env.QWEN_OAUTH_SCOPES.split(/\s+/).filter(Boolean)
  };
}

function oauthStatusKey(provider: OAuthProvider, state: string): string {
  return `${OAUTH_STATUS_PREFIX}${provider}:${state}`;
}

function oauthPendingKey(provider: OAuthProvider, state: string): string {
  return `${OAUTH_PENDING_PREFIX}${provider}:${state}`;
}

function oauthOwnerKey(provider: OAuthProvider, state: string): string {
  return `${OAUTH_OWNER_PREFIX}${provider}:${state}`;
}

async function setOAuthStateOwner(provider: OAuthProvider, state: string, userId: string): Promise<void> {
  await redis.set(oauthOwnerKey(provider, state), userId, "EX", 900);
}

async function isOAuthStateOwnedBy(provider: OAuthProvider, state: string, userId: string): Promise<boolean> {
  const owner = await redis.get(oauthOwnerKey(provider, state));
  return owner === userId;
}

function oauthRedirectUri(provider: OAuthProvider): string {
  return `${env.APP_URL.replace(/\/$/, "")}/oauth/callback/${provider}`;
}

function base64url(input: Buffer): string {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(64));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function convexHttpClient(auth?: string): ConvexHttpClient | null {
  if (!convexConfig.url) {
    return null;
  }

  const options: Record<string, unknown> = {};
  if (auth) {
    options.auth = auth;
  }
  if (convexConfig.skipConvexDeploymentUrlCheck) {
    options.skipConvexDeploymentUrlCheck = true;
  }
  return new ConvexHttpClient(convexConfig.url, options as ConstructorParameters<typeof ConvexHttpClient>[1]);
}

function convexAdminClient(): ConvexHttpClient | null {
  if (!convexConfig.adminKey) {
    return null;
  }
  const client = convexHttpClient();
  if (!client) {
    return null;
  }
  (client as unknown as { setAdminAuth: (token: string) => void }).setAdminAuth(convexConfig.adminKey);
  return client;
}

async function storeProviderTokens(provider: OAuthProvider, tokenResponse: {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
  account_email?: string;
}): Promise<void> {
  const client = convexAdminClient();
  if (!client) {
    throw new Error("Convex admin client is not configured");
  }

  await (client as unknown as { mutation: (name: string, args: unknown) => Promise<unknown> }).mutation(
    "oauth:upsertProviderTokens",
    {
      provider,
      subject: "system",
      accountEmail: tokenResponse.account_email,
      tokenType: tokenResponse.token_type,
      scope: tokenResponse.scope,
      accessTokenEncrypted: encryptString(tokenResponse.access_token, env.OAUTH_ENCRYPTION_KEY),
      refreshTokenEncrypted: tokenResponse.refresh_token
        ? encryptString(tokenResponse.refresh_token, env.OAUTH_ENCRYPTION_KEY)
        : undefined,
      expiresAt: typeof tokenResponse.expires_in === "number" ? Date.now() + tokenResponse.expires_in * 1000 : undefined
    }
  );
}

async function exchangeOAuthCode(
  provider: OAuthProvider,
  state: string,
  code: string
): Promise<void> {
  const cfg = oauthProviderConfig(provider);
  if (!cfg) {
    throw new Error(`OAuth client not configured for provider: ${provider}`);
  }

  const pendingRaw = await redis.get(oauthPendingKey(provider, state));
  if (!pendingRaw) {
    throw new Error("OAuth state is missing or expired");
  }

  const pending = JSON.parse(pendingRaw) as { verifier?: string };
  if (!pending.verifier) {
    throw new Error("OAuth PKCE verifier is missing");
  }

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: oauthRedirectUri(provider),
    client_id: cfg.clientId,
    code_verifier: pending.verifier
  });

  if (cfg.clientSecret) {
    params.set("client_secret", cfg.clientSecret);
  }

  const tokenRes = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: params.toString()
  });

  const tokenBody = (await tokenRes.json().catch(() => ({}))) as Record<string, unknown>;
  if (!tokenRes.ok) {
    throw new Error(`OAuth token exchange failed (${tokenRes.status})`);
  }

  const accessToken = typeof tokenBody.access_token === "string" ? tokenBody.access_token : "";
  if (!accessToken) {
    throw new Error("OAuth token response missing access_token");
  }

  await storeProviderTokens(provider, {
    access_token: accessToken,
    refresh_token: typeof tokenBody.refresh_token === "string" ? tokenBody.refresh_token : undefined,
    expires_in: typeof tokenBody.expires_in === "number" ? tokenBody.expires_in : undefined,
    token_type: typeof tokenBody.token_type === "string" ? tokenBody.token_type : undefined,
    scope: typeof tokenBody.scope === "string" ? tokenBody.scope : undefined,
    account_email: typeof tokenBody.email === "string" ? tokenBody.email : undefined
  });

  await redis.del(oauthPendingKey(provider, state));
}

async function syncSessionAccess(token: string, session: SessionRecord): Promise<SessionRecord> {
  let allowlisted = session.accessGranted === "true";
  try {
    allowlisted = await isAllowlistedEmail(session.email);
  } catch (error) {
    logger.warn({ error, email: session.email }, "allowlist check failed; preserving current session access state");
  }
  const expectedAccess = allowlisted ? "true" : "false";
  const expectedRole = allowlisted ? "user" : "pending";

  if (session.accessGranted !== expectedAccess || session.role !== expectedRole) {
    await redis.hset(`${AUTH_SESSION_PREFIX}${token}`, {
      accessGranted: expectedAccess,
      role: expectedRole,
      updatedAt: Date.now()
    });
    return {
      ...session,
      accessGranted: expectedAccess,
      role: expectedRole
    };
  }

  return session;
}

async function requireSession(
  request: { headers: { authorization?: string } },
  reply: { status: (code: number) => { send: (body: unknown) => unknown } },
  options: { allowPending?: boolean } = {}
) {
  const token = bearerToken(request.headers.authorization);
  if (!token) {
    reply.status(401).send({ detail: "Unauthorized" });
    return null;
  }

  const sessionRaw = (await readSession(token)) as SessionRecord | null;
  const session = sessionRaw ? await syncSessionAccess(token, sessionRaw) : null;
  if (!session) {
    reply.status(401).send({ detail: "Unauthorized" });
    return null;
  }

  if (!options.allowPending && session.accessGranted !== "true") {
    reply.status(403).send({ detail: "Access not granted" });
    return null;
  }

  return { token, session };
}

async function requireActiveAllowlistedProfile(
  token: string,
  reply: { status: (code: number) => { send: (body: unknown) => unknown } }
): Promise<boolean> {
  if (!convexConfig.url) {
    return true;
  }

  try {
    const client = convexHttpClient(token);
    if (!client) {
      return true;
    }
    let status = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
      "users:accessStatus",
      {}
    )) as { authenticated: boolean; allowlisted: boolean; activeProfile: boolean };

    if (!status.authenticated || !status.allowlisted) {
      reply.status(403).send({ detail: "Access not granted" });
      return false;
    }

    if (!status.activeProfile) {
      await (client as unknown as { mutation: (name: string, args: unknown) => Promise<unknown> }).mutation(
        "users:activateIfAllowlisted",
        {}
      );
      status = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
        "users:accessStatus",
        {}
      )) as { authenticated: boolean; allowlisted: boolean; activeProfile: boolean };
    }

    if (!status.activeProfile) {
      reply.status(403).send({ detail: "Active profile required" });
      return false;
    }
    return true;
  } catch (error) {
    logger.error({ error }, "active profile verification failed");
    reply.status(500).send({ detail: "Access status check failed" });
    return false;
  }
}

function parseTaskCounter(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function addTaskToUserIndex(userId: string, taskId: string): Promise<void> {
  const key = userTasksKey(userId);
  const current = await loadJson<string[]>(key, []);
  if (!current.includes(taskId)) {
    current.unshift(taskId);
  }
  await saveJson(key, current.slice(0, 500));
}

async function loadOwnedTaskStatus(taskId: string, userId: string): Promise<Record<string, string> | null> {
  const status = await getTaskStatus(redis, taskId);
  if (!status || Object.keys(status).length === 0) {
    return null;
  }

  if (status.userId && status.userId !== userId) {
    return null;
  }

  if (!status.userId) {
    const userTaskIds = await loadJson<string[]>(userTasksKey(userId), []);
    if (!userTaskIds.includes(taskId)) {
      return null;
    }
  }

  return status;
}

function looksLikeBrowserRequest(headers: Record<string, string | string[] | undefined>): boolean {
  return (
    Boolean(headers.origin) ||
    Boolean(headers.referer) ||
    Boolean(headers["sec-fetch-site"]) ||
    Boolean(headers["sec-fetch-mode"])
  );
}

function latestUserText(messages: Array<{ role: string; content: string }>): string {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const msg = messages[i];
    if (msg.role === "user" && typeof msg.content === "string") {
      return msg.content;
    }
  }
  return "";
}

function extractUrls(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s)]+/g) ?? [];
  return [...new Set(matches)].slice(0, 2);
}

function stripHtmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

async function tavilySearchContext(query: string): Promise<string | null> {
  if (!env.TAVILY_API_KEY || !query.trim()) {
    return null;
  }

  try {
    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        api_key: env.TAVILY_API_KEY,
        query,
        search_depth: "basic",
        max_results: 4
      })
    });

    if (!res.ok) {
      return null;
    }

    const body = (await res.json()) as {
      results?: Array<{ title?: string; url?: string; content?: string }>;
    };

    const lines = (body.results ?? []).map((r, idx) =>
      `${idx + 1}. ${r.title ?? "Untitled"}\nURL: ${r.url ?? "n/a"}\nSummary: ${(r.content ?? "").slice(0, 300)}`
    );

    return lines.length > 0 ? `Web search results:\n${lines.join("\n\n")}` : null;
  } catch {
    return null;
  }
}

async function urlFetchContext(text: string): Promise<string | null> {
  const urls = extractUrls(text);
  if (urls.length === 0) return null;

  const contexts: string[] = [];
  for (const url of urls) {
    try {
      const res = await fetch(url, { headers: { "User-Agent": "SuperhumanBot/0.1" } });
      if (!res.ok) continue;
      const raw = await res.text();
      const cleaned = stripHtmlToText(raw).slice(0, 1000);
      contexts.push(`Fetched URL: ${url}\nContent snippet: ${cleaned}`);
    } catch {
      // best-effort fetch
    }
  }

  return contexts.length > 0 ? contexts.join("\n\n") : null;
}

async function isAllowlistedEmail(email: string): Promise<boolean> {
  const client = convexAdminClient();
  if (!client) {
    // In local development without Convex configured, allow access.
    return true;
  }

  const normalized = normalizeEmail(email);
  const cached = allowlistCache.get(normalized);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.allowed;
  }

  try {
    const result = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
      "allowlist:isAllowed",
      { email: normalized }
    )) as { allowed?: boolean };
    const allowed = result.allowed === true;
    allowlistCache.set(normalized, { allowed, expiresAt: Date.now() + ALLOWLIST_CACHE_TTL_MS });
    return allowed;
  } catch {
    const allowedUsers = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
      "allowlist:list",
      {}
    )) as Array<{ email: string }>;
    const allowed = allowedUsers.some((row) => row.email === normalized);
    allowlistCache.set(normalized, { allowed, expiresAt: Date.now() + ALLOWLIST_CACHE_TTL_MS });
    return allowed;
  }
}

async function getAllowlistedForAuth(email: string): Promise<boolean> {
  try {
    return await isAllowlistedEmail(email);
  } catch (error) {
    logger.error({ error, email }, "allowlist lookup failed during auth; defaulting to denied access");
    return false;
  }
}

await app.register(cors, {
  origin: true,
  credentials: true
});

app.get("/api/health", async () => {
  const redisOk = await redis.ping().then(() => true).catch(() => false);
  return {
    ok: redisOk,
    service: "superhuman-web",
    timestamp: new Date().toISOString(),
    redisOk
  };
});

app.get("/api/config", async () => {
  return {
    status: true,
    name: "Superhuman",
    version: "0.1.0",
    default_locale: "en-US",
    default_models: ["gpt-5.3-codex"],
    features: {
      enable_signup: true,
      enable_login_form: true,
      enable_ldap: false,
      enable_websocket: false,
      enable_direct_connections: false,
      enable_message_rating: false,
      enable_web_search: true,
      enable_community_sharing: false,
      enable_channels: false,
      enable_notes: false,
      enable_workspace: false,
      enable_tools: true,
      enable_tool_servers: false,
      enable_admin_analytics: false,
      enable_evaluations: false,
      enable_admin_export: false,
      enable_public_active_users_count: false,
      enable_version_update_check: false,
      enable_code_execution: false,
      auth_trusted_header: false,
      oauth: {
        providers: {}
      }
    }
  };
});

app.get("/api/changelog", async () => ({ changes: [], latest: "0.1.0" }));
app.get("/api/version", async () => ({ version: "0.1.0", name: "superhuman" }));
app.get("/api/version/updates", async () => ({ latest: "0.1.0", has_update: false }));

app.get("/api/v1/auths/signup/enabled", async () => ({ status: true }));
app.get("/api/v1/auths/signup/user/role", async () => ({ role: "user" }));
app.get("/api/v1/auths/admin/details", async () => ({ name: "Superhuman Admin", email: "admin@localhost" }));
app.get("/api/v1/auths/admin/config", async () => ({
  SHOW_ADMIN_DETAILS: false,
  ENABLE_SIGNUP: true
}));
app.post("/api/v1/auths/admin/config", async () => ({ success: true }));
app.get("/api/v1/auths/token/expires", async () => ({ expires: 604800 }));
app.post("/api/v1/auths/token/expires/update", async () => ({ success: true }));
app.post("/api/v1/auths/update/timezone", async () => ({ success: true }));

app.post("/api/v1/auths/signup", async (request, reply) => {
  const body = request.body as { email?: string; password?: string; name?: string };
  const email = normalizeEmail(body.email ?? "");
  const password = body.password ?? "";
  const name = (body.name ?? "User").trim() || "User";

  if (!email || !password) {
    return reply.status(400).send({ detail: "Email and password are required" });
  }

  const userKey = `${AUTH_USER_PREFIX}${email}`;
  const existing = await redis.hgetall(userKey);
  if (existing && Object.keys(existing).length > 0) {
    return reply.status(400).send({ detail: "User already exists" });
  }

  await redis.hset(userKey, {
    email,
    passwordHash: hashPassword(password),
    name,
    createdAt: Date.now()
  });

  const allowlisted = await getAllowlistedForAuth(email);
  const role = allowlisted ? "user" : "pending";

  const token = randomUUID().replace(/-/g, "");
  await redis.hset(`${AUTH_SESSION_PREFIX}${token}`, {
    id: email,
    email,
    name,
    role,
    accessGranted: allowlisted ? "true" : "false",
    createdAt: Date.now()
  });
  await redis.expire(`${AUTH_SESSION_PREFIX}${token}`, 60 * 60 * 24 * 7);

  reply.header("Set-Cookie", sessionCookie(token));
  return buildSessionUser(
    {
      id: email,
      email,
      name,
      role,
      accessGranted: allowlisted ? "true" : "false"
    },
    token
  );
});

app.post("/api/v1/auths/signin", async (request, reply) => {
  const body = request.body as { email?: string; password?: string };
  const email = normalizeEmail(body.email ?? "");
  const password = body.password ?? "";

  const user = await redis.hgetall(`${AUTH_USER_PREFIX}${email}`);
  if (!user || Object.keys(user).length === 0) {
    return reply.status(401).send({ detail: "Invalid credentials" });
  }

  const incomingHash = hashPassword(password);
  if (incomingHash !== user.passwordHash) {
    return reply.status(401).send({ detail: "Invalid credentials" });
  }

  const allowlisted = await getAllowlistedForAuth(email);
  const role = allowlisted ? "user" : "pending";

  const token = randomUUID().replace(/-/g, "");
  await redis.hset(`${AUTH_SESSION_PREFIX}${token}`, {
    id: email,
    email,
    name: user.name ?? email,
    role,
    accessGranted: allowlisted ? "true" : "false",
    createdAt: Date.now()
  });
  await redis.expire(`${AUTH_SESSION_PREFIX}${token}`, 60 * 60 * 24 * 7);

  reply.header("Set-Cookie", sessionCookie(token));
  return buildSessionUser(
    {
      id: email,
      email,
      name: user.name ?? email,
      role,
      accessGranted: allowlisted ? "true" : "false"
    },
    token
  );
});

app.get("/api/v1/auths/", async (request, reply) => {
  const auth = await requireSession(request, reply, { allowPending: true });
  if (!auth) return;
  return buildSessionUser(auth.session, auth.token);
});

app.get("/api/v1/auths/signout", async (request, reply) => {
  const token = bearerToken(request.headers.authorization);
  if (token) {
    await redis.del(`${AUTH_SESSION_PREFIX}${token}`);
  }
  reply.header("Set-Cookie", sessionCookie(null));
  return { success: true };
});

app.get("/api/v1/models", async () => ({ data: listOpenAIStyleModels(env) }));
app.get("/api/models", async () => ({ data: listOpenAIStyleModels(env) }));
app.get("/api/v1/models/list", async () => listOpenAIStyleModels(env));
app.get("/api/v1/models/base", async () => listOpenAIStyleModels(env));
app.get("/api/v1/models/tags", async () => []);
app.get("/api/v1/models/model", async (request) => {
  const id = String((request.query as { id?: string }).id ?? "");
  const model = listOpenAIStyleModels(env).find((item) => item.id === id);
  if (!model) {
    return {};
  }
  return model;
});
app.get("/api/v1/models/model/profile/image", async (_, reply) => {
  return reply
    .type("image/svg+xml")
    .send(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="#0f172a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#e2e8f0" font-size="10">AI</text></svg>`);
});
app.get("/api/v1/users/:id/profile/image", async (_, reply) => {
  return reply
    .type("image/svg+xml")
    .send(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" fill="#0f172a"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#e2e8f0" font-size="10">U</text></svg>`);
});
app.get("/api/v1/tools/", async () => [
  {
    id: "builtin.web_search",
    name: "Web Search",
    meta: {
      description: "Search the web for current information using Tavily when configured."
    }
  },
  {
    id: "builtin.web_fetch",
    name: "Web Fetch",
    meta: {
      description: "Fetch and summarize URL content referenced in the prompt."
    }
  }
]);
app.get("/api/v1/tools/list", async () => [
  {
    id: "builtin.web_search",
    name: "Web Search",
    meta: {
      description: "Search the web for current information using Tavily when configured."
    }
  },
  {
    id: "builtin.web_fetch",
    name: "Web Fetch",
    meta: {
      description: "Fetch and summarize URL content referenced in the prompt."
    }
  }
]);
app.get("/api/v1/functions/", async () => []);
app.get("/api/v1/functions/list", async () => []);
app.get("/api/v1/configs/tool_servers", async () => []);
app.post("/api/v1/configs/tool_servers/verify", async () => ({ ok: false, detail: "Tool servers disabled" }));
app.get("/api/v1/configs/banners", async () => []);
app.get("/api/v1/users/user/settings", async () => ({ ui: {} }));
app.post("/api/v1/users/user/settings/update", async () => ({ success: true }));
app.get("/api/v1/users/user/info", async (request, reply) => {
  const auth = await requireSession(request, reply, { allowPending: true });
  if (!auth) return;
  return buildSessionUser(auth.session, auth.token);
});
app.post("/api/v1/users/user/info/update", async () => ({ success: true }));
app.post("/api/v1/users/user/status/update", async () => ({ success: true }));

function chatListRow(chat: ChatRecord) {
  return {
    id: chat.id,
    title: chat.title,
    created_at: chat.created_at,
    updated_at: chat.updated_at,
    folder_id: chat.folder_id,
    pinned: chat.pinned,
    archived: chat.archived,
    share_id: chat.share_id
  };
}

app.post("/api/v1/chats/new", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { chat?: unknown; folder_id?: string | null };
  const chatPayload = isRecord(body.chat) ? body.chat : {};
  const chatId = textOr(chatPayload.id, randomUUID());
  const now = nowUnixSeconds();
  const title = buildChatTitle(chatPayload, "New Chat");

  const chatRecord = normalizeChatRecord(auth.session.id, {
    id: chatId,
    title,
    chat: { ...chatPayload, id: chatId, title },
    folder_id: body.folder_id ?? null,
    created_at: toUnixSeconds(chatPayload.created_at, now),
    updated_at: now
  });

  const chats = await loadChats(auth.session.id);
  const withoutExisting = chats.filter((chat) => chat.id !== chatId);
  await saveChats(auth.session.id, [chatRecord, ...withoutExisting]);
  return chatRecord;
});

app.post("/api/v1/chats/import", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { chats?: unknown[] };
  const incoming = Array.isArray(body.chats) ? body.chats : [];
  const now = nowUnixSeconds();
  const existing = await loadChats(auth.session.id);
  const byId = new Map<string, ChatRecord>(existing.map((chat) => [chat.id, chat]));
  const imported: ChatRecord[] = [];

  for (const row of incoming) {
    if (!isRecord(row)) continue;
    const chatPayload = isRecord(row.chat) ? row.chat : {};
    const id = textOr(chatPayload.id, randomUUID());
    const title = buildChatTitle(chatPayload, "Imported Chat");

    const merged = normalizeChatRecord(auth.session.id, {
      ...(byId.get(id) ?? {}),
      id,
      title,
      chat: { ...chatPayload, id, title },
      meta: isRecord(row.meta) ? row.meta : {},
      folder_id: typeof row.folder_id === "string" ? row.folder_id : null,
      pinned: Boolean(row.pinned),
      created_at: toUnixSeconds(row.created_at, now),
      updated_at: toUnixSeconds(row.updated_at, now)
    });

    byId.set(id, merged);
    imported.push(merged);
  }

  const chats = [...byId.values()].sort((a, b) => b.updated_at - a.updated_at);
  await saveChats(auth.session.id, chats);
  return imported;
});

app.get("/api/v1/chats/", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const query = request.query as { page?: string; include_pinned?: string; include_folders?: string };
  const page = Math.max(1, Number(query.page ?? "1") || 1);
  const includePinned = query.include_pinned === "true";
  const includeFolders = query.include_folders === "true";
  const pageSize = 40;

  const chats = (await loadChats(auth.session.id))
    .filter((chat) => !chat.archived)
    .filter((chat) => (includePinned ? true : !chat.pinned))
    .filter((chat) => (includeFolders ? true : !chat.folder_id))
    .sort((a, b) => b.updated_at - a.updated_at);

  return chats.slice((page - 1) * pageSize, page * pageSize).map(chatListRow);
});

app.get("/api/v1/chats/pinned", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  return (await loadChats(auth.session.id))
    .filter((chat) => chat.pinned && !chat.archived)
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);
});

app.get("/api/v1/chats/all", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return (await loadChats(auth.session.id)).map(chatListRow);
});

app.get("/api/v1/chats/all/db", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return await loadChats(auth.session.id);
});

app.get("/api/v1/chats/archived", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const query = request.query as { page?: string };
  const page = Math.max(1, Number(query.page ?? "1") || 1);
  const pageSize = 40;

  const rows = (await loadChats(auth.session.id))
    .filter((chat) => chat.archived)
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);

  return rows.slice((page - 1) * pageSize, page * pageSize);
});

app.get("/api/v1/chats/all/archived", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return (await loadChats(auth.session.id)).filter((chat) => chat.archived).map(chatListRow);
});

app.get("/api/v1/chats/shared", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return (await loadChats(auth.session.id))
    .filter((chat) => Boolean(chat.share_id))
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);
});

app.get("/api/v1/chats/all/tags", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const counter = new Map<string, number>();
  for (const chat of await loadChats(auth.session.id)) {
    for (const tag of chat.tags) {
      counter.set(tag.name, (counter.get(tag.name) ?? 0) + 1);
    }
  }

  return [...counter.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, count]) => ({ name, count }));
});

app.get("/api/v1/chats/search", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const query = request.query as { text?: string; page?: string };
  const text = (query.text ?? "").toLowerCase();
  const page = Math.max(1, Number(query.page ?? "1") || 1);
  const pageSize = 40;

  const rows = (await loadChats(auth.session.id))
    .filter((chat) => !chat.archived)
    .filter((chat) => chat.title.toLowerCase().includes(text))
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);

  return rows.slice((page - 1) * pageSize, page * pageSize);
});

app.post("/api/v1/chats/tags", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { name?: string };
  const name = textOr(body.name, "").toLowerCase();
  if (!name) {
    return [];
  }

  return (await loadChats(auth.session.id))
    .filter((chat) => chat.tags.some((tag) => tag.name.toLowerCase() === name))
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);
});

app.get("/api/v1/chats/folder/:folderId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const folderId = (request.params as { folderId: string }).folderId;
  return (await loadChats(auth.session.id))
    .filter((chat) => chat.folder_id === folderId)
    .sort((a, b) => b.updated_at - a.updated_at);
});

app.get("/api/v1/chats/folder/:folderId/list", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const folderId = (request.params as { folderId: string }).folderId;
  const query = request.query as { page?: string };
  const page = Math.max(1, Number(query.page ?? "1") || 1);
  const pageSize = 40;

  const rows = (await loadChats(auth.session.id))
    .filter((chat) => chat.folder_id === folderId)
    .sort((a, b) => b.updated_at - a.updated_at)
    .map(chatListRow);

  return rows.slice((page - 1) * pageSize, page * pageSize);
});

app.post("/api/v1/chats/archive/all", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const now = nowUnixSeconds();
  const chats = (await loadChats(auth.session.id)).map((chat) => ({ ...chat, archived: true, updated_at: now }));
  await saveChats(auth.session.id, chats);
  return { success: true };
});

app.post("/api/v1/chats/unarchive/all", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const now = nowUnixSeconds();
  const chats = (await loadChats(auth.session.id)).map((chat) => ({ ...chat, archived: false, updated_at: now }));
  await saveChats(auth.session.id, chats);
  return { success: true };
});

app.get("/api/v1/chats/list/user/:userId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const userId = (request.params as { userId: string }).userId;
  if (userId !== auth.session.id) {
    return reply.status(403).send({ detail: "Forbidden" });
  }
  return (await loadChats(auth.session.id)).map(chatListRow);
});

app.get("/api/v1/chats/share/:shareId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const shareId = (request.params as { shareId: string }).shareId;
  const chat = (await loadChats(auth.session.id)).find((x) => x.share_id === shareId);
  if (!chat) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  return chat;
});

app.get("/api/v1/chats/:id/pinned", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chat = (await loadChats(auth.session.id)).find((x) => x.id === id);
  if (!chat) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  return { pinned: chat.pinned };
});

app.post("/api/v1/chats/:id/pin", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const now = nowUnixSeconds();
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  chats[idx] = { ...chats[idx], pinned: !chats[idx].pinned, updated_at: now };
  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.post("/api/v1/chats/:id/folder", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { folder_id?: string };
  const now = nowUnixSeconds();
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  chats[idx] = {
    ...chats[idx],
    folder_id: typeof body.folder_id === "string" ? body.folder_id : null,
    updated_at: now
  };
  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.post("/api/v1/chats/:id/archive", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  chats[idx] = { ...chats[idx], archived: true, updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.post("/api/v1/chats/:id/clone", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { title?: string };
  const chats = await loadChats(auth.session.id);
  const source = chats.find((x) => x.id === id);
  if (!source) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  const newId = randomUUID();
  const now = nowUnixSeconds();
  const cloned = normalizeChatRecord(auth.session.id, {
    ...source,
    id: newId,
    title: textOr(body.title, `Clone of ${source.title}`),
    pinned: false,
    share_id: null,
    created_at: now,
    updated_at: now,
    chat: {
      ...(source.chat ?? {}),
      id: newId,
      title: textOr(body.title, `Clone of ${source.title}`)
    }
  });

  await saveChats(auth.session.id, [cloned, ...chats]);
  return cloned;
});

app.post("/api/v1/chats/:id/clone/shared", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const source = chats.find((x) => x.id === id);
  if (!source) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  const newId = randomUUID();
  const now = nowUnixSeconds();
  const cloned = normalizeChatRecord(auth.session.id, {
    ...source,
    id: newId,
    pinned: false,
    share_id: null,
    created_at: now,
    updated_at: now,
    chat: {
      ...(source.chat ?? {}),
      id: newId
    }
  });

  await saveChats(auth.session.id, [cloned, ...chats]);
  return cloned;
});

app.post("/api/v1/chats/:id/share", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  const shareId = randomUUID().replace(/-/g, "");
  chats[idx] = { ...chats[idx], share_id: shareId, updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.delete("/api/v1/chats/:id/share", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  chats[idx] = { ...chats[idx], share_id: null, updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.get("/api/v1/chats/:id/tags", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chat = (await loadChats(auth.session.id)).find((x) => x.id === id);
  if (!chat) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  return chat.tags;
});

app.post("/api/v1/chats/:id/tags", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { name?: string };
  const name = textOr(body.name, "");
  if (!name) {
    return [];
  }

  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  const tags = normalizeTags([...(chats[idx].tags ?? []), { name }]);
  chats[idx] = { ...chats[idx], tags, updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return tags;
});

app.delete("/api/v1/chats/:id/tags", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { name?: string };
  const name = textOr(body.name, "").toLowerCase();

  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  const tags = chats[idx].tags.filter((tag) => tag.name.toLowerCase() !== name);
  chats[idx] = { ...chats[idx], tags, updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return tags;
});

app.delete("/api/v1/chats/:id/tags/all", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  chats[idx] = { ...chats[idx], tags: [], updated_at: nowUnixSeconds() };
  await saveChats(auth.session.id, chats);
  return [];
});

app.get("/api/v1/chats/:id", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const chat = (await loadChats(auth.session.id)).find((x) => x.id === id);
  if (!chat) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  return chat;
});

app.post("/api/v1/chats/:id", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const id = (request.params as { id: string }).id;
  const body = request.body as { chat?: unknown };
  if (!isRecord(body.chat)) {
    return reply.status(400).send({ detail: "chat payload is required" });
  }

  const chats = await loadChats(auth.session.id);
  const idx = chats.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  const existing = chats[idx];
  const mergedChat = { ...(existing.chat ?? {}), ...body.chat, id };
  const nextTitle = buildChatTitle(mergedChat, existing.title);
  chats[idx] = normalizeChatRecord(auth.session.id, {
    ...existing,
    title: nextTitle,
    chat: { ...mergedChat, title: nextTitle },
    tags: normalizeTags(body.chat.tags ?? existing.tags),
    updated_at: nowUnixSeconds()
  });

  await saveChats(auth.session.id, chats);
  return chats[idx];
});

app.delete("/api/v1/chats/:id", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const id = (request.params as { id: string }).id;
  const chats = await loadChats(auth.session.id);
  const existing = chats.find((x) => x.id === id);
  if (!existing) {
    return reply.status(404).send({ detail: "Chat not found" });
  }

  await saveChats(auth.session.id, chats.filter((x) => x.id !== id));
  await redis.del(chatTasksKey(id));
  return { success: true, id };
});

app.delete("/api/v1/chats/", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  await saveChats(auth.session.id, []);
  return { success: true };
});

app.post("/api/v1/folders/", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { name?: string; data?: unknown; meta?: unknown };
  const now = nowUnixSeconds();
  const folder = normalizeFolderRecord(auth.session.id, {
    id: randomUUID(),
    name: textOr(body.name, "Folder"),
    data: isRecord(body.data) ? body.data : {},
    meta: isRecord(body.meta) ? body.meta : {},
    parent_id: null,
    is_expanded: true,
    created_at: now,
    updated_at: now
  });

  const folders = await loadFolders(auth.session.id);
  await saveFolders(auth.session.id, [folder, ...folders]);
  return folder;
});

app.get("/api/v1/folders/", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return await loadFolders(auth.session.id);
});

app.get("/api/v1/folders/:id", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const folder = (await loadFolders(auth.session.id)).find((x) => x.id === id);
  if (!folder) {
    return reply.status(404).send({ detail: "Folder not found" });
  }
  return folder;
});

app.post("/api/v1/folders/:id/update", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const id = (request.params as { id: string }).id;
  const body = request.body as { name?: string; data?: unknown; meta?: unknown };
  const folders = await loadFolders(auth.session.id);
  const idx = folders.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Folder not found" });
  }

  folders[idx] = normalizeFolderRecord(auth.session.id, {
    ...folders[idx],
    name: textOr(body.name, folders[idx].name),
    data: isRecord(body.data) ? body.data : folders[idx].data,
    meta: isRecord(body.meta) ? body.meta : folders[idx].meta,
    updated_at: nowUnixSeconds()
  });
  await saveFolders(auth.session.id, folders);
  return folders[idx];
});

app.post("/api/v1/folders/:id/update/expanded", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { is_expanded?: boolean };
  const folders = await loadFolders(auth.session.id);
  const idx = folders.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Folder not found" });
  }
  folders[idx] = { ...folders[idx], is_expanded: Boolean(body.is_expanded), updated_at: nowUnixSeconds() };
  await saveFolders(auth.session.id, folders);
  return folders[idx];
});

app.post("/api/v1/folders/:id/update/parent", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { parent_id?: string };
  const folders = await loadFolders(auth.session.id);
  const idx = folders.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Folder not found" });
  }
  folders[idx] = {
    ...folders[idx],
    parent_id: typeof body.parent_id === "string" ? body.parent_id : null,
    updated_at: nowUnixSeconds()
  };
  await saveFolders(auth.session.id, folders);
  return folders[idx];
});

app.post("/api/v1/folders/:id/update/items", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const id = (request.params as { id: string }).id;
  const body = request.body as { items?: unknown };
  const folders = await loadFolders(auth.session.id);
  const idx = folders.findIndex((x) => x.id === id);
  if (idx === -1) {
    return reply.status(404).send({ detail: "Folder not found" });
  }

  const items = isRecord(body.items) ? body.items : {};
  folders[idx] = normalizeFolderRecord(auth.session.id, {
    ...folders[idx],
    items: {
      chat_ids: Array.isArray(items.chat_ids) ? items.chat_ids.filter((x): x is string => typeof x === "string") : [],
      file_ids: Array.isArray(items.file_ids) ? items.file_ids.filter((x): x is string => typeof x === "string") : []
    },
    updated_at: nowUnixSeconds()
  });

  await saveFolders(auth.session.id, folders);
  return folders[idx];
});

app.delete("/api/v1/folders/:id", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const id = (request.params as { id: string }).id;
  const query = request.query as { delete_contents?: string };
  const deleteContents = query.delete_contents === "true";

  const folders = await loadFolders(auth.session.id);
  const exists = folders.some((x) => x.id === id);
  if (!exists) {
    return reply.status(404).send({ detail: "Folder not found" });
  }

  const remainingFolders = folders.filter((x) => x.id !== id && x.parent_id !== id);
  await saveFolders(auth.session.id, remainingFolders);

  if (!deleteContents) {
    const chats = await loadChats(auth.session.id);
    const moved = chats.map((chat) => (chat.folder_id === id ? { ...chat, folder_id: null, updated_at: nowUnixSeconds() } : chat));
    await saveChats(auth.session.id, moved);
  } else {
    const chats = await loadChats(auth.session.id);
    const kept = chats.filter((chat) => chat.folder_id !== id);
    await saveChats(auth.session.id, kept);
  }

  return { success: true, id };
});

app.post("/api/v1/tasks/active/chats", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { chat_ids?: string[] };
  const chatIds = Array.isArray(body.chat_ids) ? body.chat_ids : [];
  const userChatIds = new Set((await loadChats(auth.session.id)).map((chat) => chat.id));
  const active: string[] = [];

  for (const chatId of chatIds) {
    if (!userChatIds.has(chatId)) {
      continue;
    }
    const taskIds = await loadJson<string[]>(chatTasksKey(chatId), []);
    if (taskIds.length > 0) {
      active.push(chatId);
    }
  }

  return { active_chat_ids: active };
});

app.get("/api/tasks/chat/:chatId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const chatId = (request.params as { chatId: string }).chatId;
  const chats = await loadChats(auth.session.id);
  if (!chats.some((chat) => chat.id === chatId)) {
    return reply.status(404).send({ detail: "Chat not found" });
  }
  return { task_ids: await loadJson<string[]>(chatTasksKey(chatId), []) };
});

app.post("/api/tasks/stop/:taskId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const taskId = (request.params as { taskId: string }).taskId;
  const status = await loadOwnedTaskStatus(taskId, auth.session.id);
  if (!status) {
    return reply.status(404).send({ detail: "Task not found" });
  }

  await setTaskStatus(
    redis,
    taskId,
    "cancelled",
    parseTaskCounter(status.attempt, 0),
    parseTaskCounter(status.maxAttempts, 1),
    { userId: auth.session.id, ...(status.chatId ? { chatId: status.chatId } : {}) }
  );
  return { ok: true, task_id: taskId };
});

app.post("/api/chat/completed", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { messages?: unknown[]; chat_id?: string; id?: string };
  const messages = Array.isArray(body.messages) ? body.messages : [];
  if (body.chat_id && body.id) {
    const tasks = await loadJson<string[]>(chatTasksKey(body.chat_id), []);
    await saveJson(chatTasksKey(body.chat_id), tasks.filter((taskId) => taskId !== body.id));
  }
  return { messages };
});

app.post("/api/chat/actions/:actionId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { messages?: unknown[] };
  return { action_id: (request.params as { actionId: string }).actionId, messages: Array.isArray(body.messages) ? body.messages : [] };
});

function stringifyMessagesForTask(messages: unknown): string {
  if (!Array.isArray(messages)) {
    return "";
  }

  return messages
    .map((message) => {
      if (!isRecord(message)) {
        return "";
      }
      const role = typeof message.role === "string" ? message.role : "user";
      const content = typeof message.content === "string" ? message.content : "";
      return `${role.toUpperCase()}: ${content}`;
    })
    .filter(Boolean)
    .join("\n");
}

const DEFAULT_TASK_CONFIG = {
  TASK_MODEL: "",
  TASK_MODEL_EXTERNAL: "",
  ENABLE_TITLE_GENERATION: true,
  TITLE_GENERATION_PROMPT_TEMPLATE: "",
  ENABLE_FOLLOW_UP_GENERATION: true,
  FOLLOW_UP_GENERATION_PROMPT_TEMPLATE: "",
  IMAGE_PROMPT_GENERATION_PROMPT_TEMPLATE: "",
  ENABLE_AUTOCOMPLETE_GENERATION: true,
  AUTOCOMPLETE_GENERATION_INPUT_MAX_LENGTH: -1,
  TAGS_GENERATION_PROMPT_TEMPLATE: "",
  ENABLE_TAGS_GENERATION: true,
  ENABLE_SEARCH_QUERY_GENERATION: true,
  ENABLE_RETRIEVAL_QUERY_GENERATION: true,
  QUERY_GENERATION_PROMPT_TEMPLATE: "",
  TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE: "",
  VOICE_MODE_PROMPT_TEMPLATE: ""
};

app.get("/api/v1/tasks/config", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  return await loadJson("superhuman:tasks:config", DEFAULT_TASK_CONFIG);
});

app.post("/api/v1/tasks/config/update", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = isRecord(request.body) ? request.body : {};
  const current = await loadJson("superhuman:tasks:config", DEFAULT_TASK_CONFIG);
  const next = { ...current, ...body };
  await saveJson("superhuman:tasks:config", next);
  return next;
});

app.post("/api/v1/tasks/title/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { model?: string; messages?: unknown[] };
  const model = textOr(body.model, "gpt-5.3-codex");
  const transcript = stringifyMessagesForTask(body.messages);

  try {
    return await generateModelResponse(env, {
      model,
      messages: [
        {
          role: "system",
          content:
            "Generate a short chat title in JSON only: {\"title\":\"...\"}. Keep it concise and specific."
        },
        {
          role: "user",
          content: transcript
        }
      ]
    });
  } catch (error) {
    return reply.status(500).send({ detail: error instanceof Error ? error.message : "title generation failed" });
  }
});

app.post("/api/v1/tasks/follow_ups/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { model?: string; messages?: unknown[] };
  const model = textOr(body.model, "gpt-5.3-codex");
  const transcript = stringifyMessagesForTask(body.messages);

  try {
    return await generateModelResponse(env, {
      model,
      messages: [
        {
          role: "system",
          content:
            "Return JSON only: {\"follow_ups\":[\"question 1\",\"question 2\",\"question 3\"]}. Generate useful next questions."
        },
        {
          role: "user",
          content: transcript
        }
      ]
    });
  } catch (error) {
    return reply.status(500).send({ detail: error instanceof Error ? error.message : "follow-up generation failed" });
  }
});

async function runTaskCompletion(
  reply: { status: (code: number) => { send: (body: unknown) => unknown } },
  body: { model?: string; prompt?: string; messages?: unknown[]; responses?: unknown[] },
  systemPrompt: string
) {
  const model = textOr(body.model, "gpt-5.3-codex");
  const prompt = textOr(body.prompt, stringifyMessagesForTask(body.messages));
  const responses = Array.isArray(body.responses) ? body.responses.filter((x): x is string => typeof x === "string") : [];

  try {
    return await generateModelResponse(env, {
      model,
      messages: [
        { role: "system", content: systemPrompt },
        {
          role: "user",
          content: [prompt, responses.length > 0 ? `Responses:\n${responses.join("\n\n")}` : ""].filter(Boolean).join("\n\n")
        }
      ]
    });
  } catch (error) {
    return reply.status(500).send({ detail: error instanceof Error ? error.message : "task completion failed" });
  }
}

app.post("/api/v1/tasks/tags/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { model?: string; messages?: unknown[]; prompt?: string };
  return await runTaskCompletion(reply, body, "Return JSON only: {\"tags\":[\"tag1\",\"tag2\",\"tag3\"]}.");
});

app.post("/api/v1/tasks/emoji/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { model?: string; messages?: unknown[]; prompt?: string };
  return await runTaskCompletion(reply, body, "Return JSON only: {\"emoji\":\"😀\"}. Pick one emoji.");
});

app.post("/api/v1/tasks/queries/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { model?: string; messages?: unknown[]; prompt?: string };
  return await runTaskCompletion(
    reply,
    body,
    "Return JSON only: {\"queries\":[\"search query 1\",\"search query 2\"]} for retrieval/web search."
  );
});

app.post("/api/v1/tasks/auto/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { model?: string; messages?: unknown[]; prompt?: string };
  return await runTaskCompletion(reply, body, "Return a concise assistant response.");
});

app.post("/api/v1/tasks/moa/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as { model?: string; prompt?: string; responses?: unknown[] };
  return await runTaskCompletion(reply, body, "Synthesize the best final answer from candidate responses.");
});

async function handleCompletion(
  request: OpenAIStyleChatCompletionRequest & { features?: { web_search?: boolean } },
  reply: { header: (k: string, v: string) => void; send: (body: unknown) => unknown; raw: { write: (chunk: string) => void; end: () => void } }
) {
  const userText = latestUserText(request.messages);
  const webSearchRequested = request.features?.web_search === true;

  const enrichedMessages = [...request.messages];

  if (webSearchRequested) {
    const searchContext = await tavilySearchContext(userText);
    if (searchContext) {
      enrichedMessages.unshift({
        role: "system",
        content: `${searchContext}\n\nUse these sources when useful and cite URLs in the answer.`
      });
    }
  }

  const fetchedContext = await urlFetchContext(userText);
  if (fetchedContext) {
    enrichedMessages.unshift({
      role: "system",
      content: `${fetchedContext}\n\nUse fetched webpage snippets for factual grounding.`
    });
  }

  const completion = await generateModelResponse(env, {
    ...request,
    messages: enrichedMessages
  });

  // Open WebUI's generateOpenAIChatCompletion expects JSON, even when `stream=true`.
  return reply.send(completion);
}

app.post("/api/chat/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as OpenAIStyleChatCompletionRequest;
  try {
    return await handleCompletion(body, reply);
  } catch (error) {
    return reply.status(500).send({ detail: error instanceof Error ? error.message : "completion failed" });
  }
});

app.post("/api/v1/chat/completions", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const body = request.body as OpenAIStyleChatCompletionRequest;
  try {
    return await handleCompletion(body, reply);
  } catch (error) {
    return reply.status(500).send({ detail: error instanceof Error ? error.message : "completion failed" });
  }
});

app.post("/api/v1/tasks", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const body = request.body as { prompt?: string; chatId?: string; maxAttempts?: number };
  const chatId = body.chatId?.trim() || "default";
  if (body.chatId) {
    const chats = await loadChats(auth.session.id);
    if (!chats.some((chat) => chat.id === body.chatId)) {
      return reply.status(404).send({ detail: "Chat not found" });
    }
  }

  const taskId = randomUUID();
  const task = {
    id: taskId,
    userId: auth.session.id,
    chatId,
    prompt: body.prompt ?? "",
    state: "queued",
    attempt: 0,
    maxAttempts: Math.max(1, Math.min(10, body.maxAttempts ?? 3)),
    createdAt: Date.now(),
    updatedAt: Date.now()
  } as const;

  await enqueueTask(redis, task);
  await addTaskToUserIndex(auth.session.id, taskId);
  const chatTaskIds = await loadJson<string[]>(chatTasksKey(chatId), []);
  if (!chatTaskIds.includes(taskId)) {
    chatTaskIds.push(taskId);
    await saveJson(chatTasksKey(chatId), chatTaskIds);
  }
  return { ok: true, taskId };
});

app.get("/api/v1/tasks", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const taskIds = await loadJson<string[]>(userTasksKey(auth.session.id), []);
  const tasks: Array<{ taskId: string; status: Record<string, string> }> = [];

  for (const taskId of taskIds) {
    const status = await loadOwnedTaskStatus(taskId, auth.session.id);
    if (status) {
      tasks.push({ taskId, status });
    }
  }

  tasks.sort((a, b) => parseTaskCounter(b.status.updatedAt, 0) - parseTaskCounter(a.status.updatedAt, 0));
  return { tasks };
});

app.get("/api/v1/tasks/:taskId", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const taskId = (request.params as { taskId: string }).taskId;
  const status = await loadOwnedTaskStatus(taskId, auth.session.id);
  if (!status) {
    return reply.status(404).send({ detail: "Task not found" });
  }

  return { taskId, status };
});

app.post("/api/v1/tasks/:taskId/stop", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;

  const taskId = (request.params as { taskId: string }).taskId;
  const status = await loadOwnedTaskStatus(taskId, auth.session.id);
  if (!status) {
    return reply.status(404).send({ detail: "Task not found" });
  }

  await setTaskStatus(
    redis,
    taskId,
    "cancelled",
    parseTaskCounter(status.attempt, 0),
    parseTaskCounter(status.maxAttempts, 1),
    { userId: auth.session.id, ...(status.chatId ? { chatId: status.chatId } : {}) }
  );
  return { ok: true, taskId, state: "cancelled" };
});

app.post("/api/oauth/start/:provider", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const active = await requireActiveAllowlistedProfile(auth.token, reply);
  if (!active) return;

  const providerRaw = (request.params as { provider: string }).provider;
  if (!isOAuthProvider(providerRaw)) {
    return reply.status(400).send({ detail: "unsupported provider" });
  }

  const cfg = oauthProviderConfig(providerRaw);
  if (!cfg) {
    return reply.status(400).send({ detail: `OAuth client not configured for provider: ${providerRaw}` });
  }

  const state = randomUUID();
  const { verifier, challenge } = createPkcePair();
  await redis.set(
    oauthPendingKey(providerRaw, state),
    JSON.stringify({ verifier, createdAt: Date.now(), userId: auth.session.id }),
    "EX",
    600
  );
  await setOAuthStateOwner(providerRaw, state, auth.session.id);
  await redis.set(oauthStatusKey(providerRaw, state), "pending", "EX", 900);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: oauthRedirectUri(providerRaw),
    scope: cfg.scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  return {
    ok: true,
    provider: providerRaw,
    state,
    redirect_uri: oauthRedirectUri(providerRaw),
    expires_in_seconds: 600,
    authorization_url: `${cfg.authorizationUrl}?${params.toString()}`
  };
});

app.get("/api/oauth/status/:provider", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const active = await requireActiveAllowlistedProfile(auth.token, reply);
  if (!active) return;

  const providerRaw = (request.params as { provider: string }).provider;
  if (!isOAuthProvider(providerRaw)) {
    return reply.status(400).send({ detail: "unsupported provider" });
  }

  const state = String((request.query as { state?: string }).state ?? "");
  if (!state) {
    const client = convexAdminClient();
    if (!client) {
      return { ok: false, provider: providerRaw, status: "missing_convex_admin" };
    }

    let status: { authorized?: boolean; updatedAt?: number | null; expiresAt?: number | null };
    try {
      status = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
        "oauth:providerStatus",
        { provider: providerRaw, subject: "system" }
      )) as { authorized?: boolean; updatedAt?: number | null; expiresAt?: number | null };
    } catch (error) {
      logger.error({ error, provider: providerRaw }, "oauth provider status query failed");
      return { ok: false, provider: providerRaw, status: "status_query_failed" };
    }

    return {
      ok: status.authorized === true,
      provider: providerRaw,
      status: status.authorized === true ? "authorized" : "not_authorized",
      authorized: status.authorized === true,
      updatedAt: status.updatedAt ?? null,
      expiresAt: status.expiresAt ?? null
    };
  }

  const owned = await isOAuthStateOwnedBy(providerRaw, state, auth.session.id);
  if (!owned) {
    return reply.status(404).send({ detail: "OAuth state not found" });
  }

  const statusValue = await redis.get(oauthStatusKey(providerRaw, state));
  if (!statusValue) {
    return { ok: false, provider: providerRaw, state, status: "pending" };
  }
  return {
    ok: statusValue === "authorized",
    provider: providerRaw,
    state,
    status: statusValue,
    authorized: statusValue === "authorized"
  };
});

app.get("/api/oauth/providers/status", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const active = await requireActiveAllowlistedProfile(auth.token, reply);
  if (!active) return;

  const client = convexAdminClient();
  if (!client) {
    return reply.status(400).send({ detail: "Convex admin client is not configured" });
  }

  let rows: Array<Record<string, unknown>>;
  try {
    rows = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
      "oauth:listProviderStatus",
      { subject: "system" }
    )) as Array<Record<string, unknown>>;
  } catch (error) {
    logger.error({ error }, "oauth providers status query failed");
    return reply.status(500).send({ detail: "oauth status query failed" });
  }

  return { ok: true, providers: rows };
});

app.post("/api/oauth/manual/:provider", async (request, reply) => {
  const auth = await requireSession(request, reply);
  if (!auth) return;
  const active = await requireActiveAllowlistedProfile(auth.token, reply);
  if (!active) return;

  if (looksLikeBrowserRequest(request.headers)) {
    return reply.status(403).send({ detail: "Manual OAuth exchange is restricted to CLI/server-side clients" });
  }

  const providerRaw = (request.params as { provider: string }).provider;
  if (!isOAuthProvider(providerRaw)) {
    return reply.status(400).send({ detail: "unsupported provider" });
  }

  const body = request.body as { state?: string; code?: string };
  const state = String(body.state ?? "");
  if (!state) {
    return reply.status(400).send({ detail: "state is required" });
  }

  const owned = await isOAuthStateOwnedBy(providerRaw, state, auth.session.id);
  if (!owned) {
    return reply.status(404).send({ detail: "OAuth state not found" });
  }

  const pendingRaw = await redis.get(oauthPendingKey(providerRaw, state));
  if (!pendingRaw) {
    return reply.status(400).send({ detail: "OAuth state is missing or expired" });
  }

  let pending: { userId?: string; authorizationCode?: string } = {};
  try {
    pending = JSON.parse(pendingRaw) as { userId?: string; authorizationCode?: string };
  } catch {
    pending = {};
  }

  if (pending.userId && pending.userId !== auth.session.id) {
    return reply.status(404).send({ detail: "OAuth state not found" });
  }

  const code = String(body.code ?? pending.authorizationCode ?? "");
  if (!code) {
    return reply.status(400).send({ detail: "code is required" });
  }

  try {
    await exchangeOAuthCode(providerRaw, state, code);
    await redis.set(oauthStatusKey(providerRaw, state), "authorized", "EX", 900);
    return { ok: true, provider: providerRaw, state, status: "authorized" };
  } catch (error) {
    await redis.set(oauthStatusKey(providerRaw, state), "error:exchange_failed", "EX", 900);
    logger.error({ error, provider: providerRaw }, "manual oauth exchange failed");
    return reply.status(400).send({ detail: "OAuth exchange failed" });
  }
});

app.get("/oauth/callback/:provider", async (request, reply) => {
  const providerRaw = (request.params as { provider: string }).provider;
  if (!isOAuthProvider(providerRaw)) {
    return reply.status(400).type("text/html").send("<h1>OAuth failed</h1><p>Unsupported provider.</p>");
  }

  const query = request.query as { code?: string; state?: string; error?: string };
  const state = query.state ?? "";
  if (!state) {
    return reply.type("text/html").send("<h1>OAuth failed</h1><p>Missing state.</p>");
  }

  const pendingRaw = await redis.get(oauthPendingKey(providerRaw, state));
  if (!pendingRaw) {
    await redis.set(oauthStatusKey(providerRaw, state), "error:missing_state", "EX", 900);
    return reply.type("text/html").send("<h1>OAuth failed</h1><p>State is missing or expired.</p>");
  }

  if (query.error) {
    await redis.set(oauthStatusKey(providerRaw, state), `error:${query.error}`, "EX", 900);
    return reply.type("text/html").send(`<h1>OAuth failed</h1><p>${query.error}</p>`);
  }

  if (!query.code) {
    await redis.set(oauthStatusKey(providerRaw, state), "error:missing_code", "EX", 900);
    return reply.type("text/html").send("<h1>OAuth failed</h1><p>Missing code.</p>");
  }

  try {
    const pending = JSON.parse(pendingRaw) as { verifier?: string; userId?: string };
    await redis.set(
      oauthPendingKey(providerRaw, state),
      JSON.stringify({ ...pending, authorizationCode: query.code, updatedAt: Date.now() }),
      "EX",
      600
    );
    await redis.set(oauthStatusKey(providerRaw, state), "code_received", "EX", 900);
    return reply
      .type("text/html")
      .send("<h1>OAuth code received</h1><p>Return to the CLI to complete token exchange.</p>");
  } catch (error) {
    await redis.set(oauthStatusKey(providerRaw, state), "error:callback_failed", "EX", 900);
    logger.error({ error, provider: providerRaw }, "oauth callback processing failed");
    return reply.type("text/html").send("<h1>OAuth failed</h1><p>Callback processing failed.</p>");
  }
});

app.post("/api/settings/providers/test", async (request) => {
  const body = request.body as Record<string, string | undefined>;
  const checks = Object.entries(body).map(([key, value]) => ({
    key,
    ok: Boolean(value && String(value).trim().length > 0)
  }));

  return {
    ok: checks.every((x) => x.ok),
    checks
  };
});

app.get("/api/access/status", async (request, reply) => {
  const auth = await requireSession(request, reply, { allowPending: true });
  if (!auth) {
    return { authenticated: false, allowlisted: false, activeProfile: false };
  }

  const allowlisted = auth.session.accessGranted === "true";
  return {
    authenticated: true,
    allowlisted,
    activeProfile: allowlisted
  };
});

app.get("/access-not-granted", async (_, reply) => {
  return reply.type("text/html").send(`<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
  <h1>Access not granted</h1>
  <p>Your account is authenticated, but your email is not allowlisted for this private instance.</p>
  </body></html>`);
});

app.get("/", async (_, reply) => {
  return reply.type("text/html").send(`<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
  <h1>Superhuman</h1>
  <p>Frontend baseline: Open WebUI source is vendored at <code>vendor/open-webui</code>.</p>
  <p>Use <code>superhuman doctor</code> to validate runtime dependencies.</p>
  </body></html>`);
});

const port = Number(process.env.PORT ?? 3000);

app.listen({ port, host: "0.0.0.0" }).then(() => {
  logger.info({ port }, "web server started");
});
