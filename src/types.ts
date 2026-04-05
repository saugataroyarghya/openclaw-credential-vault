// ── Provider Configuration ──

export type OAuthProviderConfig = {
  type: "oauth2";
  authUrl: string;
  tokenUrl: string;
  revokeUrl?: string;
  scopes?: string[];
  maxScopes?: string[];
  minScopes?: string[];
  clientId: string | { env: string };
  clientSecret: string | { env: string };
  pkce?: boolean;
  inject?: InjectionStrategy;
  headerName?: string;
  headerPrefix?: string;
  queryParamName?: string;
};

export type ApiKeyProviderConfig = {
  type: "api_key";
  inject?: InjectionStrategy;
  headerName?: string;
  headerPrefix?: string;
  queryParamName?: string;
};

export type ProviderConfig = OAuthProviderConfig | ApiKeyProviderConfig;

// ── Injection ──

export type InjectionStrategy = "bearer" | "header" | "query";

export type InjectionParams = {
  strategy: InjectionStrategy;
  headerName?: string;
  headerPrefix?: string;
  queryParamName?: string;
};

// ── MCP Server Configuration ──

export type McpAuthConfig = {
  provider: string;
  inject?: InjectionStrategy;
  headerName?: string;
  headerPrefix?: string;
};

export type McpServerConfig = {
  url: string;
  transport?: "streamable-http" | "sse";
  auth?: McpAuthConfig;
  toolPrefix?: string;
};

// ── User Policies ──

export type UserProviderPolicy = {
  scopes?: string[];
  allowWrite?: boolean;
};

export type UserPolicy = Record<string, UserProviderPolicy>;

// ── Channel Policies ──

export type ChannelProviderPolicy = {
  tools: string[];
};

export type ChannelUserOverride = {
  providers: Record<string, ChannelProviderPolicy>;
};

export type ChannelPolicy = {
  providers: Record<string, ChannelProviderPolicy>;
  userOverrides?: Record<string, ChannelUserOverride>;
};

// ── Plugin Config (top-level) ──

export type VaultPluginConfig = {
  providers: Record<string, ProviderConfig>;
  mcpServers?: Record<string, McpServerConfig>;
  toolProviderMap?: Record<string, string | string[]>;
  userPolicies?: Record<string, UserPolicy>;
  channelPolicies?: Record<string, ChannelPolicy>;
  callbackBaseUrl?: string;
  rateLimitPerUserPerMinute?: number;
};

// ── Credential Payloads (encrypted at rest) ──

export type OAuthCredentialPayload = {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
};

export type ApiKeyCredentialPayload = {
  api_key: string;
};

export type CredentialPayload = OAuthCredentialPayload | ApiKeyCredentialPayload;

// ── Database Row Types ──

export type CredentialRow = {
  id: number;
  agent_id: string;
  channel_user_id: string;
  channel_id: string;
  provider: string;
  auth_type: "oauth2" | "api_key";
  encrypted_data: string;
  iv: string;
  auth_tag: string;
  scopes: string | null;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
};

export type PendingStateRow = {
  state_token: string;
  agent_id: string;
  channel_user_id: string;
  channel_id: string;
  provider: string;
  pkce_verifier: string | null;
  pkce_iv: string | null;
  pkce_auth_tag: string | null;
  scopes: string | null;
  expires_at: number;
  created_at: number;
};

export type AuditAction =
  | "connect"
  | "disconnect"
  | "inject"
  | "refresh"
  | "revoke"
  | "gate_block";

export type AuditLogRow = {
  id: number;
  agent_id: string;
  channel_user_id: string;
  provider: string;
  action: AuditAction;
  tool_name: string | null;
  mcp_server: string | null;
  timestamp: number;
  metadata: string | null;
};

// ── User Identity ──

export type UserIdentity = {
  channelId: string;
  userId: string;
  conversationChannelId?: string;
};

// ── OAuth Token Response ──

export type OAuthTokenResponse = {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
};

// ── Decrypted Credential ──

export type DecryptedCredential = {
  row: CredentialRow;
  payload: CredentialPayload;
};

// ── Helpers ──

export function resolveConfigValue(value: string | { env: string }): string {
  if (typeof value === "string") return value;
  const envVal = process.env[value.env];
  if (!envVal) {
    throw new Error(`Required env var ${value.env} is not set.`);
  }
  return envVal;
}

export function isOAuthProvider(
  config: ProviderConfig,
): config is OAuthProviderConfig {
  return config.type === "oauth2";
}

export function isApiKeyProvider(
  config: ProviderConfig,
): config is ApiKeyProviderConfig {
  return config.type === "api_key";
}
