import { randomBytes } from "node:crypto";
import type { CredentialStore } from "../store/credential-store.js";
import type {
  VaultPluginConfig,
  UserIdentity,
  OAuthProviderConfig,
} from "../types.js";
import { resolveConfigValue, isOAuthProvider } from "../types.js";
import { resolveToolProviders } from "./resolution.js";
import { checkChannelPolicy } from "./channel-policy.js";
import { buildAuthorizationUrl } from "../oauth/flow.js";
import { generatePkce } from "../oauth/pkce.js";
import { CALLBACK_PATH, DEFAULT_RATE_LIMIT } from "../constants.js";

// In-memory rate limit tracking
const rateCounts = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(
  key: string,
  limit: number,
): boolean {
  const now = Date.now();
  const entry = rateCounts.get(key);

  if (!entry || now > entry.resetAt) {
    rateCounts.set(key, { count: 1, resetAt: now + 60_000 });
    return true;
  }

  if (entry.count >= limit) {
    return false;
  }

  entry.count++;
  return true;
}

export type GateResult =
  | { blocked: false }
  | { blocked: true; message: string };

/**
 * Check if a tool call should be gated.
 * Returns { blocked: false } if all credentials are present,
 * or { blocked: true, message } with connect instructions if any are missing.
 */
export function checkGate(params: {
  toolName: string;
  identity: UserIdentity;
  agentId: string;
  store: CredentialStore;
  config: VaultPluginConfig;
}): GateResult {
  const { toolName, identity, agentId, store, config } = params;

  // 1. Resolve which providers this tool requires
  const requiredProviders = resolveToolProviders(toolName, config);
  if (requiredProviders.length === 0) {
    return { blocked: false };
  }

  // 2. Check channel policies — is this tool allowed in this channel?
  for (const provider of requiredProviders) {
    const channelResult = checkChannelPolicy({
      toolName,
      provider,
      identity,
      config,
    });
    if (!channelResult.allowed) {
      store.logAudit({
        agentId,
        channelUserId: identity.userId,
        provider,
        action: "gate_block",
        toolName,
        metadata: JSON.stringify({
          reason: "channel_policy",
          detail: channelResult.reason,
        }),
      });
      return {
        blocked: true,
        message: channelResult.reason,
      };
    }
  }

  // 3. Check rate limit (renumbered from step 2)
  const rateLimit = config.rateLimitPerUserPerMinute ?? DEFAULT_RATE_LIMIT;
  for (const provider of requiredProviders) {
    const rateKey = `${agentId}:${identity.userId}:${provider}`;
    if (!checkRateLimit(rateKey, rateLimit)) {
      store.logAudit({
        agentId,
        channelUserId: identity.userId,
        provider,
        action: "gate_block",
        toolName,
        metadata: JSON.stringify({ reason: "rate_limit" }),
      });
      return {
        blocked: true,
        message: `Rate limit exceeded for ${provider}. Please wait a moment before trying again.`,
      };
    }
  }

  // 4. Check which providers the user has credentials for
  const missing: string[] = [];
  for (const provider of requiredProviders) {
    const cred = store.getCredential(agentId, identity.userId, provider);
    if (!cred) {
      missing.push(provider);
    }
  }

  if (missing.length === 0) {
    // All credentials present — log injection and allow
    for (const provider of requiredProviders) {
      store.logAudit({
        agentId,
        channelUserId: identity.userId,
        provider,
        action: "inject",
        toolName,
      });
    }
    return { blocked: false };
  }

  // 5. Build connect messages for missing providers
  const messages: string[] = [];

  for (const providerName of missing) {
    const providerConfig = config.providers[providerName];
    if (!providerConfig) {
      messages.push(
        `- *${providerName}*: Provider not configured. Contact your admin.`,
      );
      continue;
    }

    if (isOAuthProvider(providerConfig)) {
      const stateToken = randomBytes(16).toString("hex");

      // Determine scopes (check user policies)
      let scopes = providerConfig.scopes;
      const userPolicy = config.userPolicies?.[identity.userId];
      if (userPolicy?.[providerName]?.scopes) {
        scopes = userPolicy[providerName].scopes;
      }

      // Generate PKCE if enabled
      let pkce: { verifier: string; challenge: string } | undefined;
      if (providerConfig.pkce) {
        pkce = generatePkce();
      }

      // Save pending state
      store.savePendingState({
        stateToken,
        agentId,
        channelUserId: identity.userId,
        channelId: identity.channelId,
        provider: providerName,
        pkceVerifier: pkce?.verifier,
        scopes: scopes?.join(" "),
      });

      // Build auth URL
      const callbackUrl = config.callbackBaseUrl
        ? `${config.callbackBaseUrl}${CALLBACK_PATH}`
        : CALLBACK_PATH;

      const authUrl = buildAuthorizationUrl({
        provider: providerConfig,
        state: stateToken,
        callbackUrl,
        pkce: pkce
          ? { challenge: pkce.challenge, method: "S256" }
          : undefined,
        scopeOverrides: scopes,
      });

      messages.push(`- *${providerName}*: [Connect ${providerName}](${authUrl})`);
    } else {
      messages.push(
        `- *${providerName}*: Use \`/connect ${providerName} <your-api-key>\``,
      );
    }
  }

  // Log the gate block
  for (const provider of missing) {
    store.logAudit({
      agentId,
      channelUserId: identity.userId,
      provider,
      action: "gate_block",
      toolName,
      metadata: JSON.stringify({ missing }),
    });
  }

  return {
    blocked: true,
    message:
      `Authentication required. Please connect the following service(s):\n\n` +
      messages.join("\n"),
  };
}

/**
 * Parse a session key into user identity.
 * Supported formats:
 * - "channel:userId" (e.g., "slack:U12345")
 * - "channel:userId:conversationChannelId" (e.g., "slack:U12345:C_ENGINEERING")
 */
export function parseSessionKey(sessionKey: string): UserIdentity | null {
  const parts = sessionKey.split(":");
  if (parts.length < 2) return null;
  return {
    channelId: parts[0],
    userId: parts[1],
    conversationChannelId: parts[2] ?? undefined,
  };
}
