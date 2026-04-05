import type {
  VaultPluginConfig,
  UserIdentity,
  ChannelPolicy,
  ChannelProviderPolicy,
} from "../types.js";

export type ChannelCheckResult =
  | { allowed: true }
  | { allowed: false; reason: string };

/**
 * Check if a tool call is allowed by channel policies.
 *
 * Resolution:
 * 1. Find the channel policy for the conversation channel
 * 2. If user has an override in that channel, use the override (replaces, not merges)
 * 3. Check if the provider is listed
 * 4. Check if the tool name (without provider prefix) matches any pattern
 * 5. If no channel policy found, use "default" — if no default, allow (no policy = no restriction)
 */
export function checkChannelPolicy(params: {
  toolName: string;
  provider: string;
  identity: UserIdentity;
  config: VaultPluginConfig;
}): ChannelCheckResult {
  const { toolName, provider, identity, config } = params;
  const policies = config.channelPolicies;

  // No channel policies configured — everything allowed
  if (!policies) {
    return { allowed: true };
  }

  // Resolve which channel ID to use for policy lookup
  const channelKey = identity.conversationChannelId ?? "DM";

  // Find matching policy: exact channel match, then "DM" for DMs, then "default"
  let policy: ChannelPolicy | undefined = policies[channelKey];
  if (!policy && !identity.conversationChannelId) {
    policy = policies["DM"];
  }
  if (!policy) {
    policy = policies["default"];
  }

  // No matching policy and no default — allow (unconfigured = unrestricted)
  if (!policy) {
    return { allowed: true };
  }

  // Check for user-specific override (replaces channel defaults entirely)
  let providerMap: Record<string, ChannelProviderPolicy>;
  const userOverride = policy.userOverrides?.[identity.userId];
  if (userOverride) {
    providerMap = userOverride.providers;
  } else {
    providerMap = policy.providers;
  }

  // Is the provider available in this channel?
  const providerPolicy = providerMap[provider];
  if (!providerPolicy) {
    return {
      allowed: false,
      reason: `Provider "${provider}" is not available in this channel.`,
    };
  }

  // Strip the provider prefix from the tool name to get the bare tool name
  // e.g., "github_list_repos" → "list_repos" (strip "github_")
  const prefixPattern = `${provider}_`;
  const bareToolName = toolName.startsWith(prefixPattern)
    ? toolName.slice(prefixPattern.length)
    : toolName;

  // Check if the bare tool name matches any allowed pattern
  const allowed = providerPolicy.tools.some((pattern) =>
    matchToolPattern(pattern, bareToolName),
  );

  if (!allowed) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is not available in this channel.`,
    };
  }

  return { allowed: true };
}

/**
 * Match a tool name against a pattern.
 * Supports:
 * - "*" matches everything
 * - "list_*" matches anything starting with "list_"
 * - "get_repo" matches exactly "get_repo"
 */
function matchToolPattern(pattern: string, toolName: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) {
    return toolName.startsWith(pattern.slice(0, -1));
  }
  return pattern === toolName;
}
