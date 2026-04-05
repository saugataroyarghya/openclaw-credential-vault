import { randomBytes } from "node:crypto";

import type { CredentialStore } from "../store/credential-store.js";
import type {
  VaultPluginConfig,
  OAuthProviderConfig,
} from "../types.js";
import { isOAuthProvider } from "../types.js";
import { buildAuthorizationUrl } from "../oauth/flow.js";
import { generatePkce } from "../oauth/pkce.js";
import { CALLBACK_PATH } from "../constants.js";
import { APIKEY_FORM_PATH } from "../api-key/web-form.js";
import type { CommandContext, CommandResult } from "./types.js";

export function handleConnect(
  ctx: CommandContext,
  deps: { store: CredentialStore; config: VaultPluginConfig },
): CommandResult | Promise<CommandResult> {
  const { store, config } = deps;
  const parts = ctx.args.trim().split(/\s+/);
  const providerName = parts[0];

  if (!providerName) {
    const available = Object.keys(config.providers).join(", ");
    return { text: `Usage: /connect <provider>\nAvailable providers: ${available}` };
  }

  const providerConfig = config.providers[providerName];
  if (!providerConfig) {
    const available = Object.keys(config.providers).join(", ");
    return {
      text: `Unknown provider "${providerName}". Available providers: ${available}`,
    };
  }

  // Generate state token (used for both OAuth and API key web form)
  const stateToken = randomBytes(16).toString("hex");

  if (providerConfig.type === "api_key") {
    // Save pending state so the web form can look it up
    store.savePendingState({
      stateToken,
      agentId: ctx.agentId,
      channelUserId: ctx.senderId,
      channelId: ctx.channelId,
      provider: providerName,
    });

    // Direct user to the secure web form — key never appears in chat
    const formUrl = `${config.callbackBaseUrl ?? ""}${APIKEY_FORM_PATH}?state=${stateToken}`;
    return {
      text: `To connect *${providerName}*, enter your API key securely:\n${formUrl}\n\nYour key will be encrypted. The AI agent will never see it.`,
    };
  }

  // OAuth2 flow
  const oauthConfig: OAuthProviderConfig = providerConfig;

  // Determine scopes: user policy overrides take precedence
  let scopes = oauthConfig.scopes;
  if (config.userPolicies) {
    const userPolicy = config.userPolicies[ctx.senderId];
    if (userPolicy?.[providerName]?.scopes) {
      scopes = userPolicy[providerName].scopes;
    }
  }

  // Generate PKCE if the provider requires it
  let pkce: { verifier: string; challenge: string } | undefined;
  if (oauthConfig.pkce) {
    pkce = generatePkce();
  }

  const callbackUrl = (config.callbackBaseUrl ?? "") + CALLBACK_PATH;

  store.savePendingState({
    stateToken,
    agentId: ctx.agentId,
    channelUserId: ctx.senderId,
    channelId: ctx.channelId,
    provider: providerName,
    pkceVerifier: pkce?.verifier,
    scopes: scopes?.join(" "),
  });

  const authUrl = buildAuthorizationUrl({
    provider: oauthConfig,
    state: stateToken,
    callbackUrl,
    pkce: pkce ? { challenge: pkce.challenge, method: "S256" } : undefined,
    scopeOverrides: scopes,
  });

  return {
    text: `To connect *${providerName}*, please authorize access:\n${authUrl}`,
  };
}
