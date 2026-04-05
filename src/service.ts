import type { CredentialStore } from "./store/credential-store.js";
import type { VaultPluginConfig, OAuthProviderConfig } from "./types.js";
import { resolveConfigValue, isOAuthProvider } from "./types.js";
import { refreshAccessToken } from "./oauth/token-refresh.js";
import { TOKEN_REFRESH_BUFFER_MS, REFRESH_INTERVAL_MS } from "./constants.js";

export type VaultServiceDeps = {
  store: CredentialStore;
  config: VaultPluginConfig;
  log?: (msg: string) => void;
};

/**
 * Background service that handles:
 * 1. Proactive token refresh for expiring OAuth credentials
 * 2. Cleanup of expired pending OAuth states
 */
export function createVaultService(deps: VaultServiceDeps) {
  const { store, config, log = console.log } = deps;
  let intervalHandle: ReturnType<typeof setInterval> | null = null;

  async function tick(): Promise<void> {
    // 1. Refresh expiring tokens
    try {
      const expiring = store.getExpiringCredentials(TOKEN_REFRESH_BUFFER_MS);
      for (const cred of expiring) {
        const providerConfig = config.providers[cred.provider];
        if (!providerConfig || !isOAuthProvider(providerConfig)) continue;

        const oauthConfig = providerConfig as OAuthProviderConfig;
        if (!oauthConfig.tokenUrl) continue;

        let decrypted;
        try {
          decrypted = store.getDecryptedCredential(
            cred.agent_id,
            cred.channel_user_id,
            cred.provider,
          );
        } catch {
          continue;
        }

        if (!decrypted) continue;

        const payload = decrypted.payload;
        if (!("refresh_token" in payload) || !payload.refresh_token) continue;

        try {
          const newTokens = await refreshAccessToken({
            tokenUrl: oauthConfig.tokenUrl,
            clientId: resolveConfigValue(oauthConfig.clientId),
            clientSecret: resolveConfigValue(oauthConfig.clientSecret),
            refreshToken: payload.refresh_token,
          });

          store.updateCredentialTokens(
            cred.id,
            {
              access_token: newTokens.access_token,
              refresh_token: newTokens.refresh_token ?? payload.refresh_token,
              token_type: newTokens.token_type,
            },
            newTokens.expires_in
              ? Date.now() + newTokens.expires_in * 1000
              : undefined,
          );

          store.logAudit({
            agentId: cred.agent_id,
            channelUserId: cred.channel_user_id,
            provider: cred.provider,
            action: "refresh",
          });

          log(`[credential-vault] Refreshed token for ${cred.provider} (user: ${cred.channel_user_id})`);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          log(`[credential-vault] Failed to refresh ${cred.provider} for ${cred.channel_user_id}: ${msg}`);

          // If refresh fails with invalid_grant, the refresh token is revoked
          if (msg.includes("invalid_grant")) {
            store.deleteCredential(
              cred.agent_id,
              cred.channel_user_id,
              cred.provider,
            );
            store.logAudit({
              agentId: cred.agent_id,
              channelUserId: cred.channel_user_id,
              provider: cred.provider,
              action: "revoke",
              metadata: JSON.stringify({ reason: "refresh_failed_invalid_grant" }),
            });
            log(`[credential-vault] Revoked ${cred.provider} for ${cred.channel_user_id} (invalid_grant)`);
          }
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`[credential-vault] Error during token refresh cycle: ${msg}`);
    }

    // 2. Clean up expired pending states
    try {
      store.cleanupExpiredStates();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`[credential-vault] Error cleaning expired states: ${msg}`);
    }
  }

  return {
    id: "credential-vault-refresh",

    start(_ctx?: any): void {
      // Run immediately on start
      tick();
      intervalHandle = setInterval(tick, REFRESH_INTERVAL_MS);
    },

    stop(_ctx?: any): void {
      if (intervalHandle) {
        clearInterval(intervalHandle);
        intervalHandle = null;
      }
    },
  };
}
