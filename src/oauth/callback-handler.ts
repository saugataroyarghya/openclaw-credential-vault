import type { IncomingMessage, ServerResponse } from "node:http";
import type { CredentialStore } from "../store/credential-store.js";
import type { VaultPluginConfig, OAuthProviderConfig } from "../types.js";
import { resolveConfigValue } from "../types.js";
import { exchangeCodeForTokens } from "./flow.js";

const SUCCESS_HTML = `<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; text-align: center; padding-top: 80px; background: #fafafa;">
  <div style="max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h1 style="color: #22c55e;">Connected!</h1>
    <p style="color: #555;">Your account is now linked. You can close this tab and return to your chat.</p>
  </div>
</body>
</html>`;

const ERROR_HTML = (msg: string) => `<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; text-align: center; padding-top: 80px; background: #fafafa;">
  <div style="max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h1 style="color: #ef4444;">Error</h1>
    <p style="color: #555;">${escapeHtml(msg)}</p>
  </div>
</body>
</html>`;

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export type CallbackHandlerDeps = {
  store: CredentialStore;
  config: VaultPluginConfig;
};

export function createCallbackHandler(deps: CallbackHandlerDeps) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end(ERROR_HTML("Missing code or state parameter."));
      return;
    }

    // 1. Validate and consume pending state
    const pending = deps.store.consumePendingState(state);
    if (!pending) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end(ERROR_HTML("Invalid or expired link. Go back to your chat and try again."));
      return;
    }

    // 2. Resolve provider config
    const providerConfig = deps.config.providers[pending.provider];
    if (!providerConfig || providerConfig.type !== "oauth2") {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end(ERROR_HTML(`Unknown OAuth provider: ${pending.provider}`));
      return;
    }

    const oauthConfig = providerConfig as OAuthProviderConfig;

    // 3. Build callback URL
    const callbackUrl = deps.config.callbackBaseUrl
      ? `${deps.config.callbackBaseUrl}/credential-vault/oauth/callback`
      : `${url.protocol}//${url.host}/credential-vault/oauth/callback`;

    // 4. Exchange code for tokens
    let tokens;
    try {
      tokens = await exchangeCodeForTokens({
        provider: oauthConfig,
        code,
        callbackUrl,
        codeVerifier: pending.pkce_verifier ?? undefined,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Token exchange failed.";
      res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
      res.end(ERROR_HTML(msg));
      return;
    }

    // 5. Encrypt and store credentials
    deps.store.saveCredential({
      agentId: pending.agent_id,
      channelUserId: pending.channel_user_id,
      channelId: pending.channel_id,
      provider: pending.provider,
      authType: "oauth2",
      payload: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
      },
      scopes: tokens.scope,
      expiresAt: tokens.expires_in
        ? Date.now() + tokens.expires_in * 1000
        : undefined,
    });

    // 6. Audit log
    deps.store.logAudit({
      agentId: pending.agent_id,
      channelUserId: pending.channel_user_id,
      provider: pending.provider,
      action: "connect",
      metadata: JSON.stringify({
        scopes: tokens.scope,
        channelId: pending.channel_id,
      }),
    });

    // 7. Success response
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(SUCCESS_HTML);
  };
}
