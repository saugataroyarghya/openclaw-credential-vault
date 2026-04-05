/**
 * openclaw-credential-vault
 *
 * Pure auth middleware plugin for OpenClaw.
 *
 * Registers ONE tool: vault_fetch
 *   - AI sends a curl command + provider name
 *   - Vault looks up the user's credential (per-user, per-agent)
 *   - Vault injects the auth header and executes the curl
 *   - Returns only the API response — AI never sees the token
 *
 * Also provides:
 *   - before_tool_call hook: blocks exec calls that try to use vault-managed env vars
 *   - after_tool_call hook: detects 401/403 → auto-revokes credential
 *   - Channel policies: restrict which providers/tools work in which channels
 *   - /connect, /disconnect, /connections commands
 *   - OAuth + API key web form flows
 *   - Background token refresh
 */

import { join, dirname } from "node:path";
import { execSync } from "node:child_process";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { Type } from "@sinclair/typebox";
import dotenv from "dotenv";

// Load .env from the plugin's own directory
const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, ".env") });

import { CredentialStore } from "./src/store/credential-store.js";
import { createCallbackHandler } from "./src/oauth/callback-handler.js";
import { createApiKeyFormHandler, APIKEY_FORM_PATH } from "./src/api-key/web-form.js";
import { parseSessionKey } from "./src/gate/hook.js";
import { checkChannelPolicy } from "./src/gate/channel-policy.js";
import {
  handleConnect,
  handleDisconnect,
  handleConnections,
} from "./src/commands/index.js";
import { createVaultService } from "./src/service.js";
import type { VaultPluginConfig } from "./src/types.js";
import { CALLBACK_PATH, DEFAULT_RATE_LIMIT } from "./src/constants.js";

// ── Resolve state directory ──

function getStateDir(): string {
  return process.env.OPENCLAW_HOME || process.env.MOLTBOT_HOME || join(homedir(), ".openclaw");
}

// ── Rate limiting (in-memory) ──

const rateCounts = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string, limit: number): boolean {
  const now = Date.now();
  const entry = rateCounts.get(key);
  if (!entry || now > entry.resetAt) {
    rateCounts.set(key, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

// ── Plugin Entry ──

const plugin = {
  id: "credential-vault",
  name: "Credential Vault",
  description:
    "Auth middleware — vault_fetch tool, per-user OAuth/API keys, credential gating.",

  register(api: any) {
    const config = (api.pluginConfig ?? {}) as VaultPluginConfig;
    const log = api.logger?.info?.bind(api.logger) ?? console.log;

    // 1. Initialize encrypted credential store
    const stateDir = getStateDir();
    const dbPath = join(stateDir, "credential-vault", "vault.db");
    const store = new CredentialStore({ dbPath });

    log("[credential-vault] Initialized credential store");

    // 2. HTTP routes for OAuth callback and API key web form
    api.registerHttpRoute({
      path: CALLBACK_PATH,
      handler: createCallbackHandler({ store, config }),
      auth: "plugin",
    });

    api.registerHttpRoute({
      path: APIKEY_FORM_PATH,
      handler: createApiKeyFormHandler({ store, config }),
      auth: "plugin",
    });

    // 3. vault_fetch — the one tool this plugin registers
    //
    //    ctx.requesterSenderId is "trusted sender id from inbound context
    //    (runtime-provided, not tool args)" — set by OpenClaw from the chat
    //    platform's authenticated payload. Bound to this specific tool call.
    //    The AI cannot influence it.
    //
    api.registerTool(
      (ctx: any) => ({
        name: "vault_fetch",
        description:
          "Make an authenticated HTTP request. Provide a curl command (WITHOUT auth headers) " +
          "and the provider name. The vault injects your stored credential automatically. " +
          "If not connected, returns instructions to connect.",
        parameters: Type.Object({
          command: Type.String({
            description:
              "The curl command to execute, WITHOUT any auth headers. " +
              "Example: curl -X GET \"https://api.github.com/user/repos\"",
          }),
          provider: Type.String({
            description:
              "Which credential to use. Must match a configured provider " +
              "(e.g. github, google, notion, metabase).",
          }),
        }),
        async execute(_id: string, params: any) {
          const rawUserId = ctx.requesterSenderId;
          if (!rawUserId) {
            return { content: [{ type: "text", text: "Cannot identify user. No sender context available." }] };
          }

          // Scope user ID by channel to prevent cross-channel impersonation
          const channel = ctx.messageChannel ?? "unknown";
          const userId = `${channel}:${rawUserId}`;
          const agentId = ctx.agentId ?? "";
          const provider = params.provider;

          // Rate limit check
          const rateLimit = config.rateLimitPerUserPerMinute ?? DEFAULT_RATE_LIMIT;
          const rateKey = `${agentId}:${userId}:${provider}`;
          if (!checkRateLimit(rateKey, rateLimit)) {
            return {
              content: [{ type: "text", text: `Rate limit exceeded for ${provider}. Please wait a moment.` }],
            };
          }

          // Channel policy check
          if (config.channelPolicies) {
            const identity = parseSessionKey(ctx.sessionKey ?? "");
            if (identity) {
              const policyResult = checkChannelPolicy({
                toolName: `vault_fetch`,
                provider,
                identity,
                config,
              });
              if (!policyResult.allowed) {
                return { content: [{ type: "text", text: policyResult.reason }] };
              }
            }
          }

          // Look up credential
          const cred = store.getDecryptedCredential(agentId, userId, provider);
          if (!cred) {
            store.logAudit({
              agentId,
              channelUserId: userId,
              provider,
              action: "gate_block",
              toolName: "vault_fetch",
              metadata: JSON.stringify({ reason: "no_credential" }),
            });
            return {
              content: [{
                type: "text",
                text: `Not connected to ${provider}. Use /connect ${provider} to authenticate.`,
              }],
            };
          }

          // Extract token
          const token =
            "access_token" in cred.payload
              ? cred.payload.access_token
              : "api_key" in cred.payload
                ? cred.payload.api_key
                : null;

          if (!token) {
            return { content: [{ type: "text", text: `Invalid credential for ${provider}.` }] };
          }

          // Build auth header from provider config
          const providerConfig = config.providers[provider];
          const headerName = providerConfig?.headerName ?? "Authorization";
          const headerPrefix = providerConfig?.headerPrefix ?? (providerConfig?.type === "api_key" ? "" : "Bearer");
          const authValue = headerPrefix ? `${headerPrefix} ${token}` : token;
          const authFlag = `-H "${headerName}: ${authValue}"`;

          // Append auth to curl command and execute
          const fullCommand = `${params.command} ${authFlag}`;

          try {
            const result = execSync(fullCommand, {
              encoding: "utf-8",
              timeout: 30_000,
              maxBuffer: 5 * 1024 * 1024,
            });

            store.logAudit({
              agentId,
              channelUserId: userId,
              provider,
              action: "inject",
              toolName: "vault_fetch",
            });

            return { content: [{ type: "text", text: result }] };
          } catch (err: any) {
            const stderr = err.stderr ?? err.message ?? "Command failed";

            // Detect auth failure → auto-revoke
            const combined = `${err.stdout ?? ""} ${stderr}`.toLowerCase();
            if (
              combined.includes("401") ||
              combined.includes("unauthorized") ||
              combined.includes("bad credentials")
            ) {
              store.deleteCredential(agentId, userId, provider);
              store.logAudit({
                agentId,
                channelUserId: userId,
                provider,
                action: "revoke",
                toolName: "vault_fetch",
                metadata: JSON.stringify({ reason: "auth_failure_detected" }),
              });
              return {
                content: [{
                  type: "text",
                  text: `Authentication failed for ${provider}. Your credential has been removed. Use /connect ${provider} to reconnect.`,
                }],
              };
            }

            return { content: [{ type: "text", text: `Error: ${stderr}` }] };
          }
        },
      }),
      { name: "vault_fetch" },
    );

    // 4. before_tool_call — block exec calls that try to use vault-managed env vars
    //
    //    If the AI tries to bypass vault_fetch by calling exec with $NOTION_KEY
    //    or $GITHUB_TOKEN directly, block it.
    //
    api.on("before_tool_call", (event: any, _ctx: any) => {
      const toolName = event.toolName ?? _ctx.toolName;

      // Only intercept exec/process tool calls
      if (toolName !== "exec" && toolName !== "process") return undefined;

      const command = event.params?.command ?? event.params?.cmd ?? "";
      if (typeof command !== "string") return undefined;

      // Check if the command references any vault-managed provider env vars
      for (const providerName of Object.keys(config.providers)) {
        // Check common env var patterns for this provider
        const patterns = [
          `$${providerName.toUpperCase()}_KEY`,
          `$${providerName.toUpperCase()}_TOKEN`,
          `$${providerName.toUpperCase()}_API_KEY`,
          `$${providerName.toUpperCase()}_SECRET`,
          `\${${providerName.toUpperCase()}_KEY}`,
          `\${${providerName.toUpperCase()}_TOKEN}`,
          `\${${providerName.toUpperCase()}_API_KEY}`,
        ];

        for (const pattern of patterns) {
          if (command.includes(pattern)) {
            return {
              block: true,
              blockReason:
                `For security, use vault_fetch instead of exec for authenticated ${providerName} requests. ` +
                `Example: vault_fetch({ command: "curl ...", provider: "${providerName}" })`,
            };
          }
        }
      }

      return undefined;
    });

    // 5. User commands
    //    senderId is scoped by channel to match vault_fetch lookup
    const scopeSenderId = (ctx: any) => {
      const channel = ctx.channel ?? ctx.channelId ?? "unknown";
      const sender = ctx.senderId ?? ctx.from ?? "";
      return `${channel}:${sender}`;
    };

    api.registerCommand({
      name: "connect",
      description: "Connect an external service (OAuth or API key)",
      acceptsArgs: true,
      requireAuth: false,
      handler: (ctx: any) =>
        handleConnect(
          {
            args: ctx.args ?? ctx.commandBody ?? "",
            agentId: ctx.accountId ?? "",
            senderId: scopeSenderId(ctx),
            channelId: ctx.channel ?? ctx.channelId ?? "",
          },
          { store, config },
        ),
    });

    api.registerCommand({
      name: "disconnect",
      description: "Disconnect an external service",
      acceptsArgs: true,
      requireAuth: false,
      handler: (ctx: any) =>
        handleDisconnect(
          {
            args: ctx.args ?? ctx.commandBody ?? "",
            agentId: ctx.accountId ?? "",
            senderId: scopeSenderId(ctx),
            channelId: ctx.channel ?? ctx.channelId ?? "",
          },
          { store, config },
        ),
    });

    api.registerCommand({
      name: "connections",
      description: "List your connected services",
      acceptsArgs: false,
      requireAuth: false,
      handler: (ctx: any) =>
        handleConnections(
          {
            args: ctx.args ?? "",
            agentId: ctx.accountId ?? "",
            senderId: scopeSenderId(ctx),
            channelId: ctx.channel ?? ctx.channelId ?? "",
          },
          { store, config },
        ),
    });

    // 6. Background token refresh service
    api.registerService(createVaultService({ store, config, log }));

    log("[credential-vault] Plugin registered successfully");
  },
};

export default plugin;
