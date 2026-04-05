/**
 * openclaw-credential-vault
 *
 * Generic per-user credential vault plugin for OpenClaw.
 * Provides OAuth, API key management, MCP server bridge, and auth gating.
 */

import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

// Load .env from the plugin's own directory
const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, ".env") });
import { CredentialStore } from "./src/store/credential-store.js";
import { createCallbackHandler } from "./src/oauth/callback-handler.js";
import { createApiKeyFormHandler, APIKEY_FORM_PATH } from "./src/api-key/web-form.js";
import { checkGate, parseSessionKey } from "./src/gate/hook.js";
import { resolveToolProviders } from "./src/gate/resolution.js";
import {
  handleConnect,
  handleDisconnect,
  handleConnections,
} from "./src/commands/index.js";
import { discoverMcpTools } from "./src/mcp/tool-registry.js";
import {
  callMcpToolAuthenticated,
  callMcpToolUnauthenticated,
} from "./src/mcp/bridge.js";
import { createVaultService } from "./src/service.js";
import { registerGithubTools } from "./src/tools/github.js";
import { registerGoogleTools } from "./src/tools/google.js";
import { registerMetabaseTools } from "./src/tools/metabase.js";
import type { VaultPluginConfig } from "./src/types.js";
import { CALLBACK_PATH } from "./src/constants.js";

// ── Resolve state directory (same logic OpenClaw uses internally) ──

function getStateDir(): string {
  const envDir = process.env.OPENCLAW_HOME || process.env.MOLTBOT_HOME;
  if (envDir) return envDir;
  return join(homedir(), ".openclaw");
}

// ── Plugin Entry (synchronous register — OpenClaw does not await async register) ──

const plugin = {
  id: "credential-vault",
  name: "Credential Vault",
  description:
    "Per-user credential vault with OAuth, API key, MCP bridge, and auth gating.",

  register(api: any) {
    const config = (api.pluginConfig ?? {}) as VaultPluginConfig;
    const log = api.logger?.info?.bind(api.logger) ?? console.log;
    const logError = api.logger?.error?.bind(api.logger) ?? console.error;

    // 1. Initialize encrypted credential store
    const stateDir = getStateDir();
    const dbPath = join(stateDir, "credential-vault", "vault.db");
    const store = new CredentialStore({ dbPath });

    log("[credential-vault] Initialized credential store");

    // 2. Register HTTP routes (auth: "plugin" — we handle our own state-token validation)
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

    // 3. Register gate hook (before_tool_call)
    api.on("before_tool_call", (event: any, ctx: any) => {
      const identity = parseSessionKey(ctx.sessionKey ?? "");
      if (!identity) return undefined;

      const result = checkGate({
        toolName: event.toolName ?? ctx.toolName,
        identity,
        agentId: ctx.agentId ?? "",
        store,
        config,
      });

      if (result.blocked) {
        return { block: true, blockReason: result.message };
      }
      return undefined;
    });

    // 4. Register revocation detection (after_tool_call)
    api.on("after_tool_call", (event: any, ctx: any) => {
      const resultStr =
        typeof event.result === "string"
          ? event.result
          : JSON.stringify(event.result ?? "");
      const errorStr = event.error ?? "";
      const combined = `${resultStr} ${errorStr}`.toLowerCase();

      if (
        combined.includes("401") ||
        combined.includes("unauthorized") ||
        combined.includes("token is invalid") ||
        combined.includes("bad credentials")
      ) {
        const identity = parseSessionKey(ctx.sessionKey ?? "");
        if (!identity) return;

        const toolName = event.toolName ?? ctx.toolName;
        const providers = resolveToolProviders(toolName, config);
        for (const provider of providers) {
          store.deleteCredential(ctx.agentId ?? "", identity.userId, provider);
          store.logAudit({
            agentId: ctx.agentId ?? "",
            channelUserId: identity.userId,
            provider,
            action: "revoke",
            toolName,
            metadata: JSON.stringify({ reason: "detected_auth_failure" }),
          });
          log(
            `[credential-vault] Revoked ${provider} for ${identity.userId} (auth failure detected)`,
          );
        }
      }
    });

    // 5. Register user commands
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
            senderId: ctx.senderId ?? ctx.from ?? "",
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
            senderId: ctx.senderId ?? ctx.from ?? "",
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
            senderId: ctx.senderId ?? ctx.from ?? "",
            channelId: ctx.channel ?? ctx.channelId ?? "",
          },
          { store, config },
        ),
    });

    // 6. Register native tools (GitHub, Google, Metabase)
    registerGithubTools(api, store);
    registerGoogleTools(api, store);
    registerMetabaseTools(api, store);

    // 7. MCP discovery deferred to service start (async not allowed in register)
    const mcpServers = config.mcpServers ?? {};
    if (Object.keys(mcpServers).length > 0) {
      api.registerService({
        id: "credential-vault-mcp-discovery",
        start: async () => {
          for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
            try {
              const tools = await discoverMcpTools(serverName, serverConfig);
              log(
                `[credential-vault] Discovered ${tools.length} tools from MCP server "${serverName}"`,
              );

              for (const tool of tools) {
                api.registerTool(
                  (ctx: any) => ({
                    name: tool.prefixedName,
                    description: tool.description,
                    parameters: tool.inputSchema,
                    execute: async (
                      _id: string,
                      params: Record<string, unknown>,
                    ): Promise<string> => {
                      const authConfig = serverConfig.auth;
                      if (!authConfig) {
                        return callMcpToolUnauthenticated({
                          serverUrl: serverConfig.url,
                          toolName: tool.name,
                          toolInput: params,
                        });
                      }

                      const identity = parseSessionKey(ctx.sessionKey ?? "");
                      if (!identity) {
                        throw new Error(
                          "Cannot identify user for credential lookup.",
                        );
                      }

                      const decrypted = store.getDecryptedCredential(
                        ctx.agentId ?? "",
                        identity.userId,
                        authConfig.provider,
                      );

                      if (!decrypted) {
                        throw new Error(
                          `Not authenticated with ${authConfig.provider}. Use /connect ${authConfig.provider}`,
                        );
                      }

                      const credential =
                        "access_token" in decrypted.payload
                          ? decrypted.payload.access_token
                          : "api_key" in decrypted.payload
                            ? decrypted.payload.api_key
                            : "";

                      return callMcpToolAuthenticated({
                        serverUrl: serverConfig.url,
                        toolName: tool.name,
                        toolInput: params,
                        credential,
                        authConfig,
                      });
                    },
                  }),
                  { name: tool.prefixedName },
                );
              }
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              logError(
                `[credential-vault] Failed to initialize MCP server "${serverName}": ${msg}`,
              );
            }
          }
        },
      });
    }

    // 8. Register background token refresh service
    api.registerService(createVaultService({ store, config, log }));

    log("[credential-vault] Plugin registered successfully");
  },
};

export default plugin;
