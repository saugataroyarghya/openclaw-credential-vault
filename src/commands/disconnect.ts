import type { CredentialStore } from "../store/credential-store.js";
import type { VaultPluginConfig } from "../types.js";
import type { CommandContext, CommandResult } from "./types.js";

export function handleDisconnect(
  ctx: CommandContext,
  deps: { store: CredentialStore; config: VaultPluginConfig },
): CommandResult {
  const { store, config } = deps;
  const providerName = ctx.args.trim().split(/\s+/)[0];

  if (!providerName) {
    return { text: "Usage: disconnect <provider>" };
  }

  if (!config.providers[providerName]) {
    const available = Object.keys(config.providers).join(", ");
    return {
      text: `Unknown provider "${providerName}". Available providers: ${available}`,
    };
  }

  store.deleteCredential(ctx.agentId, ctx.senderId, providerName);

  store.logAudit({
    agentId: ctx.agentId,
    channelUserId: ctx.senderId,
    provider: providerName,
    action: "disconnect",
  });

  return { text: `Disconnected from ${providerName}.` };
}
