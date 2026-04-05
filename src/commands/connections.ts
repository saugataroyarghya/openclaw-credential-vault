import type { CredentialStore } from "../store/credential-store.js";
import type { VaultPluginConfig } from "../types.js";
import type { CommandContext, CommandResult } from "./types.js";

export function handleConnections(
  ctx: CommandContext,
  deps: { store: CredentialStore; config: VaultPluginConfig },
): CommandResult {
  const { store } = deps;
  const rows = store.listCredentials(ctx.agentId, ctx.senderId);

  if (rows.length === 0) {
    return { text: "No connected services." };
  }

  const lines = rows.map((row) => {
    const parts: string[] = [
      `provider: ${row.provider}`,
      `type: ${row.auth_type}`,
    ];

    if (row.scopes) {
      parts.push(`scopes: ${row.scopes}`);
    }

    parts.push(`connected_at: ${new Date(row.created_at).toISOString()}`);

    if (row.expires_at) {
      parts.push(`expires_at: ${new Date(row.expires_at).toISOString()}`);
    }

    return parts.join(" | ");
  });

  return { text: lines.join("\n") };
}
