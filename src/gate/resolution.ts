import type { VaultPluginConfig } from "../types.js";

export function resolveToolProviders(
  toolName: string,
  config: VaultPluginConfig,
): string[] {
  const { toolProviderMap, mcpServers } = config;

  // 1. Direct match in toolProviderMap
  if (toolProviderMap) {
    const direct = toolProviderMap[toolName];
    if (direct !== undefined) {
      return Array.isArray(direct) ? direct : [direct];
    }

    // 2. Wildcard match (keys ending with *)
    for (const key of Object.keys(toolProviderMap)) {
      if (key.endsWith("*")) {
        const prefix = key.slice(0, -1);
        if (toolName.startsWith(prefix)) {
          const value = toolProviderMap[key];
          return Array.isArray(value) ? value : [value];
        }
      }
    }
  }

  // 3. MCP server prefix match
  if (mcpServers) {
    for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
      const prefix = (serverConfig.toolPrefix ?? serverName) + "_";
      if (toolName.startsWith(prefix) && serverConfig.auth?.provider) {
        return [serverConfig.auth.provider];
      }
    }
  }

  // 4. No match
  return [];
}
