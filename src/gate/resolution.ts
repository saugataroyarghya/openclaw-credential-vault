import type { VaultPluginConfig } from "../types.js";

export function resolveToolProviders(
  toolName: string,
  config: VaultPluginConfig,
): string[] {
  const { toolProviderMap } = config;

  if (!toolProviderMap) return [];

  // 1. Direct match
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

  return [];
}
