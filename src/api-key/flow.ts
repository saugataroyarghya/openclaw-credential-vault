import type { VaultPluginConfig } from "../types.js";

/**
 * Build a prompt message for API key collection.
 * Returned to the user when they run `/connect <provider>` without a key.
 */
export function buildApiKeyPromptMessage(
  provider: string,
  config: VaultPluginConfig,
): string {
  const providerConfig = config.providers[provider];
  if (!providerConfig || providerConfig.type !== "api_key") {
    return `Unknown API key provider: ${provider}`;
  }

  return (
    `To connect *${provider}*, send your API key:\n` +
    `\`/connect ${provider} <your-api-key>\`\n\n` +
    `Your key will be encrypted and stored securely. ` +
    `The AI agent will never see the raw key.`
  );
}
