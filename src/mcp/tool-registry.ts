import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { McpServerConfig } from "../types.js";

export type DiscoveredTool = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  serverName: string;
  prefixedName: string;
};

export async function discoverMcpTools(
  serverName: string,
  serverConfig: McpServerConfig,
): Promise<DiscoveredTool[]> {
  const client = new Client({
    name: "openclaw-credential-vault",
    version: "0.1.0",
  });

  try {
    const transport = new StreamableHTTPClientTransport(
      new URL(serverConfig.url),
    );

    await client.connect(transport);

    const { tools } = await client.listTools();
    const prefix = serverConfig.toolPrefix ?? serverName;

    return tools.map((tool) => ({
      name: tool.name,
      description: tool.description ?? "",
      inputSchema: (tool.inputSchema ?? {}) as Record<string, unknown>,
      serverName,
      prefixedName: `${prefix}_${tool.name}`,
    }));
  } catch (error) {
    console.error(
      `[credential-vault] Failed to discover tools from MCP server "${serverName}":`,
      error,
    );
    return [];
  } finally {
    try {
      await client.close();
    } catch {
      // Ignore close errors
    }
  }
}
