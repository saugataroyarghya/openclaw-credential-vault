import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { injectCredential } from "../injection/strategies.js";
import type { McpAuthConfig } from "../types.js";

export async function callMcpToolAuthenticated(params: {
  serverUrl: string;
  toolName: string;
  toolInput: Record<string, unknown>;
  credential: string;
  authConfig: McpAuthConfig;
}): Promise<string> {
  const { serverUrl, toolName, toolInput, credential, authConfig } = params;

  const injected = injectCredential({
    headers: {},
    url: serverUrl,
    credential,
    injection: {
      strategy: authConfig.inject ?? "bearer",
      headerName: authConfig.headerName,
      headerPrefix: authConfig.headerPrefix,
    },
  });

  const client = new Client({
    name: "openclaw-credential-vault",
    version: "0.1.0",
  });

  try {
    const transport = new StreamableHTTPClientTransport(
      new URL(injected.url),
      {
        requestInit: {
          headers: injected.headers,
        },
      },
    );

    await client.connect(transport);

    const result = await client.callTool({
      name: toolName,
      arguments: toolInput,
    });

    const textParts: string[] = [];
    if (Array.isArray(result.content)) {
      for (const block of result.content) {
        if (
          typeof block === "object" &&
          block !== null &&
          "type" in block &&
          block.type === "text" &&
          "text" in block &&
          typeof block.text === "string"
        ) {
          textParts.push(block.text);
        }
      }
    }

    return textParts.length > 0
      ? textParts.join("\n")
      : "Tool returned no content.";
  } finally {
    try {
      await client.close();
    } catch {
      // Ignore close errors
    }
  }
}

export async function callMcpToolUnauthenticated(params: {
  serverUrl: string;
  toolName: string;
  toolInput: Record<string, unknown>;
}): Promise<string> {
  const { serverUrl, toolName, toolInput } = params;

  const client = new Client({
    name: "openclaw-credential-vault",
    version: "0.1.0",
  });

  try {
    const transport = new StreamableHTTPClientTransport(
      new URL(serverUrl),
    );

    await client.connect(transport);

    const result = await client.callTool({
      name: toolName,
      arguments: toolInput,
    });

    const textParts: string[] = [];
    if (Array.isArray(result.content)) {
      for (const block of result.content) {
        if (
          typeof block === "object" &&
          block !== null &&
          "type" in block &&
          block.type === "text" &&
          "text" in block &&
          typeof block.text === "string"
        ) {
          textParts.push(block.text);
        }
      }
    }

    return textParts.length > 0
      ? textParts.join("\n")
      : "Tool returned no content.";
  } finally {
    try {
      await client.close();
    } catch {
      // Ignore close errors
    }
  }
}
