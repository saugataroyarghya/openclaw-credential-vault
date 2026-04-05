import type { IncomingMessage, ServerResponse } from "node:http";
import type { CredentialStore } from "../store/credential-store.js";
import type { VaultPluginConfig } from "../types.js";

export const APIKEY_FORM_PATH = "/credential-vault/apikey";

// ── HTML Templates ──

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const PAGE_STYLE =
  'font-family: system-ui, sans-serif; text-align: center; padding-top: 80px; background: #fafafa;';

const CARD_STYLE =
  'max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);';

const SUCCESS_HTML = `<!DOCTYPE html>
<html>
<body style="${PAGE_STYLE}">
  <div style="${CARD_STYLE}">
    <h1 style="color: #22c55e;">Connected!</h1>
    <p style="color: #555;">Your API key has been saved securely. You can close this tab and return to your chat.</p>
  </div>
</body>
</html>`;

const ERROR_HTML = (msg: string) => `<!DOCTYPE html>
<html>
<body style="${PAGE_STYLE}">
  <div style="${CARD_STYLE}">
    <h1 style="color: #ef4444;">Error</h1>
    <p style="color: #555;">${escapeHtml(msg)}</p>
  </div>
</body>
</html>`;

const FORM_HTML = (provider: string, stateToken: string) => `<!DOCTYPE html>
<html>
<body style="${PAGE_STYLE}">
  <div style="${CARD_STYLE}">
    <h1 style="color: #333;">Connect ${escapeHtml(provider)}</h1>
    <p style="color: #555; margin-bottom: 24px;">Enter your API key below. It will be encrypted and stored securely.</p>
    <form method="POST" action="${APIKEY_FORM_PATH}" style="text-align: left;">
      <input type="hidden" name="state" value="${escapeHtml(stateToken)}" />
      <label for="api_key" style="display: block; margin-bottom: 8px; font-weight: 500; color: #333;">API Key</label>
      <input
        type="password"
        id="api_key"
        name="api_key"
        required
        autocomplete="off"
        style="width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; box-sizing: border-box;"
        placeholder="Paste your API key here"
      />
      <button
        type="submit"
        style="margin-top: 16px; width: 100%; padding: 10px; background: #2563eb; color: white; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 500;"
      >
        Save Key
      </button>
    </form>
  </div>
</body>
</html>`;

// ── Request Body Parsing ──

function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 64 * 1024; // 64 KB limit

    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        reject(new Error("Request body too large."));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

// ── Handler ──

export function createApiKeyFormHandler(deps: {
  store: CredentialStore;
  config: VaultPluginConfig;
}): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);

    if (req.method === "GET") {
      await handleGet(url, deps, res);
      return;
    }

    if (req.method === "POST") {
      await handlePost(req, deps, res);
      return;
    }

    res.writeHead(405, { "Content-Type": "text/html; charset=utf-8" });
    res.end(ERROR_HTML("Method not allowed."));
  };
}

// ── GET: Render form ──

async function handleGet(
  url: URL,
  deps: { store: CredentialStore; config: VaultPluginConfig },
  res: ServerResponse,
): Promise<void> {
  const stateToken = url.searchParams.get("state");

  if (!stateToken) {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(ERROR_HTML("Missing state parameter."));
    return;
  }

  const pending = deps.store.getPendingState(stateToken);
  if (!pending) {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(
      ERROR_HTML("Invalid or expired link. Go back to your chat and try again."),
    );
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(FORM_HTML(pending.provider, stateToken));
}

// ── POST: Process form submission ──

async function handlePost(
  req: IncomingMessage,
  deps: { store: CredentialStore; config: VaultPluginConfig },
  res: ServerResponse,
): Promise<void> {
  let body: string;
  try {
    body = await readRequestBody(req);
  } catch {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(ERROR_HTML("Could not read request body."));
    return;
  }

  const params = new URLSearchParams(body);
  const stateToken = params.get("state");
  const apiKey = params.get("api_key");

  if (!stateToken || !apiKey) {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(ERROR_HTML("Missing state or API key."));
    return;
  }

  // Consume the pending state (validates + deletes in one step)
  const pending = deps.store.consumePendingState(stateToken);
  if (!pending) {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(
      ERROR_HTML("Invalid or expired link. Go back to your chat and try again."),
    );
    return;
  }

  // Verify the provider is an api_key type
  const providerConfig = deps.config.providers[pending.provider];
  if (!providerConfig || providerConfig.type !== "api_key") {
    res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
    res.end(ERROR_HTML(`Provider "${pending.provider}" is not an API key provider.`));
    return;
  }

  // Encrypt and store the API key
  deps.store.saveCredential({
    agentId: pending.agent_id,
    channelUserId: pending.channel_user_id,
    channelId: pending.channel_id,
    provider: pending.provider,
    authType: "api_key",
    payload: { api_key: apiKey },
  });

  // Audit log
  deps.store.logAudit({
    agentId: pending.agent_id,
    channelUserId: pending.channel_user_id,
    provider: pending.provider,
    action: "connect",
    metadata: JSON.stringify({ method: "web_form", channelId: pending.channel_id }),
  });

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(SUCCESS_HTML);
}
