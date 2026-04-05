import type { CredentialStore } from "../store/credential-store.js";
import type { ApiKeyCredentialPayload } from "../types.js";
import { parseSessionKey } from "../gate/hook.js";

const METABASE_URL = process.env.METABASE_URL ?? "http://localhost:3000";

async function resolveApiKey(
  ctx: any,
  store: CredentialStore,
): Promise<string> {
  const identity = parseSessionKey(ctx.sessionKey);
  if (!identity) throw new Error("Invalid session key");

  const cred = store.getDecryptedCredential(
    ctx.agentId,
    identity.userId,
    "metabase",
  );
  if (!cred) {
    throw new Error("Not authenticated with Metabase. Use /connect metabase");
  }

  return (cred.payload as ApiKeyCredentialPayload).api_key;
}

export function registerMetabaseTools(api: any, store: CredentialStore): void {
  api.registerTool(
    (ctx: any) => ({
      name: "metabase_list_dashboards",
      description: "List all Metabase dashboards the user has access to.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const apiKey = await resolveApiKey(ctx, store);
        const resp = await fetch(`${METABASE_URL}/api/dashboard`, {
          headers: { "X-Metabase-Session": apiKey },
        });
        return resp.text();
      },
    }),
    { name: "metabase_list_dashboards" },
  );

  api.registerTool(
    (ctx: any) => ({
      name: "metabase_get_dashboard",
      description:
        "Get a specific Metabase dashboard by ID, including its cards and layout.",
      parameters: {
        type: "object",
        properties: { id: { type: "number", description: "Dashboard ID" } },
        required: ["id"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const apiKey = await resolveApiKey(ctx, store);
        const resp = await fetch(
          `${METABASE_URL}/api/dashboard/${params.id}`,
          { headers: { "X-Metabase-Session": apiKey } },
        );
        return resp.text();
      },
    }),
    { name: "metabase_get_dashboard" },
  );

  api.registerTool(
    (ctx: any) => ({
      name: "metabase_list_questions",
      description: "List all saved Metabase questions (cards).",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const apiKey = await resolveApiKey(ctx, store);
        const resp = await fetch(`${METABASE_URL}/api/card`, {
          headers: { "X-Metabase-Session": apiKey },
        });
        return resp.text();
      },
    }),
    { name: "metabase_list_questions" },
  );

  api.registerTool(
    (ctx: any) => ({
      name: "metabase_run_question",
      description: "Execute a saved Metabase question and return the results.",
      parameters: {
        type: "object",
        properties: { id: { type: "number", description: "Question (card) ID" } },
        required: ["id"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const apiKey = await resolveApiKey(ctx, store);
        const resp = await fetch(
          `${METABASE_URL}/api/card/${params.id}/query`,
          {
            method: "POST",
            headers: { "X-Metabase-Session": apiKey },
          },
        );
        return resp.text();
      },
    }),
    { name: "metabase_run_question" },
  );
}
