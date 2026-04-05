import type { CredentialStore } from "../store/credential-store.js";
import type { OAuthCredentialPayload, UserIdentity } from "../types.js";
import { parseSessionKey } from "../gate/hook.js";

function resolveIdentity(sessionKey: string): UserIdentity {
  const identity = parseSessionKey(sessionKey);
  if (!identity) throw new Error("Invalid session key");
  return identity;
}

function resolveToken(
  store: CredentialStore,
  agentId: string,
  userId: string,
): string {
  const cred = store.getDecryptedCredential(agentId, userId, "google");
  if (!cred) {
    throw new Error("Not authenticated with Google. Use /connect google");
  }
  return (cred.payload as OAuthCredentialPayload).access_token;
}

async function googleFetch(token: string, url: string): Promise<string> {
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return resp.text();
}

export function registerGoogleTools(
  api: any,
  store: CredentialStore,
): void {
  // 1. google_list_docs
  api.registerTool(
    (ctx: any) => ({
      name: "google_list_docs",
      description:
        "List the user's 10 most recently modified Google Docs.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const url =
          "https://www.googleapis.com/drive/v3/files" +
          "?q=mimeType%3D'application/vnd.google-apps.document'" +
          "&fields=files(id,name,modifiedTime,webViewLink)" +
          "&pageSize=10" +
          "&orderBy=modifiedTime%20desc";
        return googleFetch(token, url);
      },
    }),
    { name: "google_list_docs" },
  );

  // 2. google_get_doc
  api.registerTool(
    (ctx: any) => ({
      name: "google_get_doc",
      description:
        "Get a Google Doc by its document ID. Returns the raw document JSON.",
      parameters: {
        type: "object",
        properties: {
          documentId: {
            type: "string",
            description: "The Google Docs document ID",
          },
        },
        required: ["documentId"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const url = `https://docs.googleapis.com/v1/documents/${params.documentId}`;
        return googleFetch(token, url);
      },
    }),
    { name: "google_get_doc" },
  );

  // 3. google_list_sheets
  api.registerTool(
    (ctx: any) => ({
      name: "google_list_sheets",
      description:
        "List the user's 10 most recently modified Google Sheets.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const url =
          "https://www.googleapis.com/drive/v3/files" +
          "?q=mimeType%3D'application/vnd.google-apps.spreadsheet'" +
          "&fields=files(id,name,modifiedTime,webViewLink)" +
          "&pageSize=10" +
          "&orderBy=modifiedTime%20desc";
        return googleFetch(token, url);
      },
    }),
    { name: "google_list_sheets" },
  );

  // 4. google_get_sheet
  api.registerTool(
    (ctx: any) => ({
      name: "google_get_sheet",
      description:
        "Get a Google Sheet's metadata (title and sheet names) by its spreadsheet ID.",
      parameters: {
        type: "object",
        properties: {
          spreadsheetId: {
            type: "string",
            description: "The Google Sheets spreadsheet ID",
          },
        },
        required: ["spreadsheetId"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const url = `https://sheets.googleapis.com/v4/spreadsheets/${params.spreadsheetId}?includeGridData=false`;
        return googleFetch(token, url);
      },
    }),
    { name: "google_get_sheet" },
  );

  // 5. google_list_calendar_events
  api.registerTool(
    (ctx: any) => ({
      name: "google_list_calendar_events",
      description:
        "List the next 10 upcoming events from the user's primary Google Calendar.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const timeMin = new Date().toISOString();
        const url =
          "https://www.googleapis.com/calendar/v3/calendars/primary/events" +
          `?maxResults=10` +
          `&timeMin=${encodeURIComponent(timeMin)}` +
          `&singleEvents=true` +
          `&orderBy=startTime`;
        return googleFetch(token, url);
      },
    }),
    { name: "google_list_calendar_events" },
  );
}
