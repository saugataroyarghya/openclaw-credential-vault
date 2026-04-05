import type { CredentialStore } from "../store/credential-store.js";
import type { OAuthCredentialPayload, UserIdentity } from "../types.js";
import { parseSessionKey } from "../gate/hook.js";

const GITHUB_API = "https://api.github.com";

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
  const cred = store.getDecryptedCredential(agentId, userId, "github");
  if (!cred) {
    throw new Error("Not authenticated with GitHub. Use /connect github");
  }
  return (cred.payload as OAuthCredentialPayload).access_token;
}

async function githubFetch(
  token: string,
  path: string,
  init?: RequestInit,
): Promise<string> {
  const resp = await fetch(`${GITHUB_API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      ...init?.headers,
    },
  });
  return resp.text();
}

export function registerGithubTools(
  api: any,
  store: CredentialStore,
): void {
  // 1. github_list_repos
  api.registerTool(
    (ctx: any) => ({
      name: "github_list_repos",
      description:
        "List the authenticated user's GitHub repositories, sorted by most recently updated.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        return githubFetch(token, "/user/repos?sort=updated&per_page=10");
      },
    }),
    { name: "github_list_repos" },
  );

  // 2. github_get_repo
  api.registerTool(
    (ctx: any) => ({
      name: "github_get_repo",
      description: "Get details of a specific GitHub repository.",
      parameters: {
        type: "object",
        properties: {
          owner: { type: "string", description: "Repository owner" },
          repo: { type: "string", description: "Repository name" },
        },
        required: ["owner", "repo"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        return githubFetch(token, `/repos/${params.owner}/${params.repo}`);
      },
    }),
    { name: "github_get_repo" },
  );

  // 3. github_list_issues
  api.registerTool(
    (ctx: any) => ({
      name: "github_list_issues",
      description: "List issues for a GitHub repository.",
      parameters: {
        type: "object",
        properties: {
          owner: { type: "string", description: "Repository owner" },
          repo: { type: "string", description: "Repository name" },
          state: {
            type: "string",
            description: "Issue state filter",
            enum: ["open", "closed", "all"],
          },
        },
        required: ["owner", "repo"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const state = (params.state as string) ?? "open";
        return githubFetch(
          token,
          `/repos/${params.owner}/${params.repo}/issues?state=${state}`,
        );
      },
    }),
    { name: "github_list_issues" },
  );

  // 4. github_create_issue
  api.registerTool(
    (ctx: any) => ({
      name: "github_create_issue",
      description: "Create a new issue in a GitHub repository.",
      parameters: {
        type: "object",
        properties: {
          owner: { type: "string", description: "Repository owner" },
          repo: { type: "string", description: "Repository name" },
          title: { type: "string", description: "Issue title" },
          body: { type: "string", description: "Issue body (optional)" },
        },
        required: ["owner", "repo", "title"],
      },
      execute: async (
        _id: string,
        params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        const payload: Record<string, unknown> = { title: params.title };
        if (params.body) payload.body = params.body;
        return githubFetch(
          token,
          `/repos/${params.owner}/${params.repo}/issues`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          },
        );
      },
    }),
    { name: "github_create_issue" },
  );

  // 5. github_get_user
  api.registerTool(
    (ctx: any) => ({
      name: "github_get_user",
      description: "Get the authenticated GitHub user's profile information.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: async (
        _id: string,
        _params: Record<string, unknown>,
      ): Promise<string> => {
        const identity = resolveIdentity(ctx.sessionKey);
        const token = resolveToken(store, ctx.agentId, identity.userId);
        return githubFetch(token, "/user");
      },
    }),
    { name: "github_get_user" },
  );
}
