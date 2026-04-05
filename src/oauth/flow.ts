import type { OAuthProviderConfig, OAuthTokenResponse } from "../types.js";
import { resolveConfigValue } from "../types.js";

export function buildAuthorizationUrl(params: {
  provider: OAuthProviderConfig;
  state: string;
  callbackUrl: string;
  pkce?: { challenge: string; method: "S256" };
  scopeOverrides?: string[];
}): string {
  const { provider, state, callbackUrl, pkce, scopeOverrides } = params;

  const url = new URL(provider.authUrl);
  url.searchParams.set("client_id", resolveConfigValue(provider.clientId));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", callbackUrl);
  url.searchParams.set("state", state);

  const scopes = scopeOverrides ?? provider.scopes;
  if (scopes && scopes.length > 0) {
    const separator = provider.authorize?.scopeSeparator ?? " ";
    url.searchParams.set("scope", scopes.join(separator));
  }

  if (pkce) {
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
  }

  // Extra authorize params (e.g., Notion's owner=user, Google's access_type=offline)
  if (provider.authorize?.extraParams) {
    for (const [key, value] of Object.entries(provider.authorize.extraParams)) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

export async function exchangeCodeForTokens(params: {
  provider: OAuthProviderConfig;
  code: string;
  callbackUrl: string;
  codeVerifier?: string;
}): Promise<OAuthTokenResponse> {
  const { provider, code, callbackUrl, codeVerifier } = params;

  const authMethod = provider.token?.authMethod ?? "body";
  const bodyFormat = provider.token?.bodyFormat ?? "form";
  const includeRedirectUri = provider.token?.includeRedirectUri ?? true;

  // Build body params
  const bodyParams: Record<string, string> = {
    grant_type: provider.grantType === "client_credentials"
      ? "client_credentials"
      : "authorization_code",
    code,
  };

  if (includeRedirectUri) {
    bodyParams.redirect_uri = callbackUrl;
  }

  if (codeVerifier) {
    bodyParams.code_verifier = codeVerifier;
  }

  // Client credentials: in body or in Authorization header
  if (authMethod === "body") {
    bodyParams.client_id = resolveConfigValue(provider.clientId);
    bodyParams.client_secret = resolveConfigValue(provider.clientSecret);
  }

  // Extra token params
  if (provider.token?.extraParams) {
    for (const [key, value] of Object.entries(provider.token.extraParams)) {
      bodyParams[key] = value;
    }
  }

  // Build headers
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (authMethod === "basic") {
    const clientId = resolveConfigValue(provider.clientId);
    const clientSecret = resolveConfigValue(provider.clientSecret);
    const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    headers["Authorization"] = `Basic ${encoded}`;
  }

  // Extra token headers
  if (provider.token?.extraHeaders) {
    for (const [key, value] of Object.entries(provider.token.extraHeaders)) {
      headers[key] = value;
    }
  }

  // Build body
  let body: string;
  if (bodyFormat === "json") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(bodyParams);
  } else {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(bodyParams).toString();
  }

  const response = await fetch(provider.tokenUrl, {
    method: "POST",
    headers,
    body,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Token exchange failed (${response.status}): ${text}`,
    );
  }

  const data = (await response.json()) as Record<string, unknown>;

  if (typeof data.access_token !== "string" || !data.access_token) {
    throw new Error("Token response is missing access_token.");
  }

  return {
    access_token: data.access_token,
    token_type: typeof data.token_type === "string" ? data.token_type : undefined,
    expires_in: typeof data.expires_in === "number" ? data.expires_in : undefined,
    refresh_token:
      typeof data.refresh_token === "string" ? data.refresh_token : undefined,
    scope: typeof data.scope === "string" ? data.scope : undefined,
  };
}
