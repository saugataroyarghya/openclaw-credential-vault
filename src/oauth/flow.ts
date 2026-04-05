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
    url.searchParams.set("scope", scopes.join(" "));
  }

  if (pkce) {
    url.searchParams.set("code_challenge", pkce.challenge);
    url.searchParams.set("code_challenge_method", pkce.method);
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

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: resolveConfigValue(provider.clientId),
    client_secret: resolveConfigValue(provider.clientSecret),
    code,
    redirect_uri: callbackUrl,
  });

  if (codeVerifier) {
    body.set("code_verifier", codeVerifier);
  }

  const response = await fetch(provider.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
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
