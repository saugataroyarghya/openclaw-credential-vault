import type { OAuthTokenResponse, OAuthTokenConfig } from "../types.js";

export async function refreshAccessToken(params: {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  tokenConfig?: OAuthTokenConfig;
}): Promise<OAuthTokenResponse> {
  const { tokenUrl, clientId, clientSecret, refreshToken, tokenConfig } = params;

  const authMethod = tokenConfig?.authMethod ?? "body";
  const bodyFormat = tokenConfig?.bodyFormat ?? "form";

  // Build body params
  const bodyParams: Record<string, string> = {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  };

  if (authMethod === "body") {
    bodyParams.client_id = clientId;
    bodyParams.client_secret = clientSecret;
  }

  if (tokenConfig?.extraParams) {
    for (const [key, value] of Object.entries(tokenConfig.extraParams)) {
      bodyParams[key] = value;
    }
  }

  // Build headers
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (authMethod === "basic") {
    const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    headers["Authorization"] = `Basic ${encoded}`;
  }

  if (tokenConfig?.extraHeaders) {
    for (const [key, value] of Object.entries(tokenConfig.extraHeaders)) {
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

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers,
    body,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Token refresh failed (${response.status}): ${text}`,
    );
  }

  const data = (await response.json()) as Record<string, unknown>;

  if (typeof data.access_token !== "string" || !data.access_token) {
    throw new Error("Refresh response is missing access_token.");
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
