import type { OAuthTokenResponse } from "../types.js";

export async function refreshAccessToken(params: {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}): Promise<OAuthTokenResponse> {
  const { tokenUrl, clientId, clientSecret, refreshToken } = params;

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
  });

  const response = await fetch(tokenUrl, {
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
