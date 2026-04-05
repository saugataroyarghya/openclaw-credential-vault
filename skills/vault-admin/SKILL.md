---
name: vault-admin
description: Guide users and admins through credential vault setup — connecting services, creating new provider integrations, troubleshooting auth issues.
disable-model-invocation: true
---

# Credential Vault Administration

You have access to the credential vault plugin. Here is how it works so you can help users and admins.

## For Users

Users interact with the vault through these commands:
- `/connect <provider>` — connect a service (OAuth link or API key web form)
- `/disconnect <provider>` — remove a stored credential
- `/connections` — list connected services

When a user asks to use a service and vault_fetch returns "Not connected", guide them:
1. Tell them to run `/connect <provider>`
2. For OAuth: they click the link, authorize, and return
3. For API keys: they open the web form link, enter their key securely
4. After connecting, retry their original request

## For Admins — Adding a New Provider

When an admin wants to add a new service integration, they need three things:

### 1. Provider config in openclaw.json

For OAuth services (GitHub, Google, Linear, Slack, etc.):
```json
"<provider-name>": {
  "type": "oauth2",
  "authUrl": "<provider's OAuth authorize URL>",
  "tokenUrl": "<provider's token exchange URL>",
  "scopes": ["<required scopes>"],
  "clientId": { "env": "<ENV_VAR_NAME>" },
  "clientSecret": { "env": "<ENV_VAR_NAME>" },
  "pkce": false
}
```

For API key services (Notion, Metabase, Stripe, etc.):
```json
"<provider-name>": {
  "type": "api_key",
  "headerName": "<header name, e.g. Authorization>",
  "headerPrefix": "<prefix, e.g. Bearer, or empty string>"
}
```

### 2. Environment variables (OAuth only)

Add client ID and secret to the plugin's `.env` file:
```
<PROVIDER>_CLIENT_ID=...
<PROVIDER>_CLIENT_SECRET=...
```

Set the OAuth callback URL in the provider's developer console:
```
http://localhost:<port>/credential-vault/oauth/callback
```

### 3. A skill (SKILL.md)

Create a skill that teaches the AI how to use vault_fetch with this provider.
Place it in `~/.openclaw/workspace/skills/<provider>-vault/SKILL.md`.

Template:
```markdown
---
name: <provider>-vault
description: <Provider> API via credential vault
---

Use vault_fetch with provider "<provider>" for all <Provider> API calls.
Never include auth headers — the vault handles them.
If "Not connected", tell the user to run `/connect <provider>`.

<List common API operations as vault_fetch examples with curl commands>
```

## Troubleshooting

- "Not connected" after connecting — the credential may be stored under a different agent/channel scope. Try `/new` for a fresh session, then `/connect` again.
- "Provider not available in this channel" — the channelPolicies config doesn't allow this provider here. Admin needs to update channelPolicies.
- "Rate limit exceeded" — wait a moment and retry.
- Auth errors after previously working — the token was revoked or expired. Run `/connect <provider>` again.

## Available Providers

Check which providers are configured by looking at the vault plugin config in openclaw.json under `plugins.entries.credential-vault.config.providers`.
