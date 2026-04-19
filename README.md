# openclaw-credential-vault

> **Per-user OAuth + API key middleware for [OpenClaw](https://docs.openclaw.ai).** One `vault_fetch` tool, generic OAuth2 / API key flows, channel-scoped identity. The AI never sees user credentials.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-plugin-orange.svg)](https://docs.openclaw.ai)
[![Discord](https://img.shields.io/badge/OpenClaw-Discord-5865F2.svg)](https://discord.gg/clawd)

Each chat user (Slack, Discord, Telegram, etc.) connects their own GitHub, Google, Notion, Metabase, or any other account. The vault injects the user's credential into HTTP requests at the transport layer — your AI agent never sees raw tokens. Multi-user isolation, OAuth refresh, audit logging, channel policies, all built in.

Companion to [openclaw-file-guard](https://github.com/saugataroyarghya/openclaw-file-guard) — same middleware pattern, different domain.

## What it does

```
User: "List my GitHub repos"
  ↓
AI calls: vault_fetch({
  command: 'curl -s "https://api.github.com/user/repos"',
  provider: "github"
})
  ↓
credential-vault:
  - Looks up THIS user's GitHub token (per-user, per-agent, channel-scoped)
  - Appends auth header: -H "Authorization: Bearer <user's token>"
  - Executes the curl
  - Returns API response
  ↓
AI: "Here are your repos: ..."
```

The AI sees only the API response — never the token. Each user gets their own credentials. Same agent, multiple users, fully isolated.

## Why you need this

OpenClaw skills like `notion`, `gog`, `github` use shell commands with API keys from environment variables. That's fine for single-user setups. In multi-user chat (Slack/Discord with many people), there's only one set of env vars — everyone shares the same account. This plugin solves that: one `vault_fetch` tool, per-user credentials, secure storage.

## Architecture

Pure middleware. Registers **one tool** (`vault_fetch`) and a `before_tool_call` hook.

- **`vault_fetch` tool** — accepts a curl command + provider name, injects the user's credential, executes
- **OAuth flows** — generic OAuth2 with configurable grant types, auth methods, body formats (works with GitHub, Google, Notion, Linear, etc.)
- **API key flow** — secure web form, key never appears in chat
- **Encrypted storage** — AES-256-GCM, master key from `.env`
- **Channel-scoped identity** — user keys are `channel:senderId` (e.g., `slack:U_BOB`) to prevent cross-channel impersonation
- **Channel policies** — restrict which providers/tools work in which channels
- **Background refresh** — auto-refreshes expiring OAuth tokens
- **Audit log** — every connect, inject, refresh, revoke, and gate-block recorded
- **`before_tool_call` hook** — blocks `exec`/`process` calls that try to bypass `vault_fetch` by referencing vault-managed env vars

## Commands

| Command | Purpose |
|---|---|
| `/connect <provider>` | Connect a service (OAuth link or API key web form) |
| `/disconnect <provider>` | Disconnect a service |
| `/connections` | List your connected services |

## Setup

### 1. Install

```bash
git clone https://github.com/saugataroyarghya/openclaw-credential-vault.git
cd openclaw-credential-vault
npm install
npm run build
```

### 2. Create `.env` in the plugin directory

```bash
cp .env.example .env
```

Fill in:
```
CREDENTIAL_VAULT_MASTER_KEY=any-random-string-at-least-16-chars
GITHUB_CLIENT_ID=Iv1.abc123...
GITHUB_CLIENT_SECRET=your_secret
GOOGLE_CLIENT_ID=12345.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-...
METABASE_URL=http://localhost:3000
```

### 3. Configure OAuth callback URL

Set `callbackBaseUrl` in your OpenClaw config (see Config section below) to whatever URL your OAuth providers will redirect to:

| Setup | callbackBaseUrl | What you set in the OAuth app |
|---|---|---|
| Local (default OpenClaw port) | `http://localhost:18789` | `http://localhost:18789/credential-vault/oauth/callback` |
| Custom domain | `https://auth.yourdomain.com` | `https://auth.yourdomain.com/credential-vault/oauth/callback` |
| ngrok tunnel | `https://abc123.ngrok-free.app` | `https://abc123.ngrok-free.app/credential-vault/oauth/callback` |
| Cloudflare Tunnel | `https://auth.yourdomain.com` | Same — point tunnel at `localhost:18789` |

Update each OAuth app (GitHub, Google, etc.) with the matching callback URL.

### 4. Add config to OpenClaw

Edit `~/.openclaw/openclaw.json` and add the plugin:

```json
{
  "plugins": {
    "load": { "paths": ["/path/to/openclaw-credential-vault"] },
    "allow": ["credential-vault"],
    "entries": {
      "credential-vault": {
        "enabled": true,
        "config": {
          "callbackBaseUrl": "http://localhost:18789",
          "providers": {
            "github": {
              "type": "oauth2",
              "authUrl": "https://github.com/login/oauth/authorize",
              "tokenUrl": "https://github.com/login/oauth/access_token",
              "scopes": ["repo", "read:user"],
              "clientId": { "env": "GITHUB_CLIENT_ID" },
              "clientSecret": { "env": "GITHUB_CLIENT_SECRET" }
            },
            "google": {
              "type": "oauth2",
              "authUrl": "https://accounts.google.com/o/oauth2/v2/auth",
              "tokenUrl": "https://oauth2.googleapis.com/token",
              "scopes": [
                "https://www.googleapis.com/auth/documents.readonly",
                "https://www.googleapis.com/auth/spreadsheets.readonly",
                "https://www.googleapis.com/auth/calendar.readonly"
              ],
              "clientId": { "env": "GOOGLE_CLIENT_ID" },
              "clientSecret": { "env": "GOOGLE_CLIENT_SECRET" },
              "pkce": true,
              "authorize": {
                "extraParams": { "access_type": "offline", "prompt": "consent" }
              }
            },
            "notion": {
              "type": "oauth2",
              "authUrl": "https://api.notion.com/v1/oauth/authorize",
              "tokenUrl": "https://api.notion.com/v1/oauth/token",
              "clientId": { "env": "NOTION_CLIENT_ID" },
              "clientSecret": { "env": "NOTION_CLIENT_SECRET" },
              "authorize": {
                "extraParams": { "owner": "user" }
              },
              "token": {
                "authMethod": "basic",
                "bodyFormat": "json"
              },
              "headerPrefix": "Bearer"
            },
            "metabase": {
              "type": "api_key",
              "headerName": "X-Metabase-Session",
              "headerPrefix": ""
            }
          }
        }
      }
    }
  },
  "tools": {
    "alsoAllow": ["vault_fetch"]
  }
}
```

`tools.alsoAllow: ["vault_fetch"]` is required — without it, the tool is registered but hidden from the AI.

### 5. Restart OpenClaw

```bash
openclaw gateway restart
```

You should see:
```
[credential-vault] Initialized credential store
[credential-vault] Plugin registered successfully
```

## Provider config — generic OAuth2

The OAuth2 config supports the variation across real providers:

| Field | Purpose | Default |
|---|---|---|
| `grantType` | `authorization_code`, `client_credentials`, or `pkce` | `authorization_code` |
| `pkce` | Enable PKCE | `false` |
| `authorize.extraParams` | Extra query params for the authorize URL | none |
| `authorize.scopeSeparator` | How to join scopes (`" "` or `","`) | `" "` |
| `token.authMethod` | `basic` (header) / `body` (in request body) / `none` | `body` |
| `token.bodyFormat` | `form` (urlencoded) or `json` | `form` |
| `token.includeRedirectUri` | Whether to include redirect_uri in token request | `true` |
| `token.extraParams` | Extra body params for token request | none |
| `token.extraHeaders` | Extra headers for token request | none |
| `headerName` | Header name for credential injection | `Authorization` |
| `headerPrefix` | Header value prefix | `Bearer` (OAuth) / `""` (API key) |

Examples:

- **GitHub** uses defaults — minimal config
- **Google** needs PKCE + `access_type=offline` for refresh tokens
- **Notion** needs Basic auth + JSON body + `owner=user` param
- **Linear** needs `actor=user` param
- **Slack** uses comma-separated scopes (`scopeSeparator: ","`)

## Channel policies

Restrict providers per channel:

```json
"channelPolicies": {
  "C_ENGINEERING": {
    "providers": {
      "github": { "tools": ["*"] },
      "google": { "tools": ["*"] }
    }
  },
  "C_MARKETING": {
    "providers": {
      "github": { "tools": ["list_*", "get_*"] }
    }
  },
  "DM": {
    "providers": {
      "github": { "tools": ["*"] },
      "google": { "tools": ["*"] }
    }
  },
  "default": {
    "providers": {}
  }
}
```

Resolution: exact channel match → "DM" for DMs → "default". If `channelPolicies` is omitted entirely, no restrictions apply.

## Skills

Skills teach the AI how to use `vault_fetch` for each provider. Example:

```markdown
---
name: github-vault
description: GitHub API via credential vault
---

Use vault_fetch with provider "github" for all GitHub API calls.
Never include auth headers — the vault handles them.
If "Not connected", tell the user to run `/connect github`.

List repos:
vault_fetch({
  command: 'curl -s "https://api.github.com/user/repos?sort=updated&per_page=10"',
  provider: "github"
})
```

Place skills in `~/.openclaw/workspace/skills/<name>/SKILL.md`.

The plugin ships one skill (`vault-admin`) that teaches the AI how to help users with `/connect` and how admins should add new providers.

## How user identity works

The plugin reads `requesterSenderId` and `messageChannel` from OpenClaw's runtime context. These come from the chat platform's authenticated payload — the AI cannot fake them. User keys are stored as `channel:senderId`:

```
Slack user U_BOB    → slack:U_BOB
Discord user 12345  → discord:12345
WhatsApp +880...    → whatsapp:+880...
```

Same person on different channels = different identities, different credentials. This prevents cross-channel impersonation.

## Database

SQLite at `~/.openclaw/credential-vault/vault.db`. All credentials encrypted at rest with AES-256-GCM (key derived from `CREDENTIAL_VAULT_MASTER_KEY` via scrypt).

Tables:
- **`credentials`** — encrypted access/refresh tokens, scopes, expiry
- **`pending_oauth_states`** — short-lived OAuth state tokens (single-use, 30-min expiry)
- **`audit_log`** — every connect, inject, refresh, revoke, gate-block

## Security notes

- Tokens encrypted at rest (AES-256-GCM)
- OAuth state tokens single-use with 30-min expiry
- Channel-scoped user identity prevents cross-channel impersonation
- API keys collected via web form (HTTPS), never in chat history
- AI never sees raw credentials — only API responses
- 401/403 responses auto-revoke credentials
- Background refresh keeps OAuth tokens valid without user action
- Rate limit per user per provider (default 60/min)

## What it doesn't do

- **Not OS-level encryption.** The SQLite file is encrypted at the row level, not as a whole file. Combine with disk encryption for stronger guarantees.
- **Not a secrets manager.** This is for end-user credentials, not your service secrets. Use HashiCorp Vault or similar for those.
- **Not OpenID Connect.** Only OAuth2 access tokens. ID tokens are not parsed or validated.

## Comparison to file-guard

| Aspect | credential-vault | file-guard |
|---|---|---|
| Domain | API authentication | File access control |
| Hook | `before_tool_call` (gate + inject) | `before_tool_call` (gate only) |
| Storage | Encrypted credentials (AES-GCM) | Ownership metadata (plaintext) |
| Tools registered | `vault_fetch` | None |
| Commands | `/connect`, `/disconnect`, `/connections` | `/protect`, `/unprotect`, `/grant`, `/revoke`, `/protected` |
| User identity | `channel:senderId` (anti-spoofing) | `channel:senderId` (anti-spoofing) |

You can run them together. They don't conflict.

## License

MIT
