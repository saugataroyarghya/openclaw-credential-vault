import type Database from "better-sqlite3";

export function runMigrations(db: Database.Database): void {
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id        TEXT    NOT NULL,
      channel_user_id TEXT    NOT NULL,
      channel_id      TEXT    NOT NULL,
      provider        TEXT    NOT NULL,
      auth_type       TEXT    NOT NULL CHECK (auth_type IN ('oauth2', 'api_key')),
      encrypted_data  TEXT    NOT NULL,
      iv              TEXT    NOT NULL,
      auth_tag        TEXT    NOT NULL,
      scopes          TEXT,
      expires_at      INTEGER,
      created_at      INTEGER NOT NULL,
      updated_at      INTEGER NOT NULL,
      UNIQUE (agent_id, channel_user_id, provider)
    );

    CREATE INDEX IF NOT EXISTS idx_credentials_lookup
      ON credentials (agent_id, channel_user_id, provider);

    CREATE INDEX IF NOT EXISTS idx_credentials_expiry
      ON credentials (expires_at)
      WHERE expires_at IS NOT NULL;

    CREATE TABLE IF NOT EXISTS pending_oauth_states (
      state_token   TEXT    PRIMARY KEY,
      agent_id      TEXT    NOT NULL,
      channel_user_id TEXT  NOT NULL,
      channel_id    TEXT    NOT NULL,
      provider      TEXT    NOT NULL,
      pkce_verifier TEXT,
      pkce_iv       TEXT,
      pkce_auth_tag TEXT,
      scopes        TEXT,
      expires_at    INTEGER NOT NULL,
      created_at    INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id        TEXT    NOT NULL,
      channel_user_id TEXT    NOT NULL,
      provider        TEXT    NOT NULL,
      action          TEXT    NOT NULL,
      tool_name       TEXT,
      timestamp       INTEGER NOT NULL,
      metadata        TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_lookup
      ON audit_log (agent_id, channel_user_id, provider, timestamp);
  `);
}
