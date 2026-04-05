import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";

import type {
  AuditAction,
  AuditLogRow,
  CredentialPayload,
  CredentialRow,
  DecryptedCredential,
  PendingStateRow,
} from "../types.js";
import { encrypt, decrypt } from "../crypto.js";
import { STATE_EXPIRY_MS } from "../constants.js";
import { runMigrations } from "./migrations.js";

export class CredentialStore {
  private db: Database.Database;

  constructor({ dbPath }: { dbPath: string }) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    runMigrations(this.db);
  }

  // ── Credentials ──

  getCredential(
    agentId: string,
    channelUserId: string,
    provider: string,
  ): CredentialRow | null {
    const stmt = this.db.prepare<[string, string, string]>(
      `SELECT * FROM credentials
       WHERE agent_id = ? AND channel_user_id = ? AND provider = ?`,
    );
    return (stmt.get(agentId, channelUserId, provider) as CredentialRow) ?? null;
  }

  getDecryptedCredential(
    agentId: string,
    channelUserId: string,
    provider: string,
  ): DecryptedCredential | null {
    const row = this.getCredential(agentId, channelUserId, provider);
    if (!row) return null;

    const plaintext = decrypt(row.encrypted_data, row.iv, row.auth_tag);
    const payload: CredentialPayload = JSON.parse(plaintext);

    return { row, payload };
  }

  saveCredential(params: {
    agentId: string;
    channelUserId: string;
    channelId: string;
    provider: string;
    authType: "oauth2" | "api_key";
    payload: CredentialPayload;
    scopes?: string;
    expiresAt?: number;
  }): void {
    const {
      agentId,
      channelUserId,
      channelId,
      provider,
      authType,
      payload,
      scopes,
      expiresAt,
    } = params;

    const { ciphertext, iv, authTag } = encrypt(JSON.stringify(payload));
    const now = Date.now();

    const stmt = this.db.prepare(`
      INSERT INTO credentials
        (agent_id, channel_user_id, channel_id, provider, auth_type,
         encrypted_data, iv, auth_tag, scopes, expires_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (agent_id, channel_user_id, provider)
      DO UPDATE SET
        channel_id     = excluded.channel_id,
        auth_type      = excluded.auth_type,
        encrypted_data = excluded.encrypted_data,
        iv             = excluded.iv,
        auth_tag       = excluded.auth_tag,
        scopes         = excluded.scopes,
        expires_at     = excluded.expires_at,
        updated_at     = excluded.updated_at
    `);

    stmt.run(
      agentId,
      channelUserId,
      channelId,
      provider,
      authType,
      ciphertext,
      iv,
      authTag,
      scopes ?? null,
      expiresAt ?? null,
      now,
      now,
    );
  }

  updateCredentialTokens(
    id: number,
    payload: CredentialPayload,
    expiresAt?: number,
  ): void {
    const { ciphertext, iv, authTag } = encrypt(JSON.stringify(payload));
    const now = Date.now();

    const stmt = this.db.prepare(`
      UPDATE credentials
      SET encrypted_data = ?, iv = ?, auth_tag = ?,
          expires_at = ?, updated_at = ?
      WHERE id = ?
    `);

    stmt.run(ciphertext, iv, authTag, expiresAt ?? null, now, id);
  }

  deleteCredential(
    agentId: string,
    channelUserId: string,
    provider: string,
  ): void {
    const stmt = this.db.prepare<[string, string, string]>(
      `DELETE FROM credentials
       WHERE agent_id = ? AND channel_user_id = ? AND provider = ?`,
    );
    stmt.run(agentId, channelUserId, provider);
  }

  listCredentials(
    agentId: string,
    channelUserId: string,
  ): CredentialRow[] {
    const stmt = this.db.prepare<[string, string]>(
      `SELECT * FROM credentials
       WHERE agent_id = ? AND channel_user_id = ?`,
    );
    return stmt.all(agentId, channelUserId) as CredentialRow[];
  }

  getExpiringCredentials(bufferMs: number): CredentialRow[] {
    const threshold = Date.now() + bufferMs;

    const stmt = this.db.prepare<[number]>(
      `SELECT * FROM credentials
       WHERE expires_at IS NOT NULL AND expires_at <= ?`,
    );
    return stmt.all(threshold) as CredentialRow[];
  }

  // ── Pending OAuth States ──

  savePendingState(params: {
    stateToken: string;
    agentId: string;
    channelUserId: string;
    channelId: string;
    provider: string;
    pkceVerifier?: string;
    scopes?: string;
  }): void {
    const {
      stateToken,
      agentId,
      channelUserId,
      channelId,
      provider,
      pkceVerifier,
      scopes,
    } = params;

    let pkceVerifierEncrypted: string | null = null;
    let pkceIv: string | null = null;
    let pkceAuthTag: string | null = null;

    if (pkceVerifier) {
      const enc = encrypt(pkceVerifier);
      pkceVerifierEncrypted = enc.ciphertext;
      pkceIv = enc.iv;
      pkceAuthTag = enc.authTag;
    }

    const now = Date.now();
    const expiresAt = now + STATE_EXPIRY_MS;

    const stmt = this.db.prepare(`
      INSERT INTO pending_oauth_states
        (state_token, agent_id, channel_user_id, channel_id, provider,
         pkce_verifier, pkce_iv, pkce_auth_tag, scopes, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      stateToken,
      agentId,
      channelUserId,
      channelId,
      provider,
      pkceVerifierEncrypted,
      pkceIv,
      pkceAuthTag,
      scopes ?? null,
      expiresAt,
      now,
    );
  }

  getPendingState(stateToken: string): PendingStateRow | null {
    const stmt = this.db.prepare<[string]>(
      `SELECT * FROM pending_oauth_states WHERE state_token = ?`,
    );
    const row = stmt.get(stateToken) as PendingStateRow | undefined;

    if (!row) return null;
    if (row.expires_at < Date.now()) return null;

    return row;
  }

  consumePendingState(stateToken: string): PendingStateRow | null {
    const selectStmt = this.db.prepare<[string]>(
      `SELECT * FROM pending_oauth_states WHERE state_token = ?`,
    );
    const row = selectStmt.get(stateToken) as PendingStateRow | undefined;

    if (!row) return null;

    // Delete regardless of expiry to prevent replay
    const deleteStmt = this.db.prepare<[string]>(
      `DELETE FROM pending_oauth_states WHERE state_token = ?`,
    );
    deleteStmt.run(stateToken);

    // Check expiry after deletion
    if (row.expires_at < Date.now()) return null;

    // Decrypt PKCE verifier if present
    if (row.pkce_verifier && row.pkce_iv && row.pkce_auth_tag) {
      row.pkce_verifier = decrypt(
        row.pkce_verifier,
        row.pkce_iv,
        row.pkce_auth_tag,
      );
      // Clear encrypted metadata from the returned row
      row.pkce_iv = null;
      row.pkce_auth_tag = null;
    }

    return row;
  }

  cleanupExpiredStates(): void {
    const stmt = this.db.prepare<[number]>(
      `DELETE FROM pending_oauth_states WHERE expires_at < ?`,
    );
    stmt.run(Date.now());
  }

  // ── Audit Log ──

  logAudit(params: {
    agentId: string;
    channelUserId: string;
    provider: string;
    action: AuditAction;
    toolName?: string;
    mcpServer?: string;
    metadata?: string;
  }): void {
    const {
      agentId,
      channelUserId,
      provider,
      action,
      toolName,
      mcpServer,
      metadata,
    } = params;

    const stmt = this.db.prepare(`
      INSERT INTO audit_log
        (agent_id, channel_user_id, provider, action,
         tool_name, mcp_server, timestamp, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      agentId,
      channelUserId,
      provider,
      action,
      toolName ?? null,
      mcpServer ?? null,
      Date.now(),
      metadata ?? null,
    );
  }

  getAuditLog(agentId: string, limit = 100): AuditLogRow[] {
    const stmt = this.db.prepare<[string, number]>(
      `SELECT * FROM audit_log
       WHERE agent_id = ?
       ORDER BY timestamp DESC
       LIMIT ?`,
    );
    return stmt.all(agentId, limit) as AuditLogRow[];
  }

  // ── Lifecycle ──

  close(): void {
    this.db.close();
  }
}
