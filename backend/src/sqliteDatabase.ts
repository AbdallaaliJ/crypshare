import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

export const DATA_DIR = path.join(__dirname, "../data");
export const DATABASE_FILE = process.env.DATABASE_FILE || path.join(DATA_DIR, "crypshare.db");
export const BACKUP_DIR = path.join(DATA_DIR, "backups");
const LEGACY_STATE_FILE = process.env.LEGACY_STATE_FILE || path.join(DATA_DIR, "state.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

const db = new Database(DATABASE_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

export interface AuditEntry {
  timestamp: number;
  userId: string;
  action: string;
  previousHash: string;
  hash: string;
  actorId?: string | null;
  subjectId?: string | null;
  workspaceId?: string | null;
  visibility?: string | null;
}

export interface PreKeyRecord {
  publicKeyHex: string;
  encryptedPrivateKey: string;
  iv: string;
  consumed?: boolean;
}

export interface InboxRecord {
  filepath: string;
  originalFilename: string;
  fileSize: number;
  fileIv: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  senderUsername: string;
  signature: string;
  encryptedPrivatePreKey: string | null;
  preKeyIv: string | null;
  timestamp: number;
}

export interface VaultFileRecord {
  id: string;
  filepath: string;
  fileSize: number;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrappedFileKeyIv: string;
  createdAt: number;
  deletedAt?: number | null;
  sharedWithCount?: number;
}

export interface VaultGrantRecord {
  id: string;
  vaultFileId: string;
  ownerUsername: string;
  recipientUsername: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  signature: string;
  encryptedPrivatePreKey: string | null;
  preKeyIv: string | null;
  createdAt: number;
}

export interface VaultGrantSignatureUpdate {
  grantId: string;
  signature: string;
}

export interface SharedVaultFileRecord extends VaultGrantRecord {
  fileSize: number;
  encryptedMetadata: string;
  metadataIv: string;
  ownerIdentityPublicKeyECDH: string;
  ownerIdentityPublicKeyECDSA: string;
}

export interface UserRecord {
  salt: string;
  authSalt: string;
  authVerifierHash: string;
  identityPublicKeyECDH: string;
  identityPublicKeyECDSA: string;
  encryptedPrivateKeyECDH: string;
  ivECDH: string;
  encryptedPrivateKeyECDSA: string;
  ivECDSA: string;
  revokedAt?: number | null;
  revokedReason?: string | null;
  role?: string;
  approvedAt?: number | null;
  approvedBy?: string | null;
}

export interface SessionRecord {
  id: string;
  username: string;
  createdAt: number;
  expiresAt: number;
  userAgent: string;
}

export type WorkspaceRole = "owner" | "admin" | "member";
export type WorkspaceMemberStatus = "pending" | "active" | "revoked";

export interface WorkspaceRecord {
  id: string;
  name: string;
  inviteCode: string;
  inviteExpiresAt: number;
  createdBy: string;
  createdAt: number;
  role?: WorkspaceRole;
  status?: WorkspaceMemberStatus;
  memberCount?: number;
  pendingCount?: number;
}

export interface WorkspaceMemberRecord {
  workspaceId: string;
  username: string;
  role: WorkspaceRole;
  status: WorkspaceMemberStatus;
  joinedAt: number;
  approvedAt?: number | null;
  approvedBy?: string | null;
  identityPublicKeyECDH?: string;
  identityPublicKeyECDSA?: string;
}

interface UserRow {
  username: string;
  salt: string;
  auth_salt: string;
  auth_verifier_hash: string;
  identity_public_key_ecdh: string;
  identity_public_key_ecdsa: string;
  encrypted_private_key_ecdh: string;
  iv_ecdh: string;
  encrypted_private_key_ecdsa: string;
  iv_ecdsa: string;
  revoked_at: number | null;
  revoked_reason: string | null;
  role: string;
  approved_at: number | null;
  approved_by: string | null;
}

interface PreKeyRow {
  public_key_hex: string;
  encrypted_private_key: string;
  iv: string;
  consumed: number;
}

interface InboxRow {
  filepath: string;
  original_filename: string;
  file_size: number;
  file_iv: string;
  wrapped_file_key: string;
  ephemeral_public_key: string;
  used_pre_key: string;
  sender_username: string;
  signature: string;
  encrypted_private_pre_key: string | null;
  pre_key_iv: string | null;
  timestamp: number;
}

interface AuditRow {
  timestamp: number;
  user_id: string;
  action: string;
  previous_hash: string;
  hash: string;
  actor_id?: string | null;
  subject_id?: string | null;
  workspace_id?: string | null;
  visibility?: string | null;
}

interface VaultFileRow {
  id: string;
  filepath: string;
  file_size: number;
  encrypted_metadata: string;
  metadata_iv: string;
  wrapped_file_key: string;
  wrapped_file_key_iv: string;
  created_at: number;
  deleted_at: number | null;
  shared_with_count?: number;
}

interface VaultGrantRow {
  id: string;
  vault_file_id: string;
  owner_username: string;
  recipient_username: string;
  wrapped_file_key: string;
  ephemeral_public_key: string;
  used_pre_key: string;
  signature: string;
  encrypted_private_pre_key: string | null;
  pre_key_iv: string | null;
  created_at: number;
}

interface SharedVaultFileRow extends VaultGrantRow {
  file_size: number;
  encrypted_metadata: string;
  metadata_iv: string;
  owner_identity_public_key_ecdh: string;
  owner_identity_public_key_ecdsa: string;
}

interface SessionRow {
  id: string;
  username: string;
  created_at: number;
  expires_at: number;
  user_agent: string;
}

interface WorkspaceRow {
  id: string;
  name: string;
  invite_code: string;
  invite_expires_at: number | null;
  created_by: string;
  created_at: number;
  role?: WorkspaceRole;
  status?: WorkspaceMemberStatus;
  member_count?: number;
  pending_count?: number;
}

interface WorkspaceMemberRow {
  workspace_id: string;
  username: string;
  role: WorkspaceRole;
  status: WorkspaceMemberStatus;
  joined_at: number;
  approved_at: number | null;
  approved_by: string | null;
  identity_public_key_ecdh?: string;
  identity_public_key_ecdsa?: string;
}

function runMigration(version: number, name: string, sql: string) {
  const existing = db.prepare("SELECT version FROM schema_migrations WHERE version = ?").get(version);
  if (existing) return;

  db.transaction(() => {
    db.exec(sql);
    db.prepare("INSERT INTO schema_migrations (version, name) VALUES (?, ?)").run(version, name);
  })();
}

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
  `);

  runMigration(1, "initial_secure_share_schema", `
    CREATE TABLE users (
      username TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      auth_salt TEXT NOT NULL,
      auth_verifier_hash TEXT NOT NULL,
      identity_public_key_ecdh TEXT NOT NULL,
      identity_public_key_ecdsa TEXT NOT NULL,
      encrypted_private_key_ecdh TEXT NOT NULL,
      iv_ecdh TEXT NOT NULL,
      encrypted_private_key_ecdsa TEXT NOT NULL,
      iv_ecdsa TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );

    CREATE TABLE pre_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      public_key_hex TEXT NOT NULL UNIQUE,
      encrypted_private_key TEXT NOT NULL,
      iv TEXT NOT NULL,
      consumed INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      consumed_at INTEGER
    );

    CREATE INDEX idx_pre_keys_username_consumed ON pre_keys(username, consumed, id);

    CREATE TABLE inbox_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      filepath TEXT NOT NULL UNIQUE,
      original_filename TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      file_iv TEXT NOT NULL,
      wrapped_file_key TEXT NOT NULL,
      ephemeral_public_key TEXT NOT NULL,
      used_pre_key TEXT NOT NULL,
      sender_username TEXT NOT NULL,
      signature TEXT NOT NULL,
      encrypted_private_pre_key TEXT,
      pre_key_iv TEXT,
      timestamp INTEGER NOT NULL
    );

    CREATE INDEX idx_inbox_files_recipient_timestamp ON inbox_files(recipient_username, timestamp DESC);

    CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      user_id TEXT NOT NULL,
      action TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      hash TEXT NOT NULL UNIQUE
    );

    CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
  `);

  runMigration(2, "identity_revocation", `
    ALTER TABLE users ADD COLUMN revoked_at INTEGER;
    ALTER TABLE users ADD COLUMN revoked_reason TEXT;
  `);

  runMigration(3, "encrypted_owner_vault", `
    CREATE TABLE vault_files (
      id TEXT PRIMARY KEY,
      owner_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      filepath TEXT NOT NULL UNIQUE,
      file_size INTEGER NOT NULL,
      encrypted_metadata TEXT NOT NULL,
      metadata_iv TEXT NOT NULL,
      wrapped_file_key TEXT NOT NULL,
      wrapped_file_key_iv TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX idx_vault_files_owner_created ON vault_files(owner_username, created_at DESC);
  `);

  runMigration(4, "shared_vault_grants", `
    CREATE TABLE vault_grants (
      id TEXT PRIMARY KEY,
      vault_file_id TEXT NOT NULL REFERENCES vault_files(id) ON DELETE CASCADE,
      owner_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      recipient_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      wrapped_file_key TEXT NOT NULL,
      ephemeral_public_key TEXT NOT NULL,
      used_pre_key TEXT NOT NULL,
      signature TEXT NOT NULL,
      encrypted_private_pre_key TEXT,
      pre_key_iv TEXT,
      created_at INTEGER NOT NULL,
      UNIQUE(vault_file_id, recipient_username)
    );

    CREATE INDEX idx_vault_grants_recipient_created ON vault_grants(recipient_username, created_at DESC);
    CREATE INDEX idx_vault_grants_owner_file ON vault_grants(owner_username, vault_file_id);
  `);

  runMigration(5, "persistent_sessions", `
    CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY,
      id TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      user_agent TEXT NOT NULL
    );

    CREATE INDEX idx_sessions_username_created ON sessions(username, created_at DESC);
    CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
  `);

  runMigration(6, "identity_approval", `
    ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member';
    ALTER TABLE users ADD COLUMN approved_at INTEGER;
    ALTER TABLE users ADD COLUMN approved_by TEXT;

    UPDATE users
    SET approved_at = COALESCE(approved_at, created_at),
        approved_by = COALESCE(approved_by, 'system')
    WHERE approved_at IS NULL;

    UPDATE users
    SET role = 'admin'
    WHERE username = (
      SELECT username FROM users ORDER BY created_at ASC LIMIT 1
    );
  `);

  runMigration(7, "workspace_membership", `
    CREATE TABLE workspaces (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      invite_code TEXT NOT NULL UNIQUE,
      created_by TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE workspace_members (
      workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
      username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
      status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
      joined_at INTEGER NOT NULL,
      approved_at INTEGER,
      approved_by TEXT,
      PRIMARY KEY (workspace_id, username)
    );

    CREATE INDEX idx_workspace_members_username_status ON workspace_members(username, status);
    CREATE INDEX idx_workspace_members_workspace_status ON workspace_members(workspace_id, status);
  `);

  runMigration(8, "workspace_invite_expiry", `
    ALTER TABLE workspaces ADD COLUMN invite_expires_at INTEGER;
    UPDATE workspaces
    SET invite_expires_at = created_at + 604800000
    WHERE invite_expires_at IS NULL;
  `);

  runMigration(9, "vault_file_trash", `
    ALTER TABLE vault_files ADD COLUMN deleted_at INTEGER;
    CREATE INDEX idx_vault_files_owner_deleted_created ON vault_files(owner_username, deleted_at, created_at DESC);
  `);

  runMigration(10, "scoped_audit_visibility", `
    ALTER TABLE audit_log ADD COLUMN actor_id TEXT;
    ALTER TABLE audit_log ADD COLUMN subject_id TEXT;
    ALTER TABLE audit_log ADD COLUMN workspace_id TEXT;
    ALTER TABLE audit_log ADD COLUMN visibility TEXT NOT NULL DEFAULT 'user';

    UPDATE audit_log
    SET actor_id = COALESCE(actor_id, user_id),
        subject_id = COALESCE(subject_id, user_id)
    WHERE actor_id IS NULL OR subject_id IS NULL;

    CREATE INDEX idx_audit_log_actor ON audit_log(actor_id, timestamp);
    CREATE INDEX idx_audit_log_subject ON audit_log(subject_id, timestamp);
    CREATE INDEX idx_audit_log_workspace ON audit_log(workspace_id, timestamp);
  `);
}

function mapUser(row: UserRow): UserRecord {
  return {
    salt: row.salt,
    authSalt: row.auth_salt,
    authVerifierHash: row.auth_verifier_hash,
    identityPublicKeyECDH: row.identity_public_key_ecdh,
    identityPublicKeyECDSA: row.identity_public_key_ecdsa,
    encryptedPrivateKeyECDH: row.encrypted_private_key_ecdh,
    ivECDH: row.iv_ecdh,
    encryptedPrivateKeyECDSA: row.encrypted_private_key_ecdsa,
    ivECDSA: row.iv_ecdsa,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
    role: row.role,
    approvedAt: row.approved_at,
    approvedBy: row.approved_by
  };
}

function mapPreKey(row: PreKeyRow): PreKeyRecord {
  return {
    publicKeyHex: row.public_key_hex,
    encryptedPrivateKey: row.encrypted_private_key,
    iv: row.iv,
    consumed: row.consumed === 1
  };
}

function mapInbox(row: InboxRow): InboxRecord {
  return {
    filepath: row.filepath,
    originalFilename: row.original_filename,
    fileSize: row.file_size,
    fileIv: row.file_iv,
    wrappedFileKey: row.wrapped_file_key,
    ephemeralPublicKey: row.ephemeral_public_key,
    usedPreKey: row.used_pre_key,
    senderUsername: row.sender_username,
    signature: row.signature,
    encryptedPrivatePreKey: row.encrypted_private_pre_key,
    preKeyIv: row.pre_key_iv,
    timestamp: row.timestamp
  };
}

function mapAudit(row: AuditRow): AuditEntry {
  return {
    timestamp: row.timestamp,
    userId: row.user_id,
    action: row.action,
    previousHash: row.previous_hash,
    hash: row.hash,
    actorId: row.actor_id ?? row.user_id,
    subjectId: row.subject_id ?? row.user_id,
    workspaceId: row.workspace_id ?? null,
    visibility: row.visibility ?? "user"
  };
}

function mapVaultFile(row: VaultFileRow): VaultFileRecord {
  return {
    id: row.id,
    filepath: row.filepath,
    fileSize: row.file_size,
    encryptedMetadata: row.encrypted_metadata,
    metadataIv: row.metadata_iv,
    wrappedFileKey: row.wrapped_file_key,
    wrappedFileKeyIv: row.wrapped_file_key_iv,
    createdAt: row.created_at,
    deletedAt: row.deleted_at,
    sharedWithCount: row.shared_with_count
  };
}

function mapVaultGrant(row: VaultGrantRow): VaultGrantRecord {
  return {
    id: row.id,
    vaultFileId: row.vault_file_id,
    ownerUsername: row.owner_username,
    recipientUsername: row.recipient_username,
    wrappedFileKey: row.wrapped_file_key,
    ephemeralPublicKey: row.ephemeral_public_key,
    usedPreKey: row.used_pre_key,
    signature: row.signature,
    encryptedPrivatePreKey: row.encrypted_private_pre_key,
    preKeyIv: row.pre_key_iv,
    createdAt: row.created_at
  };
}

function mapSharedVaultFile(row: SharedVaultFileRow): SharedVaultFileRecord {
  return {
    ...mapVaultGrant(row),
    fileSize: row.file_size,
    encryptedMetadata: row.encrypted_metadata,
    metadataIv: row.metadata_iv,
    ownerIdentityPublicKeyECDH: row.owner_identity_public_key_ecdh,
    ownerIdentityPublicKeyECDSA: row.owner_identity_public_key_ecdsa
  };
}

function mapSession(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    username: row.username,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    userAgent: row.user_agent
  };
}

function mapWorkspace(row: WorkspaceRow): WorkspaceRecord {
  return {
    id: row.id,
    name: row.name,
    inviteCode: row.invite_code,
    inviteExpiresAt: row.invite_expires_at || row.created_at + 604800000,
    createdBy: row.created_by,
    createdAt: row.created_at,
    role: row.role,
    status: row.status,
    memberCount: row.member_count,
    pendingCount: row.pending_count
  };
}

function mapWorkspaceMember(row: WorkspaceMemberRow): WorkspaceMemberRecord {
  return {
    workspaceId: row.workspace_id,
    username: row.username,
    role: row.role,
    status: row.status,
    joinedAt: row.joined_at,
    approvedAt: row.approved_at,
    approvedBy: row.approved_by,
    identityPublicKeyECDH: row.identity_public_key_ecdh,
    identityPublicKeyECDSA: row.identity_public_key_ecdsa
  };
}

export function getUser(username: string) {
  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as UserRow | undefined;
  return row ? mapUser(row) : null;
}

export function createUser(username: string, user: UserRecord) {
  db.prepare(`
    INSERT INTO users (
      username, salt, auth_salt, auth_verifier_hash, identity_public_key_ecdh,
      identity_public_key_ecdsa, encrypted_private_key_ecdh, iv_ecdh,
      encrypted_private_key_ecdsa, iv_ecdsa, role, approved_at, approved_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    username,
    user.salt,
    user.authSalt,
    user.authVerifierHash,
    user.identityPublicKeyECDH,
    user.identityPublicKeyECDSA,
    user.encryptedPrivateKeyECDH,
    user.ivECDH,
    user.encryptedPrivateKeyECDSA,
    user.ivECDSA,
    user.role || "member",
    user.approvedAt || null,
    user.approvedBy || null
  );
}

export function listUsers() {
  return db.prepare(`
    SELECT username, identity_public_key_ecdh, identity_public_key_ecdsa
    FROM users
    WHERE revoked_at IS NULL AND approved_at IS NOT NULL
    ORDER BY username ASC
  `).all() as Array<{
    username: string;
    identity_public_key_ecdh: string;
    identity_public_key_ecdsa: string;
  }>;
}

export function listDiscoverableUsers(username: string) {
  return db.prepare(`
    SELECT DISTINCT u.username, u.identity_public_key_ecdh, u.identity_public_key_ecdsa
    FROM users u
    WHERE u.revoked_at IS NULL
      AND (
        u.username = ?
        OR EXISTS (
          SELECT 1
          FROM workspace_members mine
          JOIN workspace_members theirs ON theirs.workspace_id = mine.workspace_id
          WHERE mine.username = ?
            AND mine.status = 'active'
            AND theirs.username = u.username
            AND theirs.status = 'active'
        )
      )
    ORDER BY u.username ASC
  `).all(username, username) as Array<{
    username: string;
    identity_public_key_ecdh: string;
    identity_public_key_ecdsa: string;
  }>;
}

export function countApprovedUsers() {
  const row = db.prepare("SELECT COUNT(*) AS count FROM users WHERE approved_at IS NOT NULL AND revoked_at IS NULL").get() as { count: number };
  return row.count;
}

export function listPendingUsers() {
  return db.prepare(`
    SELECT username, identity_public_key_ecdh, identity_public_key_ecdsa
    FROM users
    WHERE revoked_at IS NULL AND approved_at IS NULL
    ORDER BY username ASC
  `).all() as Array<{
    username: string;
    identity_public_key_ecdh: string;
    identity_public_key_ecdsa: string;
  }>;
}

export function approveUser(username: string, approvedBy: string) {
  const approvedAt = Date.now();
  const result = db.prepare(`
    UPDATE users
    SET approved_at = ?, approved_by = ?
    WHERE username = ? AND revoked_at IS NULL AND approved_at IS NULL
  `).run(approvedAt, approvedBy, username);

  return result.changes > 0 ? { approvedAt, approvedBy } : null;
}

export function revokeUser(username: string, reason: string) {
  const revokedAt = Date.now();
  const result = db.prepare(`
    UPDATE users
    SET revoked_at = ?, revoked_reason = ?
    WHERE username = ? AND revoked_at IS NULL
  `).run(revokedAt, reason, username);

  return result.changes > 0 ? { revokedAt, reason } : null;
}

export function createSessionRecord(tokenHash: string, session: SessionRecord) {
  db.prepare(`
    INSERT INTO sessions (token_hash, id, username, created_at, expires_at, user_agent)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    tokenHash,
    session.id,
    session.username,
    session.createdAt,
    session.expiresAt,
    session.userAgent
  );
}

export function getSessionByTokenHash(tokenHash: string) {
  const row = db.prepare(`
    SELECT id, username, created_at, expires_at, user_agent
    FROM sessions
    WHERE token_hash = ?
  `).get(tokenHash) as SessionRow | undefined;

  return row ? mapSession(row) : null;
}

export function deleteSessionByTokenHash(tokenHash: string) {
  const result = db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  return result.changes > 0;
}

export function deleteSessionById(username: string, sessionId: string) {
  const result = db.prepare("DELETE FROM sessions WHERE username = ? AND id = ?").run(username, sessionId);
  return result.changes > 0;
}

export function deleteOtherSessions(username: string, currentSessionId: string) {
  const result = db.prepare("DELETE FROM sessions WHERE username = ? AND id <> ?").run(username, currentSessionId);
  return result.changes;
}

export function deleteAllSessions(username: string) {
  const result = db.prepare("DELETE FROM sessions WHERE username = ?").run(username);
  return result.changes;
}

export function cleanupExpiredSessionRecords(now = Date.now()) {
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now);
  return result.changes;
}

export function createWorkspace(workspace: WorkspaceRecord, ownerUsername: string) {
  return db.transaction(() => {
    db.prepare(`
      INSERT INTO workspaces (id, name, invite_code, invite_expires_at, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(workspace.id, workspace.name, workspace.inviteCode, workspace.inviteExpiresAt, ownerUsername, workspace.createdAt);

    db.prepare(`
      INSERT INTO workspace_members (
        workspace_id, username, role, status, joined_at, approved_at, approved_by
      ) VALUES (?, ?, 'owner', 'active', ?, ?, ?)
    `).run(workspace.id, ownerUsername, workspace.createdAt, workspace.createdAt, ownerUsername);

    return getWorkspaceMembership(workspace.id, ownerUsername);
  })();
}

export function findWorkspaceById(workspaceId: string) {
  const row = db.prepare(`
    SELECT id, name, invite_code, invite_expires_at, created_by, created_at
    FROM workspaces
    WHERE id = ?
  `).get(workspaceId) as WorkspaceRow | undefined;

  return row ? mapWorkspace(row) : null;
}

export function findWorkspaceByInviteCode(inviteCode: string) {
  const row = db.prepare(`
    SELECT id, name, invite_code, invite_expires_at, created_by, created_at
    FROM workspaces
    WHERE invite_code = ?
  `).get(inviteCode) as WorkspaceRow | undefined;

  return row ? mapWorkspace(row) : null;
}

export function listWorkspacesForUser(username: string) {
  const rows = db.prepare(`
    SELECT
      w.id,
      w.name,
      w.invite_code,
      w.invite_expires_at,
      w.created_by,
      w.created_at,
      wm.role,
      wm.status,
      (
        SELECT COUNT(*)
        FROM workspace_members active_members
        WHERE active_members.workspace_id = w.id AND active_members.status = 'active'
      ) AS member_count,
      (
        SELECT COUNT(*)
        FROM workspace_members pending_members
        WHERE pending_members.workspace_id = w.id AND pending_members.status = 'pending'
      ) AS pending_count
    FROM workspaces w
    JOIN workspace_members wm ON wm.workspace_id = w.id
    WHERE wm.username = ? AND wm.status <> 'revoked'
    ORDER BY w.created_at DESC
  `).all(username) as WorkspaceRow[];

  return rows.map(mapWorkspace);
}

export function rotateWorkspaceInvite(workspaceId: string, inviteCode: string, inviteExpiresAt: number) {
  const result = db.prepare(`
    UPDATE workspaces
    SET invite_code = ?, invite_expires_at = ?
    WHERE id = ?
  `).run(inviteCode, inviteExpiresAt, workspaceId);

  return result.changes > 0 ? findWorkspaceById(workspaceId) : null;
}

export function getWorkspaceMembership(workspaceId: string, username: string) {
  const row = db.prepare(`
    SELECT
      wm.workspace_id,
      wm.username,
      wm.role,
      wm.status,
      wm.joined_at,
      wm.approved_at,
      wm.approved_by,
      users.identity_public_key_ecdh,
      users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = ? AND wm.username = ?
  `).get(workspaceId, username) as WorkspaceMemberRow | undefined;

  return row ? mapWorkspaceMember(row) : null;
}

export function requestWorkspaceJoin(workspaceId: string, username: string) {
  return db.transaction(() => {
    const existing = getWorkspaceMembership(workspaceId, username);
    if (existing?.status === "active" || existing?.status === "pending") return existing;

    const joinedAt = Date.now();
    if (existing?.status === "revoked") {
      db.prepare(`
        UPDATE workspace_members
        SET role = 'member',
            status = 'pending',
            joined_at = ?,
            approved_at = NULL,
            approved_by = NULL
        WHERE workspace_id = ? AND username = ?
      `).run(joinedAt, workspaceId, username);
    } else {
      db.prepare(`
        INSERT INTO workspace_members (
          workspace_id, username, role, status, joined_at, approved_at, approved_by
        ) VALUES (?, ?, 'member', 'pending', ?, NULL, NULL)
      `).run(workspaceId, username, joinedAt);
    }

    return getWorkspaceMembership(workspaceId, username);
  })();
}

export function listWorkspaceMembers(workspaceId: string) {
  const rows = db.prepare(`
    SELECT
      wm.workspace_id,
      wm.username,
      wm.role,
      wm.status,
      wm.joined_at,
      wm.approved_at,
      wm.approved_by,
      users.identity_public_key_ecdh,
      users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = ?
      AND wm.status = 'active'
      AND users.revoked_at IS NULL
    ORDER BY wm.role ASC, wm.username ASC
  `).all(workspaceId) as WorkspaceMemberRow[];

  return rows.map(mapWorkspaceMember);
}

export function listPendingWorkspaceMembers(workspaceId: string) {
  const rows = db.prepare(`
    SELECT
      wm.workspace_id,
      wm.username,
      wm.role,
      wm.status,
      wm.joined_at,
      wm.approved_at,
      wm.approved_by,
      users.identity_public_key_ecdh,
      users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = ?
      AND wm.status = 'pending'
      AND users.revoked_at IS NULL
    ORDER BY wm.joined_at ASC
  `).all(workspaceId) as WorkspaceMemberRow[];

  return rows.map(mapWorkspaceMember);
}

export function approveWorkspaceMember(workspaceId: string, username: string, approvedBy: string) {
  const approvedAt = Date.now();
  const result = db.prepare(`
    UPDATE workspace_members
    SET status = 'active',
        role = CASE WHEN role = 'owner' THEN 'owner' ELSE 'member' END,
        approved_at = ?,
        approved_by = ?
    WHERE workspace_id = ? AND username = ? AND status = 'pending'
  `).run(approvedAt, approvedBy, workspaceId, username);

  return result.changes > 0 ? getWorkspaceMembership(workspaceId, username) : null;
}

export function revokeWorkspaceMember(workspaceId: string, username: string) {
  const result = db.prepare(`
    UPDATE workspace_members
    SET status = 'revoked'
    WHERE workspace_id = ? AND username = ? AND status = 'active' AND role <> 'owner'
  `).run(workspaceId, username);

  return result.changes > 0;
}

export function updateWorkspaceMemberRole(workspaceId: string, username: string, role: Exclude<WorkspaceRole, "owner">) {
  const result = db.prepare(`
    UPDATE workspace_members
    SET role = ?
    WHERE workspace_id = ? AND username = ? AND status = 'active' AND role <> 'owner'
  `).run(role, workspaceId, username);

  return result.changes > 0 ? getWorkspaceMembership(workspaceId, username) : null;
}

export function usersShareActiveWorkspace(firstUsername: string, secondUsername: string) {
  const row = db.prepare(`
    SELECT COUNT(*) AS count
    FROM workspace_members first_member
    JOIN workspace_members second_member ON second_member.workspace_id = first_member.workspace_id
    WHERE first_member.username = ?
      AND second_member.username = ?
      AND first_member.status = 'active'
      AND second_member.status = 'active'
  `).get(firstUsername, secondUsername) as { count: number };

  return row.count > 0;
}

export function listSessionRecords(username: string, currentSessionId: string) {
  cleanupExpiredSessionRecords();
  const rows = db.prepare(`
    SELECT id, username, created_at, expires_at, user_agent
    FROM sessions
    WHERE username = ?
    ORDER BY created_at DESC
  `).all(username) as SessionRow[];

  return rows.map((session) => ({
    ...mapSession(session),
    current: session.id === currentSessionId
  }));
}

export function addPreKeys(username: string, preKeys: PreKeyRecord[]) {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO pre_keys (username, public_key_hex, encrypted_private_key, iv)
    VALUES (?, ?, ?, ?)
  `);

  db.transaction(() => {
    for (const preKey of preKeys) {
      insert.run(username, preKey.publicKeyHex, preKey.encryptedPrivateKey, preKey.iv);
    }
  })();
}

export function getPreKeyStatus(username: string) {
  const row = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN consumed = 0 THEN 1 ELSE 0 END) AS available,
      SUM(CASE WHEN consumed = 1 THEN 1 ELSE 0 END) AS consumed
    FROM pre_keys
    WHERE username = ?
  `).get(username) as { total: number; available: number | null; consumed: number | null };

  return {
    total: row.total,
    available: row.available || 0,
    consumed: row.consumed || 0
  };
}

export function consumeNextPreKey(username: string) {
  return db.transaction(() => {
    const row = db.prepare(`
      SELECT public_key_hex, encrypted_private_key, iv, consumed
      FROM pre_keys
      WHERE username = ? AND consumed = 0
      ORDER BY id ASC
      LIMIT 1
    `).get(username) as PreKeyRow | undefined;

    if (!row) return null;

    db.prepare(`
      UPDATE pre_keys
      SET consumed = 1, consumed_at = ?
      WHERE username = ? AND public_key_hex = ?
    `).run(Date.now(), username, row.public_key_hex);

    return mapPreKey(row);
  })();
}

export function getPreKey(username: string, publicKeyHex: string) {
  const row = db.prepare(`
    SELECT public_key_hex, encrypted_private_key, iv, consumed
    FROM pre_keys
    WHERE username = ? AND public_key_hex = ?
  `).get(username, publicKeyHex) as PreKeyRow | undefined;

  return row ? mapPreKey(row) : null;
}

export function addInboxFile(recipientUsername: string, file: InboxRecord) {
  db.prepare(`
    INSERT INTO inbox_files (
      recipient_username, filepath, original_filename, file_size, file_iv,
      wrapped_file_key, ephemeral_public_key, used_pre_key, sender_username,
      signature, encrypted_private_pre_key, pre_key_iv, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    recipientUsername,
    file.filepath,
    file.originalFilename,
    file.fileSize,
    file.fileIv,
    file.wrappedFileKey,
    file.ephemeralPublicKey,
    file.usedPreKey,
    file.senderUsername,
    file.signature,
    file.encryptedPrivatePreKey,
    file.preKeyIv,
    file.timestamp
  );
}

export function listInbox(username: string) {
  const rows = db.prepare(`
    SELECT *
    FROM inbox_files
    WHERE recipient_username = ?
    ORDER BY timestamp DESC
  `).all(username) as InboxRow[];

  return rows.map(mapInbox);
}

export function findInboxFile(username: string, filepath: string) {
  const row = db.prepare(`
    SELECT *
    FROM inbox_files
    WHERE recipient_username = ? AND filepath = ?
  `).get(username, filepath) as InboxRow | undefined;

  return row ? mapInbox(row) : null;
}

export function addVaultFile(ownerUsername: string, file: VaultFileRecord) {
  db.prepare(`
    INSERT INTO vault_files (
      id, owner_username, filepath, file_size, encrypted_metadata, metadata_iv,
      wrapped_file_key, wrapped_file_key_iv, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    file.id,
    ownerUsername,
    file.filepath,
    file.fileSize,
    file.encryptedMetadata,
    file.metadataIv,
    file.wrappedFileKey,
    file.wrappedFileKeyIv,
    file.createdAt
  );
}

export function listVaultFiles(ownerUsername: string, options: { trashed?: boolean } = {}) {
  const rows = db.prepare(`
    SELECT
      files.*,
      (
        SELECT COUNT(*)
        FROM vault_grants grants
        WHERE grants.vault_file_id = files.id
      ) AS shared_with_count
    FROM vault_files files
    WHERE files.owner_username = ?
      AND ${options.trashed ? "files.deleted_at IS NOT NULL" : "files.deleted_at IS NULL"}
    ORDER BY files.created_at DESC
  `).all(ownerUsername) as VaultFileRow[];

  return rows.map(mapVaultFile);
}

export function findVaultFile(ownerUsername: string, id: string, options: { includeTrashed?: boolean } = {}) {
  const row = db.prepare(`
    SELECT *
    FROM vault_files
    WHERE owner_username = ? AND id = ?
      AND (? = 1 OR deleted_at IS NULL)
  `).get(ownerUsername, id, options.includeTrashed ? 1 : 0) as VaultFileRow | undefined;

  return row ? mapVaultFile(row) : null;
}

export function getVaultStorageBytes(ownerUsername: string) {
  const row = db.prepare(`
    SELECT COALESCE(SUM(file_size), 0) AS total
    FROM vault_files
    WHERE owner_username = ?
  `).get(ownerUsername) as { total: number } | undefined;

  return Number(row?.total || 0);
}

export function trashVaultFile(ownerUsername: string, id: string) {
  const deletedAt = Date.now();
  const result = db.prepare(`
    UPDATE vault_files
    SET deleted_at = ?
    WHERE owner_username = ? AND id = ? AND deleted_at IS NULL
  `).run(deletedAt, ownerUsername, id);

  return result.changes > 0 ? findVaultFile(ownerUsername, id, { includeTrashed: true }) : null;
}

export function restoreVaultFile(ownerUsername: string, id: string) {
  const result = db.prepare(`
    UPDATE vault_files
    SET deleted_at = NULL
    WHERE owner_username = ? AND id = ? AND deleted_at IS NOT NULL
  `).run(ownerUsername, id);

  return result.changes > 0 ? findVaultFile(ownerUsername, id) : null;
}

export function updateVaultFileMetadata(
  ownerUsername: string,
  id: string,
  encryptedMetadata: string,
  metadataIv: string,
  grantSignatures: VaultGrantSignatureUpdate[]
) {
  return db.transaction(() => {
    const existing = findVaultFile(ownerUsername, id);
    if (!existing) return null;

    db.prepare(`
      UPDATE vault_files
      SET encrypted_metadata = ?,
          metadata_iv = ?
      WHERE owner_username = ? AND id = ? AND deleted_at IS NULL
    `).run(encryptedMetadata, metadataIv, ownerUsername, id);

    const updateGrant = db.prepare(`
      UPDATE vault_grants
      SET signature = ?
      WHERE owner_username = ? AND vault_file_id = ? AND id = ?
    `);

    for (const grantSignature of grantSignatures) {
      updateGrant.run(grantSignature.signature, ownerUsername, id, grantSignature.grantId);
    }

    return findVaultFile(ownerUsername, id);
  })();
}

export function permanentlyDeleteVaultFile(ownerUsername: string, id: string) {
  const row = findVaultFile(ownerUsername, id, { includeTrashed: true });
  if (!row) return null;

  db.prepare("DELETE FROM vault_files WHERE owner_username = ? AND id = ?").run(ownerUsername, id);
  return row;
}

export function rotateVaultFile(
  ownerUsername: string,
  file: VaultFileRecord,
  replacementGrants: VaultGrantRecord[]
) {
  return db.transaction(() => {
    const existing = findVaultFile(ownerUsername, file.id);
    if (!existing) return null;

    db.prepare(`
      UPDATE vault_files
      SET filepath = ?,
          file_size = ?,
          encrypted_metadata = ?,
          metadata_iv = ?,
          wrapped_file_key = ?,
          wrapped_file_key_iv = ?
      WHERE owner_username = ? AND id = ?
    `).run(
      file.filepath,
      file.fileSize,
      file.encryptedMetadata,
      file.metadataIv,
      file.wrappedFileKey,
      file.wrappedFileKeyIv,
      ownerUsername,
      file.id
    );

    db.prepare("DELETE FROM vault_grants WHERE owner_username = ? AND vault_file_id = ?").run(ownerUsername, file.id);

    const insertGrant = db.prepare(`
      INSERT INTO vault_grants (
        id, vault_file_id, owner_username, recipient_username, wrapped_file_key,
        ephemeral_public_key, used_pre_key, signature, encrypted_private_pre_key,
        pre_key_iv, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const grant of replacementGrants) {
      insertGrant.run(
        grant.id,
        grant.vaultFileId,
        grant.ownerUsername,
        grant.recipientUsername,
        grant.wrappedFileKey,
        grant.ephemeralPublicKey,
        grant.usedPreKey,
        grant.signature,
        grant.encryptedPrivatePreKey,
        grant.preKeyIv,
        grant.createdAt
      );
    }

    return existing;
  })();
}

export function addVaultGrant(grant: VaultGrantRecord) {
  db.prepare(`
    INSERT INTO vault_grants (
      id, vault_file_id, owner_username, recipient_username, wrapped_file_key,
      ephemeral_public_key, used_pre_key, signature, encrypted_private_pre_key,
      pre_key_iv, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    grant.id,
    grant.vaultFileId,
    grant.ownerUsername,
    grant.recipientUsername,
    grant.wrappedFileKey,
    grant.ephemeralPublicKey,
    grant.usedPreKey,
    grant.signature,
    grant.encryptedPrivatePreKey,
    grant.preKeyIv,
    grant.createdAt
  );
}

export function listVaultGrantsForFile(ownerUsername: string, vaultFileId: string) {
  const rows = db.prepare(`
    SELECT *
    FROM vault_grants
    WHERE owner_username = ? AND vault_file_id = ?
    ORDER BY created_at DESC
  `).all(ownerUsername, vaultFileId) as VaultGrantRow[];

  return rows.map(mapVaultGrant);
}

export function listSharedVaultFiles(recipientUsername: string) {
  const rows = db.prepare(`
    SELECT
      grants.*,
      files.file_size,
      files.encrypted_metadata,
      files.metadata_iv,
      users.identity_public_key_ecdh AS owner_identity_public_key_ecdh,
      users.identity_public_key_ecdsa AS owner_identity_public_key_ecdsa
    FROM vault_grants grants
    JOIN vault_files files ON files.id = grants.vault_file_id
    JOIN users ON users.username = grants.owner_username
    WHERE grants.recipient_username = ?
      AND users.revoked_at IS NULL
      AND files.deleted_at IS NULL
    ORDER BY grants.created_at DESC
  `).all(recipientUsername) as SharedVaultFileRow[];

  return rows.map(mapSharedVaultFile);
}

export function findSharedVaultFile(recipientUsername: string, grantId: string) {
  const row = db.prepare(`
    SELECT
      grants.*,
      files.file_size,
      files.encrypted_metadata,
      files.metadata_iv,
      users.identity_public_key_ecdh AS owner_identity_public_key_ecdh,
      users.identity_public_key_ecdsa AS owner_identity_public_key_ecdsa
    FROM vault_grants grants
    JOIN vault_files files ON files.id = grants.vault_file_id
    JOIN users ON users.username = grants.owner_username
    WHERE grants.recipient_username = ?
      AND grants.id = ?
      AND users.revoked_at IS NULL
      AND files.deleted_at IS NULL
  `).get(recipientUsername, grantId) as SharedVaultFileRow | undefined;

  return row ? mapSharedVaultFile(row) : null;
}

export function findVaultFileById(id: string) {
  const row = db.prepare("SELECT * FROM vault_files WHERE id = ? AND deleted_at IS NULL").get(id) as VaultFileRow | undefined;
  return row ? mapVaultFile(row) : null;
}

export function getLastAuditHash() {
  const row = db.prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").get() as { hash: string } | undefined;
  return row?.hash || null;
}

export function appendAuditEntry(entry: AuditEntry) {
  db.prepare(`
    INSERT INTO audit_log (
      timestamp,
      user_id,
      action,
      previous_hash,
      hash,
      actor_id,
      subject_id,
      workspace_id,
      visibility
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    entry.timestamp,
    entry.userId,
    entry.action,
    entry.previousHash,
    entry.hash,
    entry.actorId || entry.userId,
    entry.subjectId || entry.userId,
    entry.workspaceId || null,
    entry.visibility || "user"
  );
}

export function getAuditLog() {
  const rows = db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all() as AuditRow[];
  return rows.map(mapAudit);
}

export function getVisibleAuditLog(username: string, adminWorkspaceIds: string[]) {
  const workspacePlaceholders = adminWorkspaceIds.map(() => "?").join(",");
  const workspaceClause = workspacePlaceholders
    ? `OR (workspace_id IN (${workspacePlaceholders}) AND visibility = 'workspace')`
    : "";
  const rows = db.prepare(`
    SELECT *
    FROM audit_log
    WHERE user_id = ?
      OR actor_id = ?
      OR subject_id = ?
      ${workspaceClause}
    ORDER BY id ASC
  `).all(username, username, username, ...adminWorkspaceIds) as AuditRow[];

  return rows.map(mapAudit);
}

export function getAuditSummary() {
  const row = db.prepare(`
    SELECT
      COUNT(*) AS block_count,
      MIN(timestamp) AS first_timestamp,
      MAX(timestamp) AS latest_timestamp
    FROM audit_log
  `).get() as { block_count: number; first_timestamp: number | null; latest_timestamp: number | null };
  const first = db.prepare("SELECT hash FROM audit_log ORDER BY id ASC LIMIT 1").get() as { hash: string } | undefined;
  const latest = db.prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").get() as { hash: string } | undefined;

  return {
    blockCount: row.block_count,
    firstTimestamp: row.first_timestamp,
    latestTimestamp: row.latest_timestamp,
    firstHash: first?.hash || null,
    latestHash: latest?.hash || null
  };
}

function importLegacyState() {
  const userCount = db.prepare("SELECT COUNT(*) AS count FROM users").get() as { count: number };
  if (userCount.count > 0 || !fs.existsSync(LEGACY_STATE_FILE)) return;

  const raw = fs.readFileSync(LEGACY_STATE_FILE, "utf8");
  const state = JSON.parse(raw) as {
    database?: Record<string, UserRecord & { preKeys?: PreKeyRecord[]; inbox?: InboxRecord[] }>;
    auditLog?: AuditEntry[];
  };

  db.transaction(() => {
    for (const [username, user] of Object.entries(state.database || {})) {
      createUser(username, {
        salt: user.salt,
        authSalt: user.authSalt || "",
        authVerifierHash: user.authVerifierHash || "",
        identityPublicKeyECDH: user.identityPublicKeyECDH,
        identityPublicKeyECDSA: user.identityPublicKeyECDSA,
        encryptedPrivateKeyECDH: user.encryptedPrivateKeyECDH,
        ivECDH: user.ivECDH,
        encryptedPrivateKeyECDSA: user.encryptedPrivateKeyECDSA,
        ivECDSA: user.ivECDSA
      });
      addPreKeys(username, user.preKeys || []);
      for (const inboxFile of user.inbox || []) {
        addInboxFile(username, inboxFile);
      }
    }

    for (const entry of state.auditLog || []) {
      appendAuditEntry(entry);
    }
  })();

  console.log(`Imported legacy JSON state from ${LEGACY_STATE_FILE}`);
}

export async function backupDatabase(destination = path.join(BACKUP_DIR, `crypshare-${Date.now()}.db`)) {
  await db.backup(destination);
  return destination;
}

export async function checkDatabaseHealth() {
  db.prepare("SELECT 1 AS ok").get();
  return { driver: "sqlite" as const, ok: true };
}

export function closeDatabase() {
  db.close();
}

migrate();
importLegacyState();
