import fs from "fs";
import path from "path";
import { Pool, type PoolClient, type QueryResultRow, types } from "pg";
import type {
  AuditEntry,
  InboxRecord,
  PreKeyRecord,
  SessionRecord,
  SharedVaultFileRecord,
  UserRecord,
  VaultFileRecord,
  VaultGrantRecord,
  VaultGrantSignatureUpdate,
  WorkspaceMemberRecord,
  WorkspaceRecord,
  WorkspaceRole
} from "./sqliteDatabase";

types.setTypeParser(20, (value) => Number(value));

export const DATA_DIR = path.join(__dirname, "../data");
export const DATABASE_FILE = process.env.DATABASE_FILE || path.join(DATA_DIR, "crypshare.db");
export const BACKUP_DIR = path.join(DATA_DIR, "backups");

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required for PostgreSQL runtime.");
}

const pool = new Pool({ connectionString: databaseUrl });

function schemaPath() {
  const candidates = [
    path.join(__dirname, "postgres", "schema.sql"),
    path.join(__dirname, "../../src/postgres/schema.sql"),
    path.join(process.cwd(), "src/postgres/schema.sql")
  ];
  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (!found) throw new Error("PostgreSQL schema.sql not found.");
  return found;
}

const ready = pool.query(fs.readFileSync(schemaPath(), "utf8"));

async function query<T extends QueryResultRow = QueryResultRow>(text: string, params: unknown[] = []) {
  await ready;
  return pool.query<T>(text, params);
}

async function withTransaction<T>(fn: (client: PoolClient) => Promise<T>) {
  await ready;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

function mapUser(row: any): UserRecord {
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

function mapPreKey(row: any): PreKeyRecord {
  return {
    publicKeyHex: row.public_key_hex,
    encryptedPrivateKey: row.encrypted_private_key,
    iv: row.iv,
    consumed: row.consumed === 1 || row.consumed === true
  };
}

function mapInbox(row: any): InboxRecord {
  return {
    filepath: row.filepath,
    originalFilename: row.original_filename,
    fileSize: Number(row.file_size),
    fileIv: row.file_iv,
    wrappedFileKey: row.wrapped_file_key,
    ephemeralPublicKey: row.ephemeral_public_key,
    usedPreKey: row.used_pre_key,
    senderUsername: row.sender_username,
    signature: row.signature,
    encryptedPrivatePreKey: row.encrypted_private_pre_key,
    preKeyIv: row.pre_key_iv,
    timestamp: Number(row.timestamp)
  };
}

function mapAudit(row: any): AuditEntry {
  return {
    timestamp: Number(row.timestamp),
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

function mapVaultFile(row: any): VaultFileRecord {
  return {
    id: row.id,
    filepath: row.filepath,
    fileSize: Number(row.file_size),
    encryptedMetadata: row.encrypted_metadata,
    metadataIv: row.metadata_iv,
    wrappedFileKey: row.wrapped_file_key,
    wrappedFileKeyIv: row.wrapped_file_key_iv,
    createdAt: Number(row.created_at),
    deletedAt: row.deleted_at === null ? null : Number(row.deleted_at),
    sharedWithCount: row.shared_with_count === undefined ? undefined : Number(row.shared_with_count)
  };
}

function mapVaultGrant(row: any): VaultGrantRecord {
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
    createdAt: Number(row.created_at)
  };
}

function mapSharedVaultFile(row: any): SharedVaultFileRecord {
  return {
    ...mapVaultGrant(row),
    fileSize: Number(row.file_size),
    encryptedMetadata: row.encrypted_metadata,
    metadataIv: row.metadata_iv,
    ownerIdentityPublicKeyECDH: row.owner_identity_public_key_ecdh,
    ownerIdentityPublicKeyECDSA: row.owner_identity_public_key_ecdsa
  };
}

function mapSession(row: any): SessionRecord {
  return {
    id: row.id,
    username: row.username,
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    userAgent: row.user_agent
  };
}

function mapWorkspace(row: any): WorkspaceRecord {
  const createdAt = Number(row.created_at);
  return {
    id: row.id,
    name: row.name,
    inviteCode: row.invite_code,
    inviteExpiresAt: row.invite_expires_at ? Number(row.invite_expires_at) : createdAt + 604800000,
    createdBy: row.created_by,
    createdAt,
    role: row.role,
    status: row.status,
    memberCount: row.member_count === undefined ? undefined : Number(row.member_count),
    pendingCount: row.pending_count === undefined ? undefined : Number(row.pending_count)
  };
}

function mapWorkspaceMember(row: any): WorkspaceMemberRecord {
  return {
    workspaceId: row.workspace_id,
    username: row.username,
    role: row.role,
    status: row.status,
    joinedAt: Number(row.joined_at),
    approvedAt: row.approved_at === null ? null : Number(row.approved_at),
    approvedBy: row.approved_by,
    identityPublicKeyECDH: row.identity_public_key_ecdh,
    identityPublicKeyECDSA: row.identity_public_key_ecdsa
  };
}

async function getWorkspaceMembershipWithClient(client: PoolClient, workspaceId: string, username: string) {
  const result = await client.query(`
    SELECT wm.workspace_id, wm.username, wm.role, wm.status, wm.joined_at, wm.approved_at, wm.approved_by,
           users.identity_public_key_ecdh, users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = $1 AND wm.username = $2
  `, [workspaceId, username]);

  return result.rows[0] ? mapWorkspaceMember(result.rows[0]) : null;
}

async function findVaultFileWithClient(client: PoolClient, ownerUsername: string, id: string, includeTrashed = false) {
  const result = await client.query(`
    SELECT *
    FROM vault_files
    WHERE owner_username = $1 AND id = $2
      AND ($3::integer = 1 OR deleted_at IS NULL)
  `, [ownerUsername, id, includeTrashed ? 1 : 0]);

  return result.rows[0] ? mapVaultFile(result.rows[0]) : null;
}

export async function getUser(username: string) {
  const result = await query("SELECT * FROM users WHERE username = $1", [username]);
  return result.rows[0] ? mapUser(result.rows[0]) : null;
}

export async function createUser(username: string, user: UserRecord) {
  await query(`
    INSERT INTO users (
      username, salt, auth_salt, auth_verifier_hash, identity_public_key_ecdh,
      identity_public_key_ecdsa, encrypted_private_key_ecdh, iv_ecdh,
      encrypted_private_key_ecdsa, iv_ecdsa, role, approved_at, approved_by
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
  `, [
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
  ]);
}

export async function listUsers() {
  const result = await query(`
    SELECT username, identity_public_key_ecdh, identity_public_key_ecdsa
    FROM users
    WHERE revoked_at IS NULL AND approved_at IS NOT NULL
    ORDER BY username ASC
  `);
  return result.rows;
}

export async function listDiscoverableUsers(username: string) {
  const result = await query(`
    SELECT DISTINCT u.username, u.identity_public_key_ecdh, u.identity_public_key_ecdsa
    FROM users u
    WHERE u.revoked_at IS NULL
      AND (
        u.username = $1
        OR EXISTS (
          SELECT 1
          FROM workspace_members mine
          JOIN workspace_members theirs ON theirs.workspace_id = mine.workspace_id
          WHERE mine.username = $2
            AND mine.status = 'active'
            AND theirs.username = u.username
            AND theirs.status = 'active'
        )
      )
    ORDER BY u.username ASC
  `, [username, username]);
  return result.rows;
}

export async function countApprovedUsers() {
  const result = await query("SELECT COUNT(*) AS count FROM users WHERE approved_at IS NOT NULL AND revoked_at IS NULL");
  return Number(result.rows[0]?.count || 0);
}

export async function listPendingUsers() {
  const result = await query(`
    SELECT username, identity_public_key_ecdh, identity_public_key_ecdsa
    FROM users
    WHERE revoked_at IS NULL AND approved_at IS NULL
    ORDER BY username ASC
  `);
  return result.rows;
}

export async function approveUser(username: string, approvedBy: string) {
  const approvedAt = Date.now();
  const result = await query(`
    UPDATE users
    SET approved_at = $1, approved_by = $2
    WHERE username = $3 AND revoked_at IS NULL AND approved_at IS NULL
  `, [approvedAt, approvedBy, username]);
  return result.rowCount && result.rowCount > 0 ? { approvedAt, approvedBy } : null;
}

export async function revokeUser(username: string, reason: string) {
  const revokedAt = Date.now();
  const result = await query(`
    UPDATE users
    SET revoked_at = $1, revoked_reason = $2
    WHERE username = $3 AND revoked_at IS NULL
  `, [revokedAt, reason, username]);
  return result.rowCount && result.rowCount > 0 ? { revokedAt, reason } : null;
}

export async function createSessionRecord(tokenHash: string, session: SessionRecord) {
  await query(`
    INSERT INTO sessions (token_hash, id, username, created_at, expires_at, user_agent)
    VALUES ($1, $2, $3, $4, $5, $6)
  `, [tokenHash, session.id, session.username, session.createdAt, session.expiresAt, session.userAgent]);
}

export async function getSessionByTokenHash(tokenHash: string) {
  const result = await query(`
    SELECT id, username, created_at, expires_at, user_agent
    FROM sessions
    WHERE token_hash = $1
  `, [tokenHash]);
  return result.rows[0] ? mapSession(result.rows[0]) : null;
}

export async function deleteSessionByTokenHash(tokenHash: string) {
  const result = await query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
  return Boolean(result.rowCount && result.rowCount > 0);
}

export async function deleteSessionById(username: string, sessionId: string) {
  const result = await query("DELETE FROM sessions WHERE username = $1 AND id = $2", [username, sessionId]);
  return Boolean(result.rowCount && result.rowCount > 0);
}

export async function deleteOtherSessions(username: string, currentSessionId: string) {
  const result = await query("DELETE FROM sessions WHERE username = $1 AND id <> $2", [username, currentSessionId]);
  return result.rowCount || 0;
}

export async function deleteAllSessions(username: string) {
  const result = await query("DELETE FROM sessions WHERE username = $1", [username]);
  return result.rowCount || 0;
}

export async function cleanupExpiredSessionRecords(now = Date.now()) {
  const result = await query("DELETE FROM sessions WHERE expires_at < $1", [now]);
  return result.rowCount || 0;
}

export async function createWorkspace(workspace: WorkspaceRecord, ownerUsername: string) {
  return withTransaction(async (client) => {
    await client.query(`
      INSERT INTO workspaces (id, name, invite_code, invite_expires_at, created_by, created_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [workspace.id, workspace.name, workspace.inviteCode, workspace.inviteExpiresAt, ownerUsername, workspace.createdAt]);
    await client.query(`
      INSERT INTO workspace_members (workspace_id, username, role, status, joined_at, approved_at, approved_by)
      VALUES ($1, $2, 'owner', 'active', $3, $4, $5)
    `, [workspace.id, ownerUsername, workspace.createdAt, workspace.createdAt, ownerUsername]);
    return getWorkspaceMembershipWithClient(client, workspace.id, ownerUsername);
  });
}

export async function findWorkspaceById(workspaceId: string) {
  const result = await query(`
    SELECT id, name, invite_code, invite_expires_at, created_by, created_at
    FROM workspaces
    WHERE id = $1
  `, [workspaceId]);
  return result.rows[0] ? mapWorkspace(result.rows[0]) : null;
}

export async function findWorkspaceByInviteCode(inviteCode: string) {
  const result = await query(`
    SELECT id, name, invite_code, invite_expires_at, created_by, created_at
    FROM workspaces
    WHERE invite_code = $1
  `, [inviteCode]);
  return result.rows[0] ? mapWorkspace(result.rows[0]) : null;
}

export async function listWorkspacesForUser(username: string) {
  const result = await query(`
    SELECT w.id, w.name, w.invite_code, w.invite_expires_at, w.created_by, w.created_at,
           wm.role, wm.status,
           (SELECT COUNT(*) FROM workspace_members active_members WHERE active_members.workspace_id = w.id AND active_members.status = 'active') AS member_count,
           (SELECT COUNT(*) FROM workspace_members pending_members WHERE pending_members.workspace_id = w.id AND pending_members.status = 'pending') AS pending_count
    FROM workspaces w
    JOIN workspace_members wm ON wm.workspace_id = w.id
    WHERE wm.username = $1 AND wm.status <> 'revoked'
    ORDER BY w.created_at DESC
  `, [username]);
  return result.rows.map(mapWorkspace);
}

export async function rotateWorkspaceInvite(workspaceId: string, inviteCode: string, inviteExpiresAt: number) {
  const result = await query(`
    UPDATE workspaces
    SET invite_code = $1, invite_expires_at = $2
    WHERE id = $3
  `, [inviteCode, inviteExpiresAt, workspaceId]);
  return result.rowCount && result.rowCount > 0 ? findWorkspaceById(workspaceId) : null;
}

export async function getWorkspaceMembership(workspaceId: string, username: string) {
  const result = await query(`
    SELECT wm.workspace_id, wm.username, wm.role, wm.status, wm.joined_at, wm.approved_at, wm.approved_by,
           users.identity_public_key_ecdh, users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = $1 AND wm.username = $2
  `, [workspaceId, username]);
  return result.rows[0] ? mapWorkspaceMember(result.rows[0]) : null;
}

export async function requestWorkspaceJoin(workspaceId: string, username: string) {
  return withTransaction(async (client) => {
    const existing = await getWorkspaceMembershipWithClient(client, workspaceId, username);
    if (existing?.status === "active" || existing?.status === "pending") return existing;

    const joinedAt = Date.now();
    if (existing?.status === "revoked") {
      await client.query(`
        UPDATE workspace_members
        SET role = 'member', status = 'pending', joined_at = $1, approved_at = NULL, approved_by = NULL
        WHERE workspace_id = $2 AND username = $3
      `, [joinedAt, workspaceId, username]);
    } else {
      await client.query(`
        INSERT INTO workspace_members (workspace_id, username, role, status, joined_at, approved_at, approved_by)
        VALUES ($1, $2, 'member', 'pending', $3, NULL, NULL)
      `, [workspaceId, username, joinedAt]);
    }

    return getWorkspaceMembershipWithClient(client, workspaceId, username);
  });
}

export async function listWorkspaceMembers(workspaceId: string) {
  const result = await query(`
    SELECT wm.workspace_id, wm.username, wm.role, wm.status, wm.joined_at, wm.approved_at, wm.approved_by,
           users.identity_public_key_ecdh, users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = $1 AND wm.status = 'active' AND users.revoked_at IS NULL
    ORDER BY wm.role ASC, wm.username ASC
  `, [workspaceId]);
  return result.rows.map(mapWorkspaceMember);
}

export async function listPendingWorkspaceMembers(workspaceId: string) {
  const result = await query(`
    SELECT wm.workspace_id, wm.username, wm.role, wm.status, wm.joined_at, wm.approved_at, wm.approved_by,
           users.identity_public_key_ecdh, users.identity_public_key_ecdsa
    FROM workspace_members wm
    JOIN users ON users.username = wm.username
    WHERE wm.workspace_id = $1 AND wm.status = 'pending' AND users.revoked_at IS NULL
    ORDER BY wm.joined_at ASC
  `, [workspaceId]);
  return result.rows.map(mapWorkspaceMember);
}

export async function approveWorkspaceMember(workspaceId: string, username: string, approvedBy: string) {
  const approvedAt = Date.now();
  const result = await query(`
    UPDATE workspace_members
    SET status = 'active',
        role = CASE WHEN role = 'owner' THEN 'owner' ELSE 'member' END,
        approved_at = $1,
        approved_by = $2
    WHERE workspace_id = $3 AND username = $4 AND status = 'pending'
  `, [approvedAt, approvedBy, workspaceId, username]);
  return result.rowCount && result.rowCount > 0 ? getWorkspaceMembership(workspaceId, username) : null;
}

export async function revokeWorkspaceMember(workspaceId: string, username: string) {
  const result = await query(`
    UPDATE workspace_members
    SET status = 'revoked'
    WHERE workspace_id = $1 AND username = $2 AND status = 'active' AND role <> 'owner'
  `, [workspaceId, username]);
  return Boolean(result.rowCount && result.rowCount > 0);
}

export async function updateWorkspaceMemberRole(workspaceId: string, username: string, role: Exclude<WorkspaceRole, "owner">) {
  const result = await query(`
    UPDATE workspace_members
    SET role = $1
    WHERE workspace_id = $2 AND username = $3 AND status = 'active' AND role <> 'owner'
  `, [role, workspaceId, username]);
  return result.rowCount && result.rowCount > 0 ? getWorkspaceMembership(workspaceId, username) : null;
}

export async function usersShareActiveWorkspace(firstUsername: string, secondUsername: string) {
  const result = await query(`
    SELECT COUNT(*) AS count
    FROM workspace_members first_member
    JOIN workspace_members second_member ON second_member.workspace_id = first_member.workspace_id
    WHERE first_member.username = $1
      AND second_member.username = $2
      AND first_member.status = 'active'
      AND second_member.status = 'active'
  `, [firstUsername, secondUsername]);
  return Number(result.rows[0]?.count || 0) > 0;
}

export async function listSessionRecords(username: string, currentSessionId: string) {
  await cleanupExpiredSessionRecords();
  const result = await query(`
    SELECT id, username, created_at, expires_at, user_agent
    FROM sessions
    WHERE username = $1
    ORDER BY created_at DESC
  `, [username]);
  return result.rows.map((session) => ({
    ...mapSession(session),
    current: session.id === currentSessionId
  }));
}

export async function addPreKeys(username: string, preKeys: PreKeyRecord[]) {
  await withTransaction(async (client) => {
    for (const preKey of preKeys) {
      await client.query(`
        INSERT INTO pre_keys (username, public_key_hex, encrypted_private_key, iv)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (public_key_hex) DO NOTHING
      `, [username, preKey.publicKeyHex, preKey.encryptedPrivateKey, preKey.iv]);
    }
  });
}

export async function getPreKeyStatus(username: string) {
  const result = await query(`
    SELECT COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN consumed = 0 THEN 1 ELSE 0 END), 0) AS available,
           COALESCE(SUM(CASE WHEN consumed = 1 THEN 1 ELSE 0 END), 0) AS consumed
    FROM pre_keys
    WHERE username = $1
  `, [username]);
  return {
    total: Number(result.rows[0]?.total || 0),
    available: Number(result.rows[0]?.available || 0),
    consumed: Number(result.rows[0]?.consumed || 0)
  };
}

export async function consumeNextPreKey(username: string) {
  return withTransaction(async (client) => {
    const result = await client.query(`
      SELECT public_key_hex, encrypted_private_key, iv, consumed
      FROM pre_keys
      WHERE username = $1 AND consumed = 0
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    `, [username]);
    const row = result.rows[0];
    if (!row) return null;

    await client.query(`
      UPDATE pre_keys
      SET consumed = 1, consumed_at = $1
      WHERE username = $2 AND public_key_hex = $3
    `, [Date.now(), username, row.public_key_hex]);
    return mapPreKey(row);
  });
}

export async function getPreKey(username: string, publicKeyHex: string) {
  const result = await query(`
    SELECT public_key_hex, encrypted_private_key, iv, consumed
    FROM pre_keys
    WHERE username = $1 AND public_key_hex = $2
  `, [username, publicKeyHex]);
  return result.rows[0] ? mapPreKey(result.rows[0]) : null;
}

export async function addInboxFile(recipientUsername: string, file: InboxRecord) {
  await query(`
    INSERT INTO inbox_files (
      recipient_username, filepath, original_filename, file_size, file_iv,
      wrapped_file_key, ephemeral_public_key, used_pre_key, sender_username,
      signature, encrypted_private_pre_key, pre_key_iv, timestamp
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
  `, [
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
  ]);
}

export async function listInbox(username: string) {
  const result = await query(`
    SELECT *
    FROM inbox_files
    WHERE recipient_username = $1
    ORDER BY timestamp DESC
  `, [username]);
  return result.rows.map(mapInbox);
}

export async function findInboxFile(username: string, filepath: string) {
  const result = await query(`
    SELECT *
    FROM inbox_files
    WHERE recipient_username = $1 AND filepath = $2
  `, [username, filepath]);
  return result.rows[0] ? mapInbox(result.rows[0]) : null;
}

export async function addVaultFile(ownerUsername: string, file: VaultFileRecord) {
  await query(`
    INSERT INTO vault_files (
      id, owner_username, filepath, file_size, encrypted_metadata, metadata_iv,
      wrapped_file_key, wrapped_file_key_iv, created_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  `, [
    file.id,
    ownerUsername,
    file.filepath,
    file.fileSize,
    file.encryptedMetadata,
    file.metadataIv,
    file.wrappedFileKey,
    file.wrappedFileKeyIv,
    file.createdAt
  ]);
}

export async function listVaultFiles(ownerUsername: string, options: { trashed?: boolean } = {}) {
  const result = await query(`
    SELECT files.*,
           (SELECT COUNT(*) FROM vault_grants grants WHERE grants.vault_file_id = files.id) AS shared_with_count
    FROM vault_files files
    WHERE files.owner_username = $1
      AND ${options.trashed ? "files.deleted_at IS NOT NULL" : "files.deleted_at IS NULL"}
    ORDER BY files.created_at DESC
  `, [ownerUsername]);
  return result.rows.map(mapVaultFile);
}

export async function findVaultFile(ownerUsername: string, id: string, options: { includeTrashed?: boolean } = {}) {
  const result = await query(`
    SELECT *
    FROM vault_files
    WHERE owner_username = $1 AND id = $2
      AND ($3::integer = 1 OR deleted_at IS NULL)
  `, [ownerUsername, id, options.includeTrashed ? 1 : 0]);
  return result.rows[0] ? mapVaultFile(result.rows[0]) : null;
}

export async function getVaultStorageBytes(ownerUsername: string) {
  const result = await query(`
    SELECT COALESCE(SUM(file_size), 0) AS total
    FROM vault_files
    WHERE owner_username = $1
  `, [ownerUsername]);
  return Number(result.rows[0]?.total || 0);
}

export async function trashVaultFile(ownerUsername: string, id: string) {
  const deletedAt = Date.now();
  const result = await query(`
    UPDATE vault_files
    SET deleted_at = $1
    WHERE owner_username = $2 AND id = $3 AND deleted_at IS NULL
  `, [deletedAt, ownerUsername, id]);
  return result.rowCount && result.rowCount > 0 ? findVaultFile(ownerUsername, id, { includeTrashed: true }) : null;
}

export async function restoreVaultFile(ownerUsername: string, id: string) {
  const result = await query(`
    UPDATE vault_files
    SET deleted_at = NULL
    WHERE owner_username = $1 AND id = $2 AND deleted_at IS NOT NULL
  `, [ownerUsername, id]);
  return result.rowCount && result.rowCount > 0 ? findVaultFile(ownerUsername, id) : null;
}

export async function updateVaultFileMetadata(
  ownerUsername: string,
  id: string,
  encryptedMetadata: string,
  metadataIv: string,
  grantSignatures: VaultGrantSignatureUpdate[]
) {
  return withTransaction(async (client) => {
    const existing = await findVaultFileWithClient(client, ownerUsername, id);
    if (!existing) return null;

    await client.query(`
      UPDATE vault_files
      SET encrypted_metadata = $1, metadata_iv = $2
      WHERE owner_username = $3 AND id = $4 AND deleted_at IS NULL
    `, [encryptedMetadata, metadataIv, ownerUsername, id]);

    for (const grantSignature of grantSignatures) {
      await client.query(`
        UPDATE vault_grants
        SET signature = $1
        WHERE owner_username = $2 AND vault_file_id = $3 AND id = $4
      `, [grantSignature.signature, ownerUsername, id, grantSignature.grantId]);
    }

    return findVaultFileWithClient(client, ownerUsername, id);
  });
}

export async function permanentlyDeleteVaultFile(ownerUsername: string, id: string) {
  const row = await findVaultFile(ownerUsername, id, { includeTrashed: true });
  if (!row) return null;
  await query("DELETE FROM vault_files WHERE owner_username = $1 AND id = $2", [ownerUsername, id]);
  return row;
}

export async function rotateVaultFile(
  ownerUsername: string,
  file: VaultFileRecord,
  replacementGrants: VaultGrantRecord[]
) {
  return withTransaction(async (client) => {
    const existing = await findVaultFileWithClient(client, ownerUsername, file.id);
    if (!existing) return null;

    await client.query(`
      UPDATE vault_files
      SET filepath = $1,
          file_size = $2,
          encrypted_metadata = $3,
          metadata_iv = $4,
          wrapped_file_key = $5,
          wrapped_file_key_iv = $6
      WHERE owner_username = $7 AND id = $8
    `, [
      file.filepath,
      file.fileSize,
      file.encryptedMetadata,
      file.metadataIv,
      file.wrappedFileKey,
      file.wrappedFileKeyIv,
      ownerUsername,
      file.id
    ]);

    await client.query("DELETE FROM vault_grants WHERE owner_username = $1 AND vault_file_id = $2", [ownerUsername, file.id]);

    for (const grant of replacementGrants) {
      await client.query(`
        INSERT INTO vault_grants (
          id, vault_file_id, owner_username, recipient_username, wrapped_file_key,
          ephemeral_public_key, used_pre_key, signature, encrypted_private_pre_key,
          pre_key_iv, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      `, [
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
      ]);
    }

    return existing;
  });
}

export async function addVaultGrant(grant: VaultGrantRecord) {
  await query(`
    INSERT INTO vault_grants (
      id, vault_file_id, owner_username, recipient_username, wrapped_file_key,
      ephemeral_public_key, used_pre_key, signature, encrypted_private_pre_key,
      pre_key_iv, created_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `, [
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
  ]);
}

export async function listVaultGrantsForFile(ownerUsername: string, vaultFileId: string) {
  const result = await query(`
    SELECT *
    FROM vault_grants
    WHERE owner_username = $1 AND vault_file_id = $2
    ORDER BY created_at DESC
  `, [ownerUsername, vaultFileId]);
  return result.rows.map(mapVaultGrant);
}

export async function listSharedVaultFiles(recipientUsername: string) {
  const result = await query(`
    SELECT grants.*, files.file_size, files.encrypted_metadata, files.metadata_iv,
           users.identity_public_key_ecdh AS owner_identity_public_key_ecdh,
           users.identity_public_key_ecdsa AS owner_identity_public_key_ecdsa
    FROM vault_grants grants
    JOIN vault_files files ON files.id = grants.vault_file_id
    JOIN users ON users.username = grants.owner_username
    WHERE grants.recipient_username = $1
      AND users.revoked_at IS NULL
      AND files.deleted_at IS NULL
    ORDER BY grants.created_at DESC
  `, [recipientUsername]);
  return result.rows.map(mapSharedVaultFile);
}

export async function findSharedVaultFile(recipientUsername: string, grantId: string) {
  const result = await query(`
    SELECT grants.*, files.file_size, files.encrypted_metadata, files.metadata_iv,
           users.identity_public_key_ecdh AS owner_identity_public_key_ecdh,
           users.identity_public_key_ecdsa AS owner_identity_public_key_ecdsa
    FROM vault_grants grants
    JOIN vault_files files ON files.id = grants.vault_file_id
    JOIN users ON users.username = grants.owner_username
    WHERE grants.recipient_username = $1
      AND grants.id = $2
      AND users.revoked_at IS NULL
      AND files.deleted_at IS NULL
  `, [recipientUsername, grantId]);
  return result.rows[0] ? mapSharedVaultFile(result.rows[0]) : null;
}

export async function findVaultFileById(id: string) {
  const result = await query("SELECT * FROM vault_files WHERE id = $1 AND deleted_at IS NULL", [id]);
  return result.rows[0] ? mapVaultFile(result.rows[0]) : null;
}

export async function getLastAuditHash() {
  const result = await query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1");
  return result.rows[0]?.hash || null;
}

export async function appendAuditEntry(entry: AuditEntry) {
  await query(`
    INSERT INTO audit_log (
      timestamp, user_id, action, previous_hash, hash, actor_id, subject_id, workspace_id, visibility
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  `, [
    entry.timestamp,
    entry.userId,
    entry.action,
    entry.previousHash,
    entry.hash,
    entry.actorId || entry.userId,
    entry.subjectId || entry.userId,
    entry.workspaceId || null,
    entry.visibility || "user"
  ]);
}

export async function getAuditLog() {
  const result = await query("SELECT * FROM audit_log ORDER BY id ASC");
  return result.rows.map(mapAudit);
}

export async function getVisibleAuditLog(username: string, adminWorkspaceIds: string[]) {
  const workspacePlaceholders = adminWorkspaceIds.map((_, index) => `$${index + 4}`).join(",");
  const workspaceClause = workspacePlaceholders
    ? `OR (workspace_id IN (${workspacePlaceholders}) AND visibility = 'workspace')`
    : "";
  const result = await query(`
    SELECT *
    FROM audit_log
    WHERE user_id = $1
      OR actor_id = $2
      OR subject_id = $3
      ${workspaceClause}
    ORDER BY id ASC
  `, [username, username, username, ...adminWorkspaceIds]);
  return result.rows.map(mapAudit);
}

export async function getAuditSummary() {
  const rowResult = await query(`
    SELECT COUNT(*) AS block_count, MIN(timestamp) AS first_timestamp, MAX(timestamp) AS latest_timestamp
    FROM audit_log
  `);
  const first = await query("SELECT hash FROM audit_log ORDER BY id ASC LIMIT 1");
  const latest = await query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1");
  const row = rowResult.rows[0];

  return {
    blockCount: Number(row?.block_count || 0),
    firstTimestamp: row?.first_timestamp ?? null,
    latestTimestamp: row?.latest_timestamp ?? null,
    firstHash: first.rows[0]?.hash || null,
    latestHash: latest.rows[0]?.hash || null
  };
}

export async function backupDatabase() {
  throw new Error("PostgreSQL runtime backups should use pg_dump or managed database snapshots.");
}

export async function checkDatabaseHealth() {
  await query("SELECT 1 AS ok");
  return { driver: "postgres" as const, ok: true };
}

export async function closeDatabase() {
  await pool.end();
}
