-- CrypShare PostgreSQL target schema.
-- This mirrors the current SQLite schema and is used by the PostgreSQL runtime adapter.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
);

CREATE TABLE IF NOT EXISTS users (
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
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
  revoked_at BIGINT,
  revoked_reason TEXT,
  role TEXT NOT NULL DEFAULT 'member',
  approved_at BIGINT,
  approved_by TEXT
);

CREATE TABLE IF NOT EXISTS pre_keys (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  public_key_hex TEXT NOT NULL UNIQUE,
  encrypted_private_key TEXT NOT NULL,
  iv TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
  consumed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_pre_keys_username_consumed ON pre_keys(username, consumed, id);

CREATE TABLE IF NOT EXISTS inbox_files (
  id BIGSERIAL PRIMARY KEY,
  recipient_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  filepath TEXT NOT NULL UNIQUE,
  original_filename TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  file_iv TEXT NOT NULL,
  wrapped_file_key TEXT NOT NULL,
  ephemeral_public_key TEXT NOT NULL,
  used_pre_key TEXT NOT NULL,
  sender_username TEXT NOT NULL,
  signature TEXT NOT NULL,
  encrypted_private_pre_key TEXT,
  pre_key_iv TEXT,
  timestamp BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inbox_files_recipient_timestamp ON inbox_files(recipient_username, timestamp DESC);

CREATE TABLE IF NOT EXISTS vault_files (
  id TEXT PRIMARY KEY,
  owner_username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  filepath TEXT NOT NULL UNIQUE,
  file_size BIGINT NOT NULL,
  encrypted_metadata TEXT NOT NULL,
  metadata_iv TEXT NOT NULL,
  wrapped_file_key TEXT NOT NULL,
  wrapped_file_key_iv TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  deleted_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_vault_files_owner_created ON vault_files(owner_username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_files_owner_deleted_created ON vault_files(owner_username, deleted_at, created_at DESC);

CREATE TABLE IF NOT EXISTS vault_grants (
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
  created_at BIGINT NOT NULL,
  UNIQUE(vault_file_id, recipient_username)
);

CREATE INDEX IF NOT EXISTS idx_vault_grants_recipient_created ON vault_grants(recipient_username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_grants_owner_file ON vault_grants(owner_username, vault_file_id);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  user_agent TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_username_created ON sessions(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  invite_code TEXT NOT NULL UNIQUE,
  invite_expires_at BIGINT,
  created_by TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
  status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
  joined_at BIGINT NOT NULL,
  approved_at BIGINT,
  approved_by TEXT,
  PRIMARY KEY (workspace_id, username)
);

CREATE INDEX IF NOT EXISTS idx_workspace_members_username_status ON workspace_members(username, status);
CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace_status ON workspace_members(workspace_id, status);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  timestamp BIGINT NOT NULL,
  user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  actor_id TEXT,
  subject_id TEXT,
  workspace_id TEXT,
  visibility TEXT NOT NULL DEFAULT 'user'
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_subject ON audit_log(subject_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_workspace ON audit_log(workspace_id, timestamp);
