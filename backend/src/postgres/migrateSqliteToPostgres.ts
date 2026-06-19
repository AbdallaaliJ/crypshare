import fs from "fs";
import path from "path";
import Database from "better-sqlite3";
import { Pool } from "pg";

const databaseFile = process.env.DATABASE_FILE || path.join(__dirname, "../../data/crypshare.db");
const databaseUrl = process.env.DATABASE_URL;
const schemaFile = path.join(__dirname, "schema.sql");

type Row = Record<string, unknown>;

const tables = [
  {
    name: "schema_migrations",
    columns: ["version", "name", "applied_at"]
  },
  {
    name: "users",
    columns: [
      "username",
      "salt",
      "auth_salt",
      "auth_verifier_hash",
      "identity_public_key_ecdh",
      "identity_public_key_ecdsa",
      "encrypted_private_key_ecdh",
      "iv_ecdh",
      "encrypted_private_key_ecdsa",
      "iv_ecdsa",
      "created_at",
      "revoked_at",
      "revoked_reason",
      "role",
      "approved_at",
      "approved_by"
    ]
  },
  {
    name: "pre_keys",
    columns: ["username", "public_key_hex", "encrypted_private_key", "iv", "consumed", "created_at", "consumed_at"]
  },
  {
    name: "inbox_files",
    columns: [
      "recipient_username",
      "filepath",
      "original_filename",
      "file_size",
      "file_iv",
      "wrapped_file_key",
      "ephemeral_public_key",
      "used_pre_key",
      "sender_username",
      "signature",
      "encrypted_private_pre_key",
      "pre_key_iv",
      "timestamp"
    ]
  },
  {
    name: "vault_files",
    columns: [
      "id",
      "owner_username",
      "filepath",
      "file_size",
      "encrypted_metadata",
      "metadata_iv",
      "wrapped_file_key",
      "wrapped_file_key_iv",
      "created_at",
      "deleted_at"
    ]
  },
  {
    name: "vault_grants",
    columns: [
      "id",
      "vault_file_id",
      "owner_username",
      "recipient_username",
      "wrapped_file_key",
      "ephemeral_public_key",
      "used_pre_key",
      "signature",
      "encrypted_private_pre_key",
      "pre_key_iv",
      "created_at"
    ]
  },
  {
    name: "sessions",
    columns: ["token_hash", "id", "username", "created_at", "expires_at", "user_agent"]
  },
  {
    name: "workspaces",
    columns: ["id", "name", "invite_code", "invite_expires_at", "created_by", "created_at"]
  },
  {
    name: "workspace_members",
    columns: ["workspace_id", "username", "role", "status", "joined_at", "approved_at", "approved_by"]
  },
  {
    name: "audit_log",
    columns: [
      "timestamp",
      "user_id",
      "action",
      "previous_hash",
      "hash",
      "actor_id",
      "subject_id",
      "workspace_id",
      "visibility"
    ]
  }
];

function assertConfig() {
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required for PostgreSQL migration.");
  }
  if (!fs.existsSync(databaseFile)) {
    throw new Error(`SQLite database not found at ${databaseFile}`);
  }
  if (!fs.existsSync(schemaFile)) {
    throw new Error(`PostgreSQL schema file not found at ${schemaFile}`);
  }
}

function existingColumns(db: Database.Database, table: string) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Row[];
  return new Set(
    rows.map((row) => String(row.name))
  );
}

function rowsForTable(db: Database.Database, table: string, columns: string[]) {
  const columnSet = existingColumns(db, table);
  const selectedColumns = columns.filter((column) => columnSet.has(column));
  if (selectedColumns.length === 0) return { selectedColumns, rows: [] as Row[] };

  const quoted = selectedColumns.map((column) => `"${column}"`).join(", ");
  return {
    selectedColumns,
    rows: db.prepare(`SELECT ${quoted} FROM "${table}"`).all() as Row[]
  };
}

async function tableHasRows(pool: Pool, table: string) {
  const result = await pool.query(`SELECT EXISTS (SELECT 1 FROM "${table}" LIMIT 1) AS exists`);
  return Boolean(result.rows[0]?.exists);
}

async function insertRows(pool: Pool, table: string, columns: string[], rows: Row[]) {
  if (rows.length === 0 || columns.length === 0) return;

  const quotedColumns = columns.map((column) => `"${column}"`).join(", ");
  const placeholders = columns.map((_, index) => `$${index + 1}`).join(", ");
  const sql = `INSERT INTO "${table}" (${quotedColumns}) VALUES (${placeholders})`;

  for (const row of rows) {
    await pool.query(sql, columns.map((column) => row[column] ?? null));
  }
}

async function main() {
  assertConfig();

  const sqlite = new Database(databaseFile, { readonly: true });
  const pool = new Pool({ connectionString: databaseUrl });
  const truncateTarget = process.env.POSTGRES_MIGRATION_TRUNCATE === "true";

  try {
    await pool.query(fs.readFileSync(schemaFile, "utf8"));

    const populatedTables = [];
    for (const table of tables) {
      if (await tableHasRows(pool, table.name)) {
        populatedTables.push(table.name);
      }
    }

    if (populatedTables.length > 0) {
      if (!truncateTarget) {
        throw new Error(
          `PostgreSQL target is not empty: ${populatedTables.join(", ")}. Set POSTGRES_MIGRATION_TRUNCATE=true to replace it.`
        );
      }

      await pool.query(`TRUNCATE ${tables.map((table) => `"${table.name}"`).join(", ")} RESTART IDENTITY CASCADE`);
    }

    await pool.query("BEGIN");
    for (const table of tables) {
      const { selectedColumns, rows } = rowsForTable(sqlite, table.name, table.columns);
      await insertRows(pool, table.name, selectedColumns, rows);
      console.log(`Migrated ${rows.length} row(s) into ${table.name}`);
    }
    await pool.query("COMMIT");
  } catch (err) {
    await pool.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    sqlite.close();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
