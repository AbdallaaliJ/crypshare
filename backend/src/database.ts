import type * as DatabaseAdapter from "./sqliteDatabase";

export type {
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
  WorkspaceMemberStatus,
  WorkspaceRecord,
  WorkspaceRole
} from "./sqliteDatabase";

export const DATABASE_DRIVER = (process.env.DATABASE_DRIVER || (process.env.DATABASE_URL ? "postgres" : "sqlite")).toLowerCase();

function loadAdapter(): typeof DatabaseAdapter {
  if (DATABASE_DRIVER === "postgres" || DATABASE_DRIVER === "postgresql") {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is required when DATABASE_DRIVER=postgres.");
    }
    return require("./postgresDatabase") as typeof DatabaseAdapter;
  }

  if (DATABASE_DRIVER !== "sqlite") {
    throw new Error(`Unsupported DATABASE_DRIVER "${DATABASE_DRIVER}". Use "sqlite" or "postgres".`);
  }

  return require("./sqliteDatabase") as typeof DatabaseAdapter;
}

const adapter = loadAdapter();

export const DATA_DIR = adapter.DATA_DIR;
export const DATABASE_FILE = adapter.DATABASE_FILE;
export const BACKUP_DIR = adapter.BACKUP_DIR;

export const getUser: typeof adapter.getUser = (...args) => adapter.getUser(...args);
export const createUser: typeof adapter.createUser = (...args) => adapter.createUser(...args);
export const listUsers: typeof adapter.listUsers = (...args) => adapter.listUsers(...args);
export const listDiscoverableUsers: typeof adapter.listDiscoverableUsers = (...args) => adapter.listDiscoverableUsers(...args);
export const countApprovedUsers: typeof adapter.countApprovedUsers = (...args) => adapter.countApprovedUsers(...args);
export const listPendingUsers: typeof adapter.listPendingUsers = (...args) => adapter.listPendingUsers(...args);
export const approveUser: typeof adapter.approveUser = (...args) => adapter.approveUser(...args);
export const revokeUser: typeof adapter.revokeUser = (...args) => adapter.revokeUser(...args);
export const createSessionRecord: typeof adapter.createSessionRecord = (...args) => adapter.createSessionRecord(...args);
export const getSessionByTokenHash: typeof adapter.getSessionByTokenHash = (...args) => adapter.getSessionByTokenHash(...args);
export const deleteSessionByTokenHash: typeof adapter.deleteSessionByTokenHash = (...args) => adapter.deleteSessionByTokenHash(...args);
export const deleteSessionById: typeof adapter.deleteSessionById = (...args) => adapter.deleteSessionById(...args);
export const deleteOtherSessions: typeof adapter.deleteOtherSessions = (...args) => adapter.deleteOtherSessions(...args);
export const deleteAllSessions: typeof adapter.deleteAllSessions = (...args) => adapter.deleteAllSessions(...args);
export const cleanupExpiredSessionRecords: typeof adapter.cleanupExpiredSessionRecords = (...args) => adapter.cleanupExpiredSessionRecords(...args);
export const createWorkspace: typeof adapter.createWorkspace = (...args) => adapter.createWorkspace(...args);
export const findWorkspaceById: typeof adapter.findWorkspaceById = (...args) => adapter.findWorkspaceById(...args);
export const findWorkspaceByInviteCode: typeof adapter.findWorkspaceByInviteCode = (...args) => adapter.findWorkspaceByInviteCode(...args);
export const listWorkspacesForUser: typeof adapter.listWorkspacesForUser = (...args) => adapter.listWorkspacesForUser(...args);
export const rotateWorkspaceInvite: typeof adapter.rotateWorkspaceInvite = (...args) => adapter.rotateWorkspaceInvite(...args);
export const getWorkspaceMembership: typeof adapter.getWorkspaceMembership = (...args) => adapter.getWorkspaceMembership(...args);
export const requestWorkspaceJoin: typeof adapter.requestWorkspaceJoin = (...args) => adapter.requestWorkspaceJoin(...args);
export const listWorkspaceMembers: typeof adapter.listWorkspaceMembers = (...args) => adapter.listWorkspaceMembers(...args);
export const listPendingWorkspaceMembers: typeof adapter.listPendingWorkspaceMembers = (...args) => adapter.listPendingWorkspaceMembers(...args);
export const approveWorkspaceMember: typeof adapter.approveWorkspaceMember = (...args) => adapter.approveWorkspaceMember(...args);
export const revokeWorkspaceMember: typeof adapter.revokeWorkspaceMember = (...args) => adapter.revokeWorkspaceMember(...args);
export const updateWorkspaceMemberRole: typeof adapter.updateWorkspaceMemberRole = (...args) => adapter.updateWorkspaceMemberRole(...args);
export const usersShareActiveWorkspace: typeof adapter.usersShareActiveWorkspace = (...args) => adapter.usersShareActiveWorkspace(...args);
export const listSessionRecords: typeof adapter.listSessionRecords = (...args) => adapter.listSessionRecords(...args);
export const addPreKeys: typeof adapter.addPreKeys = (...args) => adapter.addPreKeys(...args);
export const getPreKeyStatus: typeof adapter.getPreKeyStatus = (...args) => adapter.getPreKeyStatus(...args);
export const consumeNextPreKey: typeof adapter.consumeNextPreKey = (...args) => adapter.consumeNextPreKey(...args);
export const getPreKey: typeof adapter.getPreKey = (...args) => adapter.getPreKey(...args);
export const addInboxFile: typeof adapter.addInboxFile = (...args) => adapter.addInboxFile(...args);
export const listInbox: typeof adapter.listInbox = (...args) => adapter.listInbox(...args);
export const findInboxFile: typeof adapter.findInboxFile = (...args) => adapter.findInboxFile(...args);
export const addVaultFile: typeof adapter.addVaultFile = (...args) => adapter.addVaultFile(...args);
export const listVaultFiles: typeof adapter.listVaultFiles = (...args) => adapter.listVaultFiles(...args);
export const findVaultFile: typeof adapter.findVaultFile = (...args) => adapter.findVaultFile(...args);
export const getVaultStorageBytes: typeof adapter.getVaultStorageBytes = (...args) => adapter.getVaultStorageBytes(...args);
export const trashVaultFile: typeof adapter.trashVaultFile = (...args) => adapter.trashVaultFile(...args);
export const restoreVaultFile: typeof adapter.restoreVaultFile = (...args) => adapter.restoreVaultFile(...args);
export const updateVaultFileMetadata: typeof adapter.updateVaultFileMetadata = (...args) => adapter.updateVaultFileMetadata(...args);
export const permanentlyDeleteVaultFile: typeof adapter.permanentlyDeleteVaultFile = (...args) => adapter.permanentlyDeleteVaultFile(...args);
export const rotateVaultFile: typeof adapter.rotateVaultFile = (...args) => adapter.rotateVaultFile(...args);
export const addVaultGrant: typeof adapter.addVaultGrant = (...args) => adapter.addVaultGrant(...args);
export const listVaultGrantsForFile: typeof adapter.listVaultGrantsForFile = (...args) => adapter.listVaultGrantsForFile(...args);
export const listSharedVaultFiles: typeof adapter.listSharedVaultFiles = (...args) => adapter.listSharedVaultFiles(...args);
export const findSharedVaultFile: typeof adapter.findSharedVaultFile = (...args) => adapter.findSharedVaultFile(...args);
export const findVaultFileById: typeof adapter.findVaultFileById = (...args) => adapter.findVaultFileById(...args);
export const getLastAuditHash: typeof adapter.getLastAuditHash = (...args) => adapter.getLastAuditHash(...args);
export const appendAuditEntry: typeof adapter.appendAuditEntry = (...args) => adapter.appendAuditEntry(...args);
export const getAuditLog: typeof adapter.getAuditLog = (...args) => adapter.getAuditLog(...args);
export const getVisibleAuditLog: typeof adapter.getVisibleAuditLog = (...args) => adapter.getVisibleAuditLog(...args);
export const getAuditSummary: typeof adapter.getAuditSummary = (...args) => adapter.getAuditSummary(...args);
export const backupDatabase: typeof adapter.backupDatabase = (...args) => adapter.backupDatabase(...args);
export const checkDatabaseHealth: typeof adapter.checkDatabaseHealth = (...args) => adapter.checkDatabaseHealth(...args);
export const closeDatabase: typeof adapter.closeDatabase = (...args) => adapter.closeDatabase(...args);
