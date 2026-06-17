import express from "express";
import cors from "cors";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";
import http from "http";
import { WebSocketServer, type WebSocket } from "ws";
import {
  addInboxFile,
  addPreKeys,
  addVaultFile,
  addVaultGrant,
  appendAuditEntry,
  approveWorkspaceMember,
  cleanupExpiredSessionRecords,
  consumeNextPreKey,
  approveUser,
  countApprovedUsers,
  createSessionRecord,
  createUser,
  createWorkspace,
  deleteAllSessions,
  deleteOtherSessions,
  deleteSessionById,
  deleteSessionByTokenHash,
  findWorkspaceById,
  findWorkspaceByInviteCode,
  findInboxFile,
  findSharedVaultFile,
  findVaultFile,
  findVaultFileById,
  getLastAuditHash,
  getVisibleAuditLog,
  getPreKey,
  getPreKeyStatus,
  getSessionByTokenHash,
  getUser,
  getVaultStorageBytes,
  getWorkspaceMembership,
  listInbox,
  listDiscoverableUsers,
  listPendingUsers,
  listSessionRecords,
  listSharedVaultFiles,
  listPendingWorkspaceMembers,
  listWorkspaceMembers,
  listWorkspacesForUser,
  listVaultGrantsForFile,
  listVaultFiles,
  requestWorkspaceJoin,
  rotateWorkspaceInvite,
  permanentlyDeleteVaultFile,
  restoreVaultFile,
  revokeWorkspaceMember,
  revokeUser,
  rotateVaultFile,
  trashVaultFile,
  updateVaultFileMetadata,
  updateWorkspaceMemberRole,
  usersShareActiveWorkspace
} from "./database";
import type { InboxRecord, SessionRecord, UserRecord, VaultFileRecord, VaultGrantRecord, VaultGrantSignatureUpdate, WorkspaceMemberRecord } from "./database";

const NODE_ENV = process.env.NODE_ENV || "development";
const PUBLIC_DEPLOYMENT = process.env.CRYPSHARE_PUBLIC_DEPLOYMENT === "true" || NODE_ENV === "production";
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, "../uploads");
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "256kb";
const DEFAULT_UPLOAD_FILE_LIMIT_BYTES = 15 * 1024 * 1024 * 1024;
const UPLOAD_FILE_LIMIT_BYTES = Number(process.env.UPLOAD_FILE_LIMIT_BYTES || DEFAULT_UPLOAD_FILE_LIMIT_BYTES);
const UPLOAD_FIELD_LIMIT_BYTES = Number(process.env.UPLOAD_FIELD_LIMIT_BYTES || 1024 * 256);
const VAULT_CHUNK_UPLOAD_LIMIT_BYTES = Number(process.env.VAULT_CHUNK_UPLOAD_LIMIT_BYTES || 8 * 1024 * 1024);
const VAULT_UPLOAD_SESSION_TTL_MS = Math.max(Number(process.env.VAULT_UPLOAD_SESSION_TTL_MS || 1000 * 60 * 60 * 4), 1000 * 60 * 10);
const USER_STORAGE_QUOTA_BYTES = Number(process.env.USER_STORAGE_QUOTA_BYTES || 100 * 1024 * 1024 * 1024);
const GENERAL_RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 1000 * 60);
const GENERAL_RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 600);
const AUTH_RATE_LIMIT_WINDOW_MS = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 1000 * 60 * 5);
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX || 30);
const WORKSPACE_INVITE_TTL_MS = Math.max(Number(process.env.WORKSPACE_INVITE_TTL_MS || 1000 * 60 * 60 * 24 * 7), 1000 * 60 * 5);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 8);
const SESSION_COOKIE_ENABLED = process.env.SESSION_COOKIE_ENABLED === "true";
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "__Host-crypshare_session";
const CSRF_COOKIE_NAME = process.env.CSRF_COOKIE_NAME || "__Host-crypshare_csrf";
const CSRF_HEADER_NAME = (process.env.CSRF_HEADER_NAME || "x-csrf-token").toLowerCase();
const SESSION_COOKIE_SECRET = process.env.SESSION_COOKIE_SECRET || (PUBLIC_DEPLOYMENT ? "" : "dev-only-crypshare-cookie-secret-change-for-production");
const SESSION_COOKIE_SECURE = process.env.SESSION_COOKIE_SECURE
  ? process.env.SESSION_COOKIE_SECURE === "true"
  : PUBLIC_DEPLOYMENT;
const SESSION_COOKIE_SAMESITE = (process.env.SESSION_COOKIE_SAMESITE || "strict").toLowerCase();
const SESSION_RETURN_BEARER_TOKEN = process.env.SESSION_RETURN_BEARER_TOKEN !== "false";
const P2P_SESSION_TTL_MS = Math.max(Number(process.env.P2P_SESSION_TTL_MS || 1000 * 60 * 15), 1000 * 60);
const P2P_STUN_URLS = (process.env.P2P_STUN_URLS || "")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);
const P2P_TURN_URLS = (process.env.P2P_TURN_URLS || "turn:127.0.0.1:3478?transport=udp,turn:127.0.0.1:3478?transport=tcp")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);
const P2P_TURN_USERNAME = process.env.P2P_TURN_USERNAME || "crypshare";
const P2P_TURN_CREDENTIAL = process.env.P2P_TURN_CREDENTIAL || "change-this-turn-password";
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

function validateRuntimeConfig() {
  if (!PUBLIC_DEPLOYMENT) return;

  const failures: string[] = [];
  if (CORS_ORIGINS.length === 0) {
    failures.push("CORS_ORIGINS must be set for public deployments.");
  }
  if (!process.env.DATABASE_FILE) {
    failures.push("DATABASE_FILE must be set to a durable production database path.");
  }
  if (!process.env.UPLOAD_DIR) {
    failures.push("UPLOAD_DIR must be set to a durable encrypted blob storage path.");
  }
  if (P2P_TURN_URLS.length === 0) {
    failures.push("P2P_TURN_URLS must be configured because P2P is relay-only.");
  }
  if (!process.env.P2P_TURN_USERNAME || !process.env.P2P_TURN_CREDENTIAL) {
    failures.push("P2P_TURN_USERNAME and P2P_TURN_CREDENTIAL must be explicitly configured.");
  }
  if (P2P_TURN_USERNAME === "crypshare" || P2P_TURN_CREDENTIAL === "change-this-turn-password") {
    failures.push("Default TURN credentials are not allowed in public deployments.");
  }
  if (SESSION_TTL_MS > 1000 * 60 * 60 * 24) {
    failures.push("SESSION_TTL_MS should be 24 hours or less for public deployments.");
  }
  if (SESSION_COOKIE_ENABLED && SESSION_COOKIE_SECRET.length < 32) {
    failures.push("SESSION_COOKIE_SECRET must be at least 32 characters when session cookies are enabled.");
  }
  if (!SESSION_COOKIE_ENABLED && !SESSION_RETURN_BEARER_TOKEN) {
    failures.push("SESSION_RETURN_BEARER_TOKEN=false requires SESSION_COOKIE_ENABLED=true.");
  }

  if (failures.length > 0) {
    throw new Error(`Unsafe CrypShare production configuration:\n- ${failures.join("\n- ")}`);
  }
}

validateRuntimeConfig();
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const VAULT_CHUNK_SESSION_DIR = path.join(UPLOAD_DIR, ".chunk-sessions");
fs.mkdirSync(VAULT_CHUNK_SESSION_DIR, { recursive: true });

const uploadMiddleware = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: UPLOAD_FILE_LIMIT_BYTES,
    fieldSize: UPLOAD_FIELD_LIMIT_BYTES,
    files: 1,
    fields: 32
  }
});
const chunkUploadMiddleware = multer({
  dest: VAULT_CHUNK_SESSION_DIR,
  limits: {
    fileSize: VAULT_CHUNK_UPLOAD_LIMIT_BYTES,
    fields: 8,
    files: 1
  }
});
export const app = express();
const PORT = Number(process.env.PORT || 3001);
const vaultUploadSessions = new Map<string, {
  id: string;
  ownerUsername: string;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrappedFileKeyIv: string;
  expectedChunks: number;
  expectedSize: number;
  receivedChunks: Set<number>;
  dir: string;
  createdAt: number;
  expiresAt: number;
}>();
const vaultUploadCleanupInterval = setInterval(cleanupExpiredVaultUploadSessions, Math.min(VAULT_UPLOAD_SESSION_TTL_MS, 1000 * 60 * 15));
vaultUploadCleanupInterval.unref?.();
const p2pClients = new Map<string, Set<WebSocket>>();
const p2pSessions = new Map<string, {
  id: string;
  senderUsername: string;
  recipientUsername: string;
  relayAllowed: boolean;
  createdAt: number;
  expiresAt: number;
}>();

app.disable("x-powered-by");
app.disable("etag");
app.use(cors({
  origin: CORS_ORIGINS.length > 0 ? CORS_ORIGINS : true,
  credentials: SESSION_COOKIE_ENABLED
}));
app.use(requestContext);
app.use(securityHeaders);
app.use(createRateLimiter("general", GENERAL_RATE_LIMIT_WINDOW_MS, GENERAL_RATE_LIMIT_MAX));
app.use(requestLogger);
app.use(express.json({ limit: JSON_BODY_LIMIT }));

app.get("/", (_req, res) => {
  res.json({
    name: "CrypShare API",
    status: "ok",
    health: "/health",
    note: "Open the Vite frontend URL to use the app. This backend serves API and WebSocket routes."
  });
});

const GENESIS_HASH = "0".repeat(64);
const rateLimitBuckets = new Map<string, { count: number; resetAt: number }>();
const P2P_SIGNALING_TICKET_TTL_MS = 60_000;
const p2pSignalingTickets = new Map<string, { username: string; expiresAt: number }>();

interface AuditContext {
  actorId?: string;
  subjectId?: string;
  workspaceId?: string;
  visibility?: "user" | "workspace";
}

function getClientId(req: express.Request) {
  return req.ip || req.socket.remoteAddress || "unknown";
}

function createRateLimiter(name: string, windowMs: number, maxRequests: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.path === "/health") {
      next();
      return;
    }

    const now = Date.now();
    const key = `${name}:${getClientId(req)}`;
    const bucket = rateLimitBuckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      rateLimitBuckets.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }

    bucket.count += 1;
    const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
    res.setHeader("Retry-After", String(retryAfter));

    if (bucket.count > maxRequests) {
      console.warn(JSON.stringify({
        event: "rate_limit_exceeded",
        limiter: name,
        requestId: res.locals.requestId,
        client: getClientId(req),
        path: req.path
      }));
      res.status(429).json({ error: "Too many requests. Try again later." });
      return;
    }

    next();
  };
}

function requestContext(req: express.Request, res: express.Response, next: express.NextFunction) {
  const requestId = crypto.randomUUID();
  res.locals.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  next();
}

function securityHeaders(_req: express.Request, res: express.Response, next: express.NextFunction) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  next();
}

function requestLogger(req: express.Request, res: express.Response, next: express.NextFunction) {
  const startedAt = Date.now();
  res.on("finish", () => {
    console.log(JSON.stringify({
      event: "request",
      requestId: res.locals.requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - startedAt
    }));
  });
  next();
}

function sha256Hex(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function identityFingerprintFor(username: string, userRecord: UserRecord) {
  return sha256Hex([
    "crypshare-identity-v1",
    username,
    userRecord.identityPublicKeyECDH,
    userRecord.identityPublicKeyECDSA
  ].join(":"));
}

function normalizeFingerprint(value: unknown) {
  return typeof value === "string" ? value.replace(/[^a-f0-9]/gi, "").toLowerCase() : "";
}

function fingerprintAllowsIdentityAccess(username: string, userRecord: UserRecord, candidate: unknown) {
  const normalizedCandidate = normalizeFingerprint(candidate);
  return normalizedCandidate.length >= 32 && identityFingerprintFor(username, userRecord).startsWith(normalizedCandidate);
}

function safeCompareHex(a: string, b: string) {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b) || a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

function isSafeUsername(value: unknown) {
  return typeof value === "string" && /^[a-zA-Z0-9._-]{2,40}$/.test(value);
}

function isNonEmptyBoundedString(value: unknown, maxLength: number) {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= maxLength;
}

function isLikelyEncryptedComponent(value: unknown) {
  return typeof value === "string" && value.length > 0 && value.length <= UPLOAD_FIELD_LIMIT_BYTES;
}

function createWorkspaceInvite() {
  return {
    inviteCode: crypto.randomBytes(16).toString("hex"),
    inviteExpiresAt: Date.now() + WORKSPACE_INVITE_TTL_MS
  };
}

function removeUploadedFile(filename?: string) {
  if (!filename) return;
  const uploadedPath = path.join(UPLOAD_DIR, filename);
  if (fs.existsSync(uploadedPath)) {
    fs.unlinkSync(uploadedPath);
  }
}

function removeMulterFile(file?: Express.Multer.File) {
  if (!file?.path) return;
  fs.rmSync(file.path, { force: true });
}

function removePathRecursive(targetPath: string) {
  if (!targetPath.startsWith(VAULT_CHUNK_SESSION_DIR)) return;
  fs.rmSync(targetPath, { recursive: true, force: true });
}

function cleanupExpiredVaultUploadSessions() {
  const now = Date.now();
  for (const [id, session] of vaultUploadSessions.entries()) {
    if (session.expiresAt <= now) {
      removePathRecursive(session.dir);
      vaultUploadSessions.delete(id);
    }
  }
}

function storageQuotaSnapshot(username: string, incomingBytes = 0, replacingBytes = 0) {
  const usedBytes = getVaultStorageBytes(username);
  const quotaBytes = USER_STORAGE_QUOTA_BYTES;
  const projectedBytes = Math.max(usedBytes - replacingBytes, 0) + incomingBytes;
  return {
    usedBytes,
    quotaBytes,
    availableBytes: Math.max(quotaBytes - usedBytes, 0),
    projectedBytes,
    allowed: quotaBytes <= 0 || projectedBytes <= quotaBytes
  };
}

function chunkPath(session: { dir: string }, index: number) {
  return path.join(session.dir, `${index}.chunk`);
}

function pipeFileToStream(sourcePath: string, target: fs.WriteStream) {
  return new Promise<void>((resolve, reject) => {
    const source = fs.createReadStream(sourcePath);
    source.on("error", reject);
    target.on("error", reject);
    source.on("end", resolve);
    source.pipe(target, { end: false });
  });
}

async function assembleVaultChunks(session: { dir: string; expectedChunks: number }, finalPath: string) {
  const target = fs.createWriteStream(finalPath, { flags: "wx" });
  try {
    for (let index = 0; index < session.expectedChunks; index += 1) {
      await pipeFileToStream(chunkPath(session, index), target);
    }
  } catch (err) {
    target.destroy();
    fs.rmSync(finalPath, { force: true });
    throw err;
  }

  await new Promise<void>((resolve, reject) => {
    target.end(() => resolve());
    target.on("error", reject);
  });
}

function buildVaultGrant(ownerUsername: string, vaultFileId: string, input: Partial<VaultGrantRecord>) {
  const { recipientUsername, wrappedFileKey, ephemeralPublicKey, usedPreKey, signature } = input;
  if (!recipientUsername || !wrappedFileKey || !ephemeralPublicKey || !usedPreKey || !signature) {
    return { status: 400, error: "Missing encrypted grant components" };
  }

  if (recipientUsername === ownerUsername) {
    return { status: 400, error: "Use your owner vault access for your own files" };
  }

  const recipient = getUser(recipientUsername);
  if (!recipient) {
    return { status: 404, error: `Recipient ${recipientUsername} not found` };
  }
  if (recipient.revokedAt) {
    return { status: 410, error: `Recipient ${recipientUsername} identity has been revoked` };
  }

  if (!usersShareActiveWorkspace(ownerUsername, recipientUsername)) {
    return { status: 403, error: `Recipient ${recipientUsername} is not an active member of a shared workspace` };
  }

  const matchingPreKey = getPreKey(recipientUsername, usedPreKey);
  if (!matchingPreKey) {
    return { status: 400, error: `Recipient ${recipientUsername} pre-key was not found` };
  }

  const grant: VaultGrantRecord = {
    id: crypto.randomUUID(),
    vaultFileId,
    ownerUsername,
    recipientUsername,
    wrappedFileKey,
    ephemeralPublicKey,
    usedPreKey,
    signature,
    encryptedPrivatePreKey: matchingPreKey.encryptedPrivateKey,
    preKeyIv: matchingPreKey.iv,
    createdAt: Date.now()
  };

  return { grant };
}

function createSession(username: string, userAgent: string) {
  cleanupExpiredSessions();
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256Hex(token);
  const id = crypto.randomBytes(16).toString("hex");
  const createdAt = Date.now();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  createSessionRecord(tokenHash, { id, username, createdAt, expiresAt, userAgent });
  return { token, tokenHash, id, expiresAt };
}

function cleanupExpiredSessions() {
  cleanupExpiredSessionRecords();
}

function getBearerToken(req: express.Request) {
  const authHeader = req.headers.authorization;
  return authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length) : "";
}

function parseCookies(req: express.Request) {
  const header = req.headers.cookie || "";
  const cookies = new Map<string, string>();
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!name) continue;
    cookies.set(name, decodeURIComponent(value));
  }
  return cookies;
}

function getCookieToken(req: express.Request) {
  if (!SESSION_COOKIE_ENABLED) return "";
  return parseCookies(req).get(SESSION_COOKIE_NAME) || "";
}

function cookieSameSite() {
  return SESSION_COOKIE_SAMESITE === "lax" || SESSION_COOKIE_SAMESITE === "none" ? SESSION_COOKIE_SAMESITE : "strict";
}

function cookieAttributes(options: { httpOnly: boolean; maxAgeMs?: number }) {
  const attributes = [
    "Path=/",
    `SameSite=${cookieSameSite()}`,
    options.httpOnly ? "HttpOnly" : "",
    SESSION_COOKIE_SECURE ? "Secure" : "",
    options.maxAgeMs !== undefined ? `Max-Age=${Math.max(Math.floor(options.maxAgeMs / 1000), 0)}` : ""
  ].filter(Boolean);

  return attributes.join("; ");
}

function setCookie(res: express.Response, name: string, value: string, options: { httpOnly: boolean; maxAgeMs?: number }) {
  res.append("Set-Cookie", `${name}=${encodeURIComponent(value)}; ${cookieAttributes(options)}`);
}

function clearCookie(res: express.Response, name: string, httpOnly: boolean) {
  setCookie(res, name, "", { httpOnly, maxAgeMs: 0 });
}

function signCsrfToken(csrfNonce: string, tokenHash: string) {
  if (!SESSION_COOKIE_SECRET) return "";
  return crypto
    .createHmac("sha256", SESSION_COOKIE_SECRET)
    .update(`${csrfNonce}:${tokenHash}`)
    .digest("hex");
}

function createCsrfToken(tokenHash: string) {
  const nonce = crypto.randomBytes(16).toString("hex");
  const signature = signCsrfToken(nonce, tokenHash);
  return `${nonce}.${signature}`;
}

function safeCompareString(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function validateCsrfToken(candidate: string, tokenHash: string) {
  const [nonce, signature] = candidate.split(".");
  if (!nonce || !signature || !/^[a-f0-9]{32}$/i.test(nonce) || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  return safeCompareString(signature, signCsrfToken(nonce, tokenHash));
}

function setSessionCookies(res: express.Response, token: string, tokenHash: string, expiresAt: number) {
  if (!SESSION_COOKIE_ENABLED) return "";

  const maxAgeMs = Math.max(expiresAt - Date.now(), 0);
  const csrfToken = createCsrfToken(tokenHash);
  setCookie(res, SESSION_COOKIE_NAME, token, { httpOnly: true, maxAgeMs });
  setCookie(res, CSRF_COOKIE_NAME, csrfToken, { httpOnly: false, maxAgeMs });
  return csrfToken;
}

function clearSessionCookies(res: express.Response) {
  if (!SESSION_COOKIE_ENABLED) return;
  clearCookie(res, SESSION_COOKIE_NAME, true);
  clearCookie(res, CSRF_COOKIE_NAME, false);
}

function getSession(req: express.Request) {
  const bearerToken = getBearerToken(req);
  if (bearerToken) return getSessionFromToken(bearerToken, "bearer");

  const cookieToken = getCookieToken(req);
  return getSessionFromToken(cookieToken, "cookie");
}

function getSessionFromToken(token: string, source: "bearer" | "cookie") {
  if (!token) return null;

  const tokenHash = sha256Hex(token);
  const session = getSessionByTokenHash(tokenHash);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    deleteSessionByTokenHash(tokenHash);
    return null;
  }

  return { token, tokenHash, session, source };
}

function isCsrfSafeMethod(method: string) {
  return ["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

function requireCookieCsrf(req: express.Request, res: express.Response, tokenHash: string) {
  if (isCsrfSafeMethod(req.method)) return true;

  const cookies = parseCookies(req);
  const cookieToken = cookies.get(CSRF_COOKIE_NAME) || "";
  const headerToken = typeof req.headers[CSRF_HEADER_NAME] === "string" ? req.headers[CSRF_HEADER_NAME] as string : "";

  if (!cookieToken || !headerToken || !safeCompareString(cookieToken, headerToken) || !validateCsrfToken(headerToken, tokenHash)) {
    res.status(403).json({ error: "CSRF verification failed" });
    return false;
  }

  return true;
}

function listUserSessions(username: string, currentSessionId: string) {
  return listSessionRecords(username, currentSessionId);
}

function revokeSession(username: string, sessionId: string) {
  return deleteSessionById(username, sessionId);
}

function revokeOtherSessions(username: string, currentSessionId: string) {
  return deleteOtherSessions(username, currentSessionId);
}

function revokeAllSessions(username: string) {
  return deleteAllSessions(username);
}

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authSession = getSession(req);
  if (!authSession) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  if (authSession.source === "cookie" && !requireCookieCsrf(req, res, authSession.tokenHash)) {
    return;
  }

  const userRecord = getUser(authSession.session.username);
  if (!userRecord || userRecord.revokedAt) {
    deleteSessionByTokenHash(authSession.tokenHash);
    res.status(403).json({ error: "Identity is not active" });
    return;
  }

  res.locals.authUsername = authSession.session.username;
  res.locals.authRole = userRecord.role || "member";
  res.locals.authSessionId = authSession.session.id;
  res.locals.authTokenHash = authSession.tokenHash;
  next();
}

function requireAdmin(_req: express.Request, res: express.Response, next: express.NextFunction) {
  if (res.locals.authRole !== "admin") {
    res.status(403).json({ error: "Admin approval required" });
    return;
  }

  next();
}

function requireSelf(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authUsername = res.locals.authUsername;
  if (!authUsername) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const requestedUsername = req.params.username || req.body?.username;
  if (authUsername !== requestedUsername) {
    res.status(403).json({ error: "Not authorized for this identity" });
    return;
  }

  next();
}

function serializeWorkspaceMember(member: WorkspaceMemberRecord) {
  return {
    workspaceId: member.workspaceId,
    username: member.username,
    role: member.role,
    status: member.status,
    joinedAt: member.joinedAt,
    approvedAt: member.approvedAt || null,
    approvedBy: member.approvedBy || null,
    identityPublicKeyECDH: member.identityPublicKeyECDH,
    identityPublicKeyECDSA: member.identityPublicKeyECDSA
  };
}

function requireWorkspaceMember(workspaceId: string, username: string) {
  const membership = getWorkspaceMembership(workspaceId, username);
  if (!membership || membership.status !== "active") return null;
  return membership;
}

function requireWorkspaceAdmin(workspaceId: string, username: string) {
  const membership = requireWorkspaceMember(workspaceId, username);
  if (!membership || !["owner", "admin"].includes(membership.role)) return null;
  return membership;
}

function requireWorkspaceOwner(workspaceId: string, username: string) {
  const membership = requireWorkspaceMember(workspaceId, username);
  if (!membership || membership.role !== "owner") return null;
  return membership;
}

function appendAuditLog(userId: string, action: string, context: AuditContext = {}) {
  const previousHash = getLastAuditHash() || GENESIS_HASH;
  const timestamp = Date.now();
  
  const actorId = context.actorId || userId;
  const subjectId = context.subjectId || userId;
  const workspaceId = context.workspaceId || null;
  const visibility = context.visibility || "user";
  const payload = JSON.stringify([timestamp, userId, action, actorId, subjectId, workspaceId, visibility]) + previousHash;
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  
  appendAuditEntry({ timestamp, userId, action, previousHash, hash, actorId, subjectId, workspaceId, visibility });
  console.log(`[AUDIT LOG] ${action} -> [Hash: ${hash.substring(0, 8)}...]`);
}

function visibleAuditHashPayload(entry: ReturnType<typeof getVisibleAuditLog>[number]) {
  return JSON.stringify([
    entry.timestamp,
    entry.userId,
    entry.action,
    entry.actorId || entry.userId,
    entry.subjectId || entry.userId,
    entry.workspaceId || null,
    entry.visibility || "user"
  ]);
}

function buildVisibleAuditView(username: string) {
  const adminWorkspaceIds = listWorkspacesForUser(username)
    .filter((workspace) => workspace.status === "active" && ["owner", "admin"].includes(workspace.role || ""))
    .map((workspace) => workspace.id);
  const visibleEntries = getVisibleAuditLog(username, adminWorkspaceIds);
  let previousHash = GENESIS_HASH;

  return visibleEntries.map((entry) => {
    const hash = sha256Hex(visibleAuditHashPayload(entry) + previousHash);
    const visibleEntry = {
      ...entry,
      previousHash,
      hash
    };
    previousHash = hash;
    return visibleEntry;
  });
}

function visibleAuditSummary(entries: ReturnType<typeof buildVisibleAuditView>) {
  const latestEntry = entries.length > 0 ? entries[entries.length - 1] : null;
  return {
    blockCount: entries.length,
    firstTimestamp: entries[0]?.timestamp || null,
    latestTimestamp: latestEntry?.timestamp || null,
    firstHash: entries[0]?.hash || null,
    latestHash: latestEntry?.hash || null
  };
}
// -------------------------------------

function cleanupExpiredP2PSessions() {
  const now = Date.now();
  for (const [sessionId, session] of p2pSessions.entries()) {
    if (session.expiresAt <= now) {
      p2pSessions.delete(sessionId);
      routeP2PMessage(session.senderUsername, {
        type: "p2p-expired",
        sessionId
      });
      routeP2PMessage(session.recipientUsername, {
        type: "p2p-expired",
        sessionId
      });
    }
  }
}

function addP2PClient(username: string, socket: WebSocket) {
  const sockets = p2pClients.get(username) || new Set<WebSocket>();
  sockets.add(socket);
  p2pClients.set(username, sockets);
}

function removeP2PClient(username: string, socket: WebSocket) {
  const sockets = p2pClients.get(username);
  if (!sockets) return;
  sockets.delete(socket);
  if (sockets.size === 0) {
    p2pClients.delete(username);
  }
}

function routeP2PMessage(username: string, message: Record<string, unknown>) {
  const sockets = p2pClients.get(username);
  if (!sockets) return false;

  const payload = JSON.stringify(message);
  let delivered = false;
  for (const socket of sockets) {
    if (socket.readyState === socket.OPEN) {
      socket.send(payload);
      delivered = true;
    }
  }
  return delivered;
}

function parseP2PMessage(raw: Buffer) {
  try {
    const parsed = JSON.parse(raw.toString()) as Record<string, unknown>;
    return parsed && typeof parsed.type === "string" ? parsed : null;
  } catch {
    return null;
  }
}

function sendP2PError(socket: WebSocket, error: string, sessionId?: string) {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify({ type: "p2p-error", error, sessionId }));
  }
}

function cleanupP2PSignalingTickets() {
  const now = Date.now();
  for (const [ticketHash, ticket] of p2pSignalingTickets.entries()) {
    if (ticket.expiresAt <= now) {
      p2pSignalingTickets.delete(ticketHash);
    }
  }
}

function createP2PSignalingTicket(username: string) {
  cleanupP2PSignalingTickets();
  const ticket = crypto.randomBytes(32).toString("base64url");
  const ticketHash = sha256Hex(ticket);
  const expiresAt = Date.now() + P2P_SIGNALING_TICKET_TTL_MS;
  p2pSignalingTickets.set(ticketHash, {
    username,
    expiresAt
  });
  return {
    ticket,
    expiresAt
  };
}

function consumeP2PSignalingTicket(ticket: string) {
  cleanupP2PSignalingTickets();
  const ticketHash = sha256Hex(ticket);
  const record = p2pSignalingTickets.get(ticketHash);
  p2pSignalingTickets.delete(ticketHash);
  if (!record || record.expiresAt <= Date.now()) return null;
  return record.username;
}

function getP2PSessionForUser(sessionId: unknown, username: string) {
  if (typeof sessionId !== "string") return null;
  cleanupExpiredP2PSessions();
  const session = p2pSessions.get(sessionId);
  if (!session) return null;
  return [session.senderUsername, session.recipientUsername].includes(username) ? session : null;
}

function attachP2PSignaling(server: http.Server) {
  const websocketServer = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    const requestUrl = new URL(req.url || "", `http://${req.headers.host || "localhost"}`);
    if (requestUrl.pathname !== "/p2p/signaling") return;

    const ticket = requestUrl.searchParams.get("ticket") || "";
    const ticketUsername = ticket ? consumeP2PSignalingTicket(ticket) : null;
    if (!ticketUsername) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    const userRecord = getUser(ticketUsername);
    if (!userRecord || userRecord.revokedAt) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    websocketServer.handleUpgrade(req, socket, head, (ws) => {
      websocketServer.emit("connection", ws, req, ticketUsername);
    });
  });

  websocketServer.on("connection", (socket: WebSocket, _req: http.IncomingMessage, username: string) => {
    const userRecord = getUser(username);
    if (!userRecord || userRecord.revokedAt) {
      socket.close();
      return;
    }

    addP2PClient(username, socket);
    socket.send(JSON.stringify({ type: "p2p-ready", username }));

    socket.on("message", (raw) => {
      cleanupExpiredP2PSessions();
      const message = parseP2PMessage(Buffer.isBuffer(raw) ? raw : Buffer.from(raw.toString()));
      if (!message) {
        sendP2PError(socket, "Invalid P2P signaling message.");
        return;
      }

      if (message.type === "p2p-invite") {
        const recipientUsername = typeof message.recipientUsername === "string" ? message.recipientUsername : "";
        if (!isSafeUsername(recipientUsername)) {
          sendP2PError(socket, "Invalid recipient.");
          return;
        }
        if (recipientUsername === username) {
          sendP2PError(socket, "Choose another recipient.");
          return;
        }
        const recipient = getUser(recipientUsername);
        if (!recipient || recipient.revokedAt) {
          sendP2PError(socket, "Recipient identity is unavailable.");
          return;
        }
        const usersShareWorkspace = usersShareActiveWorkspace(username, recipientUsername);
        if (!usersShareWorkspace && !fingerprintAllowsIdentityAccess(recipientUsername, recipient, message.recipientFingerprint)) {
          sendP2PError(socket, "Recipient identity invite fingerprint is required for unknown-user P2P.");
          return;
        }

        const sessionId = crypto.randomUUID();
        const session = {
          id: sessionId,
          senderUsername: username,
          recipientUsername,
          relayAllowed: message.relayAllowed === true,
          createdAt: Date.now(),
          expiresAt: Date.now() + P2P_SESSION_TTL_MS
        };
        p2pSessions.set(sessionId, session);
        appendAuditLog(username, "P2P Invite Created", {
          actorId: username,
          subjectId: recipientUsername
        });

        socket.send(JSON.stringify({
          type: "p2p-invite-created",
          sessionId,
          recipientUsername,
          delivered: false,
          relayAllowed: session.relayAllowed,
          expiresAt: session.expiresAt
        }));
        const delivered = routeP2PMessage(recipientUsername, {
          type: "p2p-invite",
          sessionId,
          senderUsername: username,
          senderFingerprint: identityFingerprintFor(username, userRecord),
          relayAllowed: session.relayAllowed,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt
        });
        socket.send(JSON.stringify({
          type: "p2p-invite-delivery",
          sessionId,
          recipientUsername,
          delivered
        }));
        return;
      }

      if (message.type === "p2p-accept" || message.type === "p2p-decline") {
        const session = getP2PSessionForUser(message.sessionId, username);
        if (!session || session.recipientUsername !== username) {
          sendP2PError(socket, "P2P session unavailable.", typeof message.sessionId === "string" ? message.sessionId : undefined);
          return;
        }

        if (message.type === "p2p-decline") {
          p2pSessions.delete(session.id);
          appendAuditLog(username, "P2P Declined", {
            actorId: username,
            subjectId: session.senderUsername
          });
          routeP2PMessage(session.senderUsername, {
            type: "p2p-declined",
            sessionId: session.id,
            recipientUsername: username
          });
          return;
        }

        appendAuditLog(username, "P2P Accepted", {
          actorId: username,
          subjectId: session.senderUsername
        });
        routeP2PMessage(session.senderUsername, {
          type: "p2p-accepted",
          sessionId: session.id,
          recipientUsername: username
        });
        return;
      }

      if (message.type === "p2p-signal") {
        const session = getP2PSessionForUser(message.sessionId, username);
        if (!session) {
          sendP2PError(socket, "P2P session unavailable.", typeof message.sessionId === "string" ? message.sessionId : undefined);
          return;
        }

        const signalType = message.signalType;
        if (typeof signalType !== "string" || !["offer", "answer", "ice", "failed", "completed"].includes(signalType)) {
          sendP2PError(socket, "Invalid P2P signal.", session.id);
          return;
        }

        if (signalType === "completed") {
          appendAuditLog(username, "P2P Completed", {
            actorId: username,
            subjectId: username === session.senderUsername ? session.recipientUsername : session.senderUsername
          });
          p2pSessions.delete(session.id);
        }
        if (signalType === "failed") {
          appendAuditLog(username, "P2P Failed", {
            actorId: username,
            subjectId: username === session.senderUsername ? session.recipientUsername : session.senderUsername
          });
          p2pSessions.delete(session.id);
        }

        const targetUsername = username === session.senderUsername ? session.recipientUsername : session.senderUsername;
        const delivered = routeP2PMessage(targetUsername, {
          type: "p2p-signal",
          sessionId: session.id,
          fromUsername: username,
          signalType,
          payload: message.payload || null
        });
        console.log(JSON.stringify({
          event: "p2p_signal",
          sessionId: session.id,
          from: username,
          to: targetUsername,
          signalType,
          delivered
        }));
        if (!delivered && signalType !== "failed" && signalType !== "completed") {
          sendP2PError(socket, "Peer is no longer connected.", session.id);
        }
      }
    });

    socket.on("close", () => {
      removeP2PClient(username, socket);
    });
  });

  return websocketServer;
}

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/upload-limits", (req, res) => {
  res.json({
    uploadFileLimitBytes: UPLOAD_FILE_LIMIT_BYTES,
    uploadFieldLimitBytes: UPLOAD_FIELD_LIMIT_BYTES,
    vaultChunkUploadLimitBytes: VAULT_CHUNK_UPLOAD_LIMIT_BYTES,
    vaultUploadSessionTtlMs: VAULT_UPLOAD_SESSION_TTL_MS,
    mode: "resumable-encrypted-chunks",
    note: "Vault uploads use resumable encrypted chunks. The server stores encrypted bytes only; multi-terabyte deployments still need durable object storage."
  });
});

app.get("/p2p/ice-config", requireAuth, (_req, res) => {
  const turnConfigured = P2P_TURN_URLS.length > 0 && !!P2P_TURN_USERNAME && !!P2P_TURN_CREDENTIAL;
  const turnServers: RTCIceServer[] = turnConfigured ? [{
    urls: P2P_TURN_URLS,
    username: P2P_TURN_USERNAME,
    credential: P2P_TURN_CREDENTIAL
  }] : [];
  res.json({
    iceServers: turnServers,
    turnConfigured,
    relayOnly: true,
    sessionTtlMs: P2P_SESSION_TTL_MS,
    privacyNote: "P2P uses TURN relay-only mode. TURN can see IPs, timing, and packet sizes, but CrypShare encrypts file metadata and chunks before WebRTC sends them."
  });
});

app.post("/p2p/signaling-ticket", requireAuth, (_req, res) => {
  const ticket = createP2PSignalingTicket(res.locals.authUsername);
  res.json({
    ...ticket,
    ttlMs: P2P_SIGNALING_TICKET_TTL_MS
  });
});

app.get("/p2p/identity/:username", requireAuth, (req, res) => {
  if (!isSafeUsername(req.params.username)) {
    res.status(400).json({ error: "Invalid username" });
    return;
  }

  const userRecord = getUser(req.params.username);
  if (!userRecord || userRecord.revokedAt) {
    res.status(userRecord?.revokedAt ? 410 : 404).json({ error: "P2P identity unavailable" });
    return;
  }

  const sharedWorkspace = usersShareActiveWorkspace(res.locals.authUsername, req.params.username);
  const inviteFingerprint = req.query.fingerprint;
  if (req.params.username !== res.locals.authUsername && !sharedWorkspace && !fingerprintAllowsIdentityAccess(req.params.username, userRecord, inviteFingerprint)) {
    res.status(403).json({ error: "Identity invite fingerprint required for unknown-user P2P" });
    return;
  }

  res.json({
    username: req.params.username,
    identityPublicKeyECDH: userRecord.identityPublicKeyECDH,
    identityPublicKeyECDSA: userRecord.identityPublicKeyECDSA
  });
});

const authRateLimiter = createRateLimiter("auth", AUTH_RATE_LIMIT_WINDOW_MS, AUTH_RATE_LIMIT_MAX);

app.post("/register", authRateLimiter, (req, res) => {
  const { username, salt, authSalt, authVerifierHash, identityPublicKeyECDH, identityPublicKeyECDSA, encryptedPrivateKeyECDH, ivECDH, encryptedPrivateKeyECDSA, ivECDSA } = req.body;
  if (!username || !salt || !authSalt || !authVerifierHash || !identityPublicKeyECDH || !identityPublicKeyECDSA || !encryptedPrivateKeyECDH || !ivECDH || !encryptedPrivateKeyECDSA || !ivECDSA) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }
  if (!isSafeUsername(username)) {
    res.status(400).json({ error: "Username must be 2-40 characters using letters, numbers, dots, underscores, or hyphens" });
    return;
  }
  if (getUser(username)) {
    res.status(409).json({ error: "Username already exists" });
    return;
  }

  const approvedUserCount = countApprovedUsers();
  const bootstrapAdmin = approvedUserCount === 0;
  const approvedAt = Date.now();

  // Store encrypted identity material; private keys remain wrapped by the client-side KEK.
  const userRecord: UserRecord = {
    salt,
    authSalt,
    authVerifierHash,
    identityPublicKeyECDH,
    identityPublicKeyECDSA,
    encryptedPrivateKeyECDH,
    ivECDH,
    encryptedPrivateKeyECDSA,
    ivECDSA,
    role: bootstrapAdmin ? "admin" : "member",
    approvedAt,
    approvedBy: "self-service"
  };
  createUser(username, userRecord);

  appendAuditLog(username, bootstrapAdmin ? "Bootstrap Admin Registration" : "Identity Registration");

  console.log(`Registered user: ${username}`);
  console.log(`Stored Identity payload keys:`, Object.keys(userRecord));

  res.json({
    message: bootstrapAdmin ? "Bootstrap admin identity securely deposited" : "Identity securely deposited",
    approved: true,
    role: userRecord.role
  });
});

app.get("/session-material/:username", authRateLimiter, (req, res) => {
  const { username } = req.params;
  const userRecord = getUser(username);

  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (userRecord.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }

  if (!userRecord.authSalt || !userRecord.authVerifierHash) {
    res.status(409).json({ error: "This identity was created before server-side sessions. Re-register it to enable protected access." });
    return;
  }

  res.json({ salt: userRecord.salt, authSalt: userRecord.authSalt });
});

app.post("/sessions", authRateLimiter, (req, res) => {
  const { username, authSecret } = req.body;
  const userRecord = getUser(username);

  if (!username || !authSecret) {
    res.status(400).json({ error: "Missing username or auth secret" });
    return;
  }

  if (!userRecord?.authVerifierHash || userRecord.revokedAt) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const presentedHash = sha256Hex(authSecret);
  if (!safeCompareHex(presentedHash, userRecord.authVerifierHash)) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const session = createSession(username, req.get("user-agent") || "Unknown client");
  const csrfToken = setSessionCookies(res, session.token, session.tokenHash, session.expiresAt);
  appendAuditLog(username, "Session Established");
  res.json({
    token: SESSION_RETURN_BEARER_TOKEN ? session.token : undefined,
    id: session.id,
    expiresAt: session.expiresAt,
    csrfToken: csrfToken || undefined,
    cookieSession: SESSION_COOKIE_ENABLED
  });
});

app.get("/sessions", requireAuth, (req, res) => {
  res.json({
    sessions: listUserSessions(res.locals.authUsername, res.locals.authSessionId)
  });
});

app.delete("/sessions/current", requireAuth, (req, res) => {
  deleteSessionByTokenHash(res.locals.authTokenHash);
  clearSessionCookies(res);
  appendAuditLog(res.locals.authUsername, "Session Revoked");
  res.json({ message: "Current session revoked" });
});

app.delete("/sessions/:sessionId", requireAuth, (req, res) => {
  const revoked = revokeSession(res.locals.authUsername, req.params.sessionId);
  if (!revoked) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Session Revoked");
  res.json({ message: "Session revoked" });
});

app.post("/sessions/revoke-others", requireAuth, (req, res) => {
  const revoked = revokeOtherSessions(res.locals.authUsername, res.locals.authSessionId);
  appendAuditLog(res.locals.authUsername, "Other Sessions Revoked");
  res.json({ message: "Other sessions revoked", revoked });
});

app.post("/identity/:username/revoke", requireAuth, requireSelf, (req, res) => {
  const { username } = req.params;
  const reason = typeof req.body?.reason === "string" && req.body.reason.trim()
    ? req.body.reason.trim().slice(0, 240)
    : "User requested emergency identity revocation";

  const userRecord = getUser(username);
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (userRecord.revokedAt) {
    res.status(409).json({ error: "Identity already revoked" });
    return;
  }

  const revocation = revokeUser(username, reason);
  if (!revocation) {
    res.status(409).json({ error: "Identity already revoked" });
    return;
  }

  const revokedSessions = revokeAllSessions(username);
  clearSessionCookies(res);
  appendAuditLog(username, "Identity Revoked");
  res.json({ message: "Identity revoked", revokedAt: revocation.revokedAt, revokedSessions });
});

app.get("/admin/pending-identities", requireAuth, requireAdmin, (_req, res) => {
  const pending = listPendingUsers().map((user) => ({
    username: user.username,
    identityPublicKeyECDH: user.identity_public_key_ecdh,
    identityPublicKeyECDSA: user.identity_public_key_ecdsa
  }));
  res.json({ pending });
});

app.post("/admin/identities/:username/approve", requireAuth, requireAdmin, (req, res) => {
  const { username } = req.params;
  if (username === res.locals.authUsername) {
    res.status(400).json({ error: "Current identity is already active" });
    return;
  }

  const userRecord = getUser(username);
  if (!userRecord) {
    res.status(404).json({ error: "Identity not found" });
    return;
  }
  if (userRecord.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }
  if (userRecord.approvedAt) {
    res.status(409).json({ error: "Identity already approved" });
    return;
  }

  const approval = approveUser(username, res.locals.authUsername);
  if (!approval) {
    res.status(409).json({ error: "Identity could not be approved" });
    return;
  }

  appendAuditLog(username, "Identity Approved");
  res.json({ message: "Identity approved", approvedAt: approval.approvedAt, approvedBy: approval.approvedBy });
});

app.post("/workspaces", requireAuth, (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    res.status(400).json({ error: "Workspace name is required" });
    return;
  }
  if (name.length > 80) {
    res.status(400).json({ error: "Workspace name must be 80 characters or fewer" });
    return;
  }

  const invite = createWorkspaceInvite();
  const workspace = {
    id: crypto.randomUUID(),
    name,
    inviteCode: invite.inviteCode,
    inviteExpiresAt: invite.inviteExpiresAt,
    createdBy: res.locals.authUsername as string,
    createdAt: Date.now()
  };

  const ownerMembership = createWorkspace(workspace, res.locals.authUsername);
  appendAuditLog(res.locals.authUsername, "Workspace Created", {
    actorId: res.locals.authUsername,
    subjectId: res.locals.authUsername,
    workspaceId: workspace.id,
    visibility: "workspace"
  });
  res.json({ workspace: { ...workspace, role: ownerMembership?.role, status: ownerMembership?.status, memberCount: 1, pendingCount: 0 } });
});

app.get("/workspaces", requireAuth, (_req, res) => {
  res.json({ workspaces: listWorkspacesForUser(res.locals.authUsername) });
});

app.get("/workspaces/:id/members", requireAuth, (req, res) => {
  const membership = requireWorkspaceMember(req.params.id, res.locals.authUsername);
  if (!membership) {
    res.status(403).json({ error: "Active workspace membership required" });
    return;
  }

  res.json({ members: listWorkspaceMembers(req.params.id).map(serializeWorkspaceMember) });
});

app.post("/workspaces/:id/join", requireAuth, (req, res) => {
  const inviteCode = typeof req.body?.inviteCode === "string" ? req.body.inviteCode.trim() : "";
  if (!inviteCode) {
    res.status(400).json({ error: "Workspace invite code is required" });
    return;
  }
  if (!/^[a-f0-9]{32}$/i.test(inviteCode)) {
    res.status(400).json({ error: "Workspace invite code format is invalid" });
    return;
  }

  const workspace = findWorkspaceById(req.params.id);
  if (!workspace) {
    res.status(404).json({ error: "Workspace not found" });
    return;
  }

  const inviteWorkspace = findWorkspaceByInviteCode(inviteCode);
  if (!inviteWorkspace || inviteWorkspace.id !== workspace.id) {
    res.status(403).json({ error: "Invalid workspace invite code" });
    return;
  }
  if (workspace.inviteExpiresAt <= Date.now()) {
    res.status(410).json({ error: "Workspace invite code has expired. Ask a workspace admin to rotate it." });
    return;
  }

  const membership = requestWorkspaceJoin(workspace.id, res.locals.authUsername);
  if (!membership) {
    res.status(500).json({ error: "Unable to request workspace access" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Workspace Join Requested", {
    actorId: res.locals.authUsername,
    subjectId: res.locals.authUsername,
    workspaceId: workspace.id,
    visibility: "workspace"
  });
  res.json({
    message: membership.status === "active" ? "Already an active workspace member" : "Workspace join request submitted",
    membership: serializeWorkspaceMember(membership)
  });
});

app.get("/workspaces/:id/pending-members", requireAuth, (req, res) => {
  const adminMembership = requireWorkspaceAdmin(req.params.id, res.locals.authUsername);
  if (!adminMembership) {
    res.status(403).json({ error: "Workspace admin approval required" });
    return;
  }

  res.json({ pending: listPendingWorkspaceMembers(req.params.id).map(serializeWorkspaceMember) });
});

app.post("/workspaces/:id/invite/rotate", requireAuth, (req, res) => {
  const adminMembership = requireWorkspaceAdmin(req.params.id, res.locals.authUsername);
  if (!adminMembership) {
    res.status(403).json({ error: "Workspace admin approval required" });
    return;
  }

  const workspace = findWorkspaceById(req.params.id);
  if (!workspace) {
    res.status(404).json({ error: "Workspace not found" });
    return;
  }

  const invite = createWorkspaceInvite();
  const rotatedWorkspace = rotateWorkspaceInvite(workspace.id, invite.inviteCode, invite.inviteExpiresAt);
  if (!rotatedWorkspace) {
    res.status(500).json({ error: "Unable to rotate workspace invite" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Workspace Invite Rotated", {
    actorId: res.locals.authUsername,
    subjectId: res.locals.authUsername,
    workspaceId: workspace.id,
    visibility: "workspace"
  });
  res.json({ message: "Workspace invite rotated", workspace: rotatedWorkspace });
});

app.post("/workspaces/:id/members/:username/approve", requireAuth, (req, res) => {
  const adminMembership = requireWorkspaceAdmin(req.params.id, res.locals.authUsername);
  if (!adminMembership) {
    res.status(403).json({ error: "Workspace admin approval required" });
    return;
  }

  if (!isSafeUsername(req.params.username)) {
    res.status(400).json({ error: "Invalid username" });
    return;
  }

  const target = getUser(req.params.username);
  if (!target) {
    res.status(404).json({ error: "Identity not found" });
    return;
  }
  if (target.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }

  const membership = approveWorkspaceMember(req.params.id, req.params.username, res.locals.authUsername);
  if (!membership) {
    res.status(409).json({ error: "Member is not pending approval" });
    return;
  }

  appendAuditLog(req.params.username, "Workspace Member Approved", {
    actorId: res.locals.authUsername,
    subjectId: req.params.username,
    workspaceId: req.params.id,
    visibility: "workspace"
  });
  res.json({ message: "Workspace member approved", member: serializeWorkspaceMember(membership) });
});

app.post("/workspaces/:id/members/:username/revoke", requireAuth, (req, res) => {
  const adminMembership = requireWorkspaceAdmin(req.params.id, res.locals.authUsername);
  if (!adminMembership) {
    res.status(403).json({ error: "Workspace admin approval required" });
    return;
  }

  if (!isSafeUsername(req.params.username)) {
    res.status(400).json({ error: "Invalid username" });
    return;
  }

  if (req.params.username === res.locals.authUsername) {
    res.status(400).json({ error: "Workspace admins cannot revoke their current session identity" });
    return;
  }

  const targetMembership = getWorkspaceMembership(req.params.id, req.params.username);
  if (!targetMembership) {
    res.status(404).json({ error: "Workspace member not found" });
    return;
  }
  if (targetMembership.role === "owner") {
    res.status(400).json({ error: "Workspace owner cannot be revoked" });
    return;
  }

  const revoked = revokeWorkspaceMember(req.params.id, req.params.username);
  if (!revoked) {
    res.status(409).json({ error: "Workspace member is not active" });
    return;
  }

  appendAuditLog(req.params.username, "Workspace Member Revoked", {
    actorId: res.locals.authUsername,
    subjectId: req.params.username,
    workspaceId: req.params.id,
    visibility: "workspace"
  });
  res.json({ message: "Workspace member revoked" });
});

app.post("/workspaces/:id/members/:username/role", requireAuth, (req, res) => {
  const ownerMembership = requireWorkspaceOwner(req.params.id, res.locals.authUsername);
  if (!ownerMembership) {
    res.status(403).json({ error: "Workspace owner role required" });
    return;
  }

  if (!isSafeUsername(req.params.username)) {
    res.status(400).json({ error: "Invalid username" });
    return;
  }

  const role = req.body?.role;
  if (role !== "admin" && role !== "member") {
    res.status(400).json({ error: "Workspace role must be admin or member" });
    return;
  }

  if (req.params.username === res.locals.authUsername) {
    res.status(400).json({ error: "Workspace owners cannot change their own owner role" });
    return;
  }

  const targetMembership = getWorkspaceMembership(req.params.id, req.params.username);
  if (!targetMembership) {
    res.status(404).json({ error: "Workspace member not found" });
    return;
  }
  if (targetMembership.status !== "active") {
    res.status(409).json({ error: "Workspace member is not active" });
    return;
  }
  if (targetMembership.role === "owner") {
    res.status(400).json({ error: "Workspace owner role cannot be changed here" });
    return;
  }

  const membership = updateWorkspaceMemberRole(req.params.id, req.params.username, role);
  if (!membership) {
    res.status(409).json({ error: "Workspace member role could not be updated" });
    return;
  }

  appendAuditLog(req.params.username, "Workspace Member Role Changed", {
    actorId: res.locals.authUsername,
    subjectId: req.params.username,
    workspaceId: req.params.id,
    visibility: "workspace"
  });
  res.json({ message: "Workspace member role updated", member: serializeWorkspaceMember(membership) });
});

app.post("/upload-prekeys", requireAuth, requireSelf, (req, res) => {
  const { username, preKeys } = req.body;
  if (!username || !preKeys || !Array.isArray(preKeys)) {
    res.status(400).json({ error: "Missing username or preKeys array" });
    return;
  }
  if (!getUser(username)) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  addPreKeys(username, preKeys);
  const remaining = getPreKeyStatus(username).available;
  appendAuditLog(username, "One-Time Pre-Key Bundle Uploaded");
  console.log(`Stored ${preKeys.length} One-Time Pre-Keys for user ${username}. Available: ${remaining}`);
  res.json({ message: "Pre-Keys safely uploaded!", remaining });
});

app.get("/prekeys/:username/status", requireAuth, requireSelf, (req, res) => {
  const { username } = req.params;
  const userRecord = getUser(username);

  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (userRecord.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }

  res.json(getPreKeyStatus(username));
});

app.get("/share-readiness/:username", requireAuth, (req, res) => {
  const { username } = req.params;
  if (!isSafeUsername(username)) {
    res.status(400).json({ error: "Invalid username" });
    return;
  }
  if (username === res.locals.authUsername) {
    res.status(400).json({ error: "Use your owner vault access for your own files" });
    return;
  }

  const userRecord = getUser(username);
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  if (userRecord.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }

  const workspaceApproved = usersShareActiveWorkspace(res.locals.authUsername, username);
  if (!workspaceApproved) {
    res.status(403).json({ error: "Recipient is not an active member of a shared workspace" });
    return;
  }

  const preKeyStatus = getPreKeyStatus(username);
  res.json({
    username,
    workspaceApproved: true,
    preKeysAvailable: preKeyStatus.available > 0,
    availablePreKeys: preKeyStatus.available
  });
});

app.get("/prekey/:username", requireAuth, (req, res) => {
  const { username } = req.params;
  const userRecord = getUser(username);
  
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (userRecord.revokedAt) {
    res.status(410).json({ error: "Identity has been revoked" });
    return;
  }

  if (username !== res.locals.authUsername && !usersShareActiveWorkspace(res.locals.authUsername, username)) {
    res.status(403).json({ error: "Recipient is not an active member of a shared workspace" });
    return;
  }
  
  const preKey = consumeNextPreKey(username);
  if (!preKey) {
    res.status(404).json({ error: "No pre-keys available for this user" });
    return;
  }

  const remaining = getPreKeyStatus(username).available;
  console.log(`Issued One-Time Pre-Key for ${username}. Remaining: ${remaining}`);
  
  // Return only the public part
  res.json({ 
    preKey: { publicKeyHex: preKey.publicKeyHex },
    identityPublicKeyECDH: userRecord.identityPublicKeyECDH,
    identityPublicKeyECDSA: userRecord.identityPublicKeyECDSA
  });
});

app.get("/users", requireAuth, (req, res) => {
  const users = listDiscoverableUsers(res.locals.authUsername).map((user) => ({
    username: user.username,
    identityPublicKeyECDH: user.identity_public_key_ecdh,
    identityPublicKeyECDSA: user.identity_public_key_ecdsa
  }));
  res.json(users);
});

app.get("/security-summary", requireAuth, (_req, res) => {
  const workspaces = listWorkspacesForUser(res.locals.authUsername);
  const preKeys = getPreKeyStatus(res.locals.authUsername);
  const sessions = listSessionRecords(res.locals.authUsername, res.locals.authSessionId);
  const auditSummary = visibleAuditSummary(buildVisibleAuditView(res.locals.authUsername));
  const files = listVaultFiles(res.locals.authUsername);
  const storage = storageQuotaSnapshot(res.locals.authUsername);

  res.json({
    workspaces: {
      active: workspaces.filter((workspace) => workspace.status === "active").length,
      pending: workspaces.filter((workspace) => workspace.status === "pending").length
    },
    preKeys,
    sessions: {
      active: sessions.length
    },
    audit: {
      blocks: auditSummary.blockCount,
      latestHash: auditSummary.latestHash
    },
    files: {
      owned: files.length,
      shared: files.reduce((total, file) => total + (file.sharedWithCount || 0), 0)
    },
    storage: {
      usedBytes: storage.usedBytes,
      quotaBytes: storage.quotaBytes,
      availableBytes: storage.availableBytes
    }
  });
});

app.get("/storage-summary", requireAuth, (_req, res) => {
  const storage = storageQuotaSnapshot(res.locals.authUsername);
  res.json({
    usedBytes: storage.usedBytes,
    quotaBytes: storage.quotaBytes,
    availableBytes: storage.availableBytes
  });
});

app.get("/vault-files", requireAuth, (req, res) => {
  res.json({ files: listVaultFiles(res.locals.authUsername, { trashed: req.query.trash === "true" }) });
});

app.post("/vault-files", requireAuth, uploadMiddleware.single("fileBlob"), (req, res) => {
  const { encryptedMetadata, metadataIv, wrappedFileKey, wrappedFileKeyIv } = req.body;
  if (!req.file || !encryptedMetadata || !metadataIv || !wrappedFileKey || !wrappedFileKeyIv) {
    removeUploadedFile(req.file?.filename);
    res.status(400).json({ error: "Missing encrypted vault file components" });
    return;
  }
  if (![encryptedMetadata, metadataIv, wrappedFileKey, wrappedFileKeyIv].every(isLikelyEncryptedComponent)) {
    removeUploadedFile(req.file.filename);
    res.status(400).json({ error: "Invalid encrypted vault file components" });
    return;
  }

  const quota = storageQuotaSnapshot(res.locals.authUsername, req.file.size);
  if (!quota.allowed) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(res.locals.authUsername, "Vault Upload Blocked Quota");
    res.status(413).json({
      error: "Encrypted storage quota exceeded",
      usedBytes: quota.usedBytes,
      quotaBytes: quota.quotaBytes,
      projectedBytes: quota.projectedBytes
    });
    return;
  }

  const vaultFile: VaultFileRecord = {
    id: crypto.randomUUID(),
    filepath: req.file.filename,
    fileSize: req.file.size,
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrappedFileKeyIv,
    createdAt: Date.now()
  };

  addVaultFile(res.locals.authUsername, vaultFile);
  appendAuditLog(res.locals.authUsername, "Vault File Uploaded");
  res.json({ message: "Encrypted vault file stored", file: vaultFile });
});

app.post("/vault-file-upload-sessions", requireAuth, (req, res) => {
  cleanupExpiredVaultUploadSessions();

  const {
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrappedFileKeyIv,
    expectedChunks,
    expectedSize
  } = req.body;

  const normalizedExpectedChunks = Number(expectedChunks);
  const normalizedExpectedSize = Number(expectedSize);
  if (
    !encryptedMetadata ||
    !metadataIv ||
    !wrappedFileKey ||
    !wrappedFileKeyIv ||
    !Number.isInteger(normalizedExpectedChunks) ||
    normalizedExpectedChunks < 1 ||
    normalizedExpectedChunks > 250000 ||
    !Number.isInteger(normalizedExpectedSize) ||
    normalizedExpectedSize < 1 ||
    normalizedExpectedSize > UPLOAD_FILE_LIMIT_BYTES
  ) {
    res.status(400).json({ error: "Missing or invalid encrypted upload session components" });
    return;
  }

  if (![encryptedMetadata, metadataIv, wrappedFileKey, wrappedFileKeyIv].every(isLikelyEncryptedComponent)) {
    res.status(400).json({ error: "Invalid encrypted upload session components" });
    return;
  }

  const quota = storageQuotaSnapshot(res.locals.authUsername, normalizedExpectedSize);
  if (!quota.allowed) {
    appendAuditLog(res.locals.authUsername, "Vault Upload Blocked Quota");
    res.status(413).json({
      error: "Encrypted storage quota exceeded",
      usedBytes: quota.usedBytes,
      quotaBytes: quota.quotaBytes,
      projectedBytes: quota.projectedBytes
    });
    return;
  }

  const id = crypto.randomUUID();
  const dir = path.join(VAULT_CHUNK_SESSION_DIR, id);
  fs.mkdirSync(dir, { recursive: false });
  const now = Date.now();
  vaultUploadSessions.set(id, {
    id,
    ownerUsername: res.locals.authUsername,
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrappedFileKeyIv,
    expectedChunks: normalizedExpectedChunks,
    expectedSize: normalizedExpectedSize,
    receivedChunks: new Set<number>(),
    dir,
    createdAt: now,
    expiresAt: now + VAULT_UPLOAD_SESSION_TTL_MS
  });

  res.json({
    uploadSessionId: id,
    expiresAt: now + VAULT_UPLOAD_SESSION_TTL_MS,
    chunkLimitBytes: VAULT_CHUNK_UPLOAD_LIMIT_BYTES
  });
});

app.get("/vault-file-upload-sessions/:id", requireAuth, (req, res) => {
  cleanupExpiredVaultUploadSessions();
  const session = vaultUploadSessions.get(req.params.id);
  if (!session || session.ownerUsername !== res.locals.authUsername) {
    res.status(404).json({ error: "Upload session not found" });
    return;
  }

  res.json({
    uploadSessionId: session.id,
    expiresAt: session.expiresAt,
    expectedChunks: session.expectedChunks,
    receivedChunks: Array.from(session.receivedChunks).sort((a, b) => a - b),
    expectedSize: session.expectedSize
  });
});

app.post("/vault-file-upload-sessions/:id/chunks/:index", requireAuth, chunkUploadMiddleware.single("chunk"), (req, res) => {
  cleanupExpiredVaultUploadSessions();
  const session = vaultUploadSessions.get(req.params.id);
  const index = Number(req.params.index);

  if (!session || session.ownerUsername !== res.locals.authUsername) {
    removeMulterFile(req.file);
    res.status(404).json({ error: "Upload session not found" });
    return;
  }

  if (!req.file || !Number.isInteger(index) || index < 0 || index >= session.expectedChunks) {
    removeMulterFile(req.file);
    res.status(400).json({ error: "Invalid encrypted chunk upload" });
    return;
  }

  const targetPath = chunkPath(session, index);
  fs.rmSync(targetPath, { force: true });
  fs.renameSync(req.file.path, targetPath);
  session.receivedChunks.add(index);

  res.json({
    received: session.receivedChunks.size,
    expected: session.expectedChunks
  });
});

app.post("/vault-file-upload-sessions/:id/complete", requireAuth, async (req, res) => {
  cleanupExpiredVaultUploadSessions();
  const session = vaultUploadSessions.get(req.params.id);
  if (!session || session.ownerUsername !== res.locals.authUsername) {
    res.status(404).json({ error: "Upload session not found" });
    return;
  }

  if (session.receivedChunks.size !== session.expectedChunks) {
    res.status(409).json({
      error: "Upload session is missing encrypted chunks",
      received: session.receivedChunks.size,
      expected: session.expectedChunks
    });
    return;
  }

  for (let index = 0; index < session.expectedChunks; index += 1) {
    if (!fs.existsSync(chunkPath(session, index))) {
      res.status(409).json({ error: `Upload session is missing encrypted chunk ${index}` });
      return;
    }
  }

  const finalFilename = `${crypto.randomUUID()}.vault`;
  const finalPath = path.join(UPLOAD_DIR, finalFilename);
  try {
    await assembleVaultChunks(session, finalPath);
    const actualSize = fs.statSync(finalPath).size;
    if (actualSize !== session.expectedSize) {
      fs.rmSync(finalPath, { force: true });
      res.status(400).json({ error: "Encrypted upload size mismatch" });
      return;
    }

    const quota = storageQuotaSnapshot(res.locals.authUsername, actualSize);
    if (!quota.allowed) {
      fs.rmSync(finalPath, { force: true });
      appendAuditLog(res.locals.authUsername, "Vault Upload Blocked Quota");
      res.status(413).json({
        error: "Encrypted storage quota exceeded",
        usedBytes: quota.usedBytes,
        quotaBytes: quota.quotaBytes,
        projectedBytes: quota.projectedBytes
      });
      return;
    }

    const vaultFile: VaultFileRecord = {
      id: crypto.randomUUID(),
      filepath: finalFilename,
      fileSize: actualSize,
      encryptedMetadata: session.encryptedMetadata,
      metadataIv: session.metadataIv,
      wrappedFileKey: session.wrappedFileKey,
      wrappedFileKeyIv: session.wrappedFileKeyIv,
      createdAt: Date.now()
    };

    addVaultFile(res.locals.authUsername, vaultFile);
    vaultUploadSessions.delete(session.id);
    removePathRecursive(session.dir);
    appendAuditLog(res.locals.authUsername, "Vault File Uploaded In Chunks");
    res.json({ message: "Encrypted vault file stored", file: vaultFile });
  } catch {
    fs.rmSync(finalPath, { force: true });
    res.status(500).json({ error: "Unable to assemble encrypted vault file" });
  }
});

app.delete("/vault-file-upload-sessions/:id", requireAuth, (req, res) => {
  const session = vaultUploadSessions.get(req.params.id);
  if (!session || session.ownerUsername !== res.locals.authUsername) {
    res.status(404).json({ error: "Upload session not found" });
    return;
  }

  vaultUploadSessions.delete(session.id);
  removePathRecursive(session.dir);
  res.json({ message: "Encrypted upload session cancelled" });
});

app.patch("/vault-files/:id/metadata", requireAuth, (req, res) => {
  const file = findVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  const { encryptedMetadata, metadataIv, grantSignatures } = req.body;
  if (!encryptedMetadata || !metadataIv) {
    res.status(400).json({ error: "Missing encrypted metadata components" });
    return;
  }
  if (![encryptedMetadata, metadataIv].every(isLikelyEncryptedComponent)) {
    res.status(400).json({ error: "Invalid encrypted metadata components" });
    return;
  }

  if (grantSignatures !== undefined && !Array.isArray(grantSignatures)) {
    res.status(400).json({ error: "Grant signatures must be an array" });
    return;
  }

  const currentGrants = listVaultGrantsForFile(res.locals.authUsername, file.id);
  const submittedSignatures = (grantSignatures || []) as Partial<VaultGrantSignatureUpdate>[];
  const signatureByGrantId = new Map<string, string>();
  for (const entry of submittedSignatures) {
    if (!entry.grantId || !entry.signature || !isLikelyEncryptedComponent(entry.grantId) || !isLikelyEncryptedComponent(entry.signature)) {
      res.status(400).json({ error: "Invalid grant signature update" });
      return;
    }
    signatureByGrantId.set(entry.grantId, entry.signature);
  }

  if (signatureByGrantId.size !== currentGrants.length) {
    res.status(409).json({ error: "Metadata edits must refresh every active grant signature" });
    return;
  }

  for (const grant of currentGrants) {
    if (!signatureByGrantId.has(grant.id)) {
      res.status(409).json({ error: "Missing refreshed signature for an active grant" });
      return;
    }
  }

  const updatedFile = updateVaultFileMetadata(
    res.locals.authUsername,
    file.id,
    encryptedMetadata,
    metadataIv,
    currentGrants.map((grant) => ({
      grantId: grant.id,
      signature: signatureByGrantId.get(grant.id)!
    }))
  );
  if (!updatedFile) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Vault File Metadata Updated");
  res.json({ message: "Vault file metadata updated", file: updatedFile });
});

app.get("/vault-files/:id/download", requireAuth, (req, res) => {
  const file = findVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  const filepath = path.join(UPLOAD_DIR, file.filepath);
  if (!fs.existsSync(filepath)) {
    res.status(404).json({ error: "Encrypted vault blob not found" });
    return;
  }

  res.download(filepath);
});

app.delete("/vault-files/:id", requireAuth, (req, res) => {
  const file = trashVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Vault File Moved To Trash");
  res.json({ message: "Vault file moved to trash", file });
});

app.post("/vault-files/:id/restore", requireAuth, (req, res) => {
  const file = restoreVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Trashed vault file not found" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Vault File Restored");
  res.json({ message: "Vault file restored", file });
});

app.delete("/vault-files/:id/permanent", requireAuth, (req, res) => {
  const file = permanentlyDeleteVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  const filepath = path.join(UPLOAD_DIR, file.filepath);
  if (fs.existsSync(filepath)) {
    fs.unlinkSync(filepath);
  }

  appendAuditLog(res.locals.authUsername, "Vault File Permanently Deleted");
  res.json({ message: "Vault file permanently deleted" });
});

app.post("/vault-files/:id/share", requireAuth, (req, res) => {
  const file = findVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  const { recipientUsername, wrappedFileKey, ephemeralPublicKey, usedPreKey, signature } = req.body;
  if (!recipientUsername || !wrappedFileKey || !ephemeralPublicKey || !usedPreKey || !signature) {
    appendAuditLog(res.locals.authUsername, "Vault Share Blocked");
    res.status(400).json({ error: "Missing encrypted grant components" });
    return;
  }
  if (!isSafeUsername(recipientUsername) || ![wrappedFileKey, ephemeralPublicKey, usedPreKey, signature].every(isLikelyEncryptedComponent)) {
    appendAuditLog(res.locals.authUsername, "Vault Share Blocked");
    res.status(400).json({ error: "Invalid encrypted grant components" });
    return;
  }

  if (recipientUsername === res.locals.authUsername) {
    appendAuditLog(res.locals.authUsername, "Vault Share Blocked");
    res.status(400).json({ error: "Use your owner vault access for your own files" });
    return;
  }

  const grantResult = buildVaultGrant(res.locals.authUsername, file.id, {
    recipientUsername,
    wrappedFileKey,
    ephemeralPublicKey,
    usedPreKey,
    signature
  });
  if ("error" in grantResult) {
    appendAuditLog(res.locals.authUsername, "Vault Share Blocked");
    res.status(grantResult.status || 400).json({ error: grantResult.error });
    return;
  }

  try {
    addVaultGrant(grantResult.grant);
  } catch {
    res.status(409).json({ error: "File is already shared with this recipient" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Vault File Shared");
  res.json({ message: "Vault file shared", grant: grantResult.grant });
});

app.post("/vault-files/:id/rotate", requireAuth, uploadMiddleware.single("fileBlob"), (req, res) => {
  const file = findVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    removeUploadedFile(req.file?.filename);
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  const { encryptedMetadata, metadataIv, wrappedFileKey, wrappedFileKeyIv } = req.body;
  if (!req.file || !encryptedMetadata || !metadataIv || !wrappedFileKey || !wrappedFileKeyIv) {
    removeUploadedFile(req.file?.filename);
    res.status(400).json({ error: "Missing rotated vault file components" });
    return;
  }
  if (![encryptedMetadata, metadataIv, wrappedFileKey, wrappedFileKeyIv].every(isLikelyEncryptedComponent)) {
    removeUploadedFile(req.file.filename);
    res.status(400).json({ error: "Invalid rotated vault file components" });
    return;
  }

  let grantInputs: Partial<VaultGrantRecord>[] = [];
  try {
    const parsed = req.body.grants ? JSON.parse(req.body.grants) : [];
    if (!Array.isArray(parsed)) throw new Error("Grant set must be an array");
    grantInputs = parsed;
  } catch {
    removeUploadedFile(req.file.filename);
    res.status(400).json({ error: "Invalid replacement grant set" });
    return;
  }

  const seenRecipients = new Set<string>();
  const replacementGrants: VaultGrantRecord[] = [];
  for (const grantInput of grantInputs) {
    if (grantInput.recipientUsername && seenRecipients.has(grantInput.recipientUsername)) {
      removeUploadedFile(req.file.filename);
      res.status(409).json({ error: `Duplicate replacement grant for ${grantInput.recipientUsername}` });
      return;
    }

    const grantResult = buildVaultGrant(res.locals.authUsername, file.id, grantInput);
    if ("error" in grantResult) {
      removeUploadedFile(req.file.filename);
      res.status(grantResult.status || 400).json({ error: grantResult.error });
      return;
    }

    seenRecipients.add(grantResult.grant.recipientUsername);
    replacementGrants.push(grantResult.grant);
  }

  const quota = storageQuotaSnapshot(res.locals.authUsername, req.file.size, file.fileSize);
  if (!quota.allowed) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(res.locals.authUsername, "Vault Upload Blocked Quota");
    res.status(413).json({
      error: "Encrypted storage quota exceeded",
      usedBytes: quota.usedBytes,
      quotaBytes: quota.quotaBytes,
      projectedBytes: quota.projectedBytes
    });
    return;
  }

  const rotatedFile: VaultFileRecord = {
    ...file,
    filepath: req.file.filename,
    fileSize: req.file.size,
    encryptedMetadata,
    metadataIv,
    wrappedFileKey,
    wrappedFileKeyIv
  };

  try {
    const previousFile = rotateVaultFile(res.locals.authUsername, rotatedFile, replacementGrants);
    if (!previousFile) {
      removeUploadedFile(req.file.filename);
      res.status(404).json({ error: "Vault file not found" });
      return;
    }

    if (previousFile.filepath !== req.file.filename) {
      removeUploadedFile(previousFile.filepath);
    }
  } catch {
    removeUploadedFile(req.file.filename);
    res.status(500).json({ error: "Unable to rotate vault file" });
    return;
  }

  appendAuditLog(res.locals.authUsername, "Vault File Rotated");
  res.json({ message: "Vault file rotated", file: rotatedFile, grants: replacementGrants });
});

app.get("/vault-files/:id/grants", requireAuth, (req, res) => {
  const file = findVaultFile(res.locals.authUsername, req.params.id);
  if (!file) {
    res.status(404).json({ error: "Vault file not found" });
    return;
  }

  res.json({ grants: listVaultGrantsForFile(res.locals.authUsername, req.params.id) });
});

app.get("/shared-vault-files", requireAuth, (req, res) => {
  res.json({ files: listSharedVaultFiles(res.locals.authUsername) });
});

app.get("/shared-vault-files/:grantId/download", requireAuth, (req, res) => {
  const grant = findSharedVaultFile(res.locals.authUsername, req.params.grantId);
  if (!grant) {
    res.status(404).json({ error: "Shared vault file not found" });
    return;
  }

  const file = findVaultFileById(grant.vaultFileId);
  if (!file) {
    res.status(404).json({ error: "Shared vault file missing" });
    return;
  }

  const filepath = path.join(UPLOAD_DIR, file.filepath);
  if (!fs.existsSync(filepath)) {
    res.status(404).json({ error: "Encrypted vault blob not found" });
    return;
  }

  res.download(filepath);
});

app.get("/identity/:username", requireAuth, requireSelf, (req, res) => {
  const { username } = req.params;
  const userRecord = getUser(username);
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({
    salt: userRecord.salt,
    encryptedPrivateKeyECDH: userRecord.encryptedPrivateKeyECDH,
    ivECDH: userRecord.ivECDH,
    encryptedPrivateKeyECDSA: userRecord.encryptedPrivateKeyECDSA,
    ivECDSA: userRecord.ivECDSA,
    role: userRecord.role || "member",
    approvedAt: userRecord.approvedAt || null,
    approvedBy: userRecord.approvedBy || null
  });
});

app.post("/upload", requireAuth, uploadMiddleware.single("fileBlob"), (req, res) => {
  const { recipientUsername, senderUsername, signature, fileIv, wrappedFileKey, ephemeralPublicKey, usedPreKey, originalFilename } = req.body;
  if (!recipientUsername || !senderUsername || !signature || !req.file || !fileIv || !wrappedFileKey || !ephemeralPublicKey || !usedPreKey) {
    removeUploadedFile(req.file?.filename);
    appendAuditLog(res.locals.authUsername || "anonymous", "Dispatch Blocked");
    res.status(400).json({ error: "Missing file package components" });
    return;
  }
  if (!isSafeUsername(recipientUsername) || !isSafeUsername(senderUsername) || ![signature, fileIv, wrappedFileKey, ephemeralPublicKey, usedPreKey].every(isLikelyEncryptedComponent)) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(res.locals.authUsername, "Dispatch Blocked");
    res.status(400).json({ error: "Invalid file package components" });
    return;
  }
  if (senderUsername !== res.locals.authUsername) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(res.locals.authUsername, "Dispatch Blocked");
    res.status(403).json({ error: "Sender does not match authenticated identity" });
    return;
  }
  const recipient = getUser(recipientUsername);
  if (!recipient) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(senderUsername, "Dispatch Blocked");
    res.status(404).json({ error: "Recipient not found" });
    return;
  }
  if (recipient.revokedAt) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(senderUsername, "Dispatch Blocked");
    res.status(410).json({ error: "Recipient identity has been revoked" });
    return;
  }
  if (!usersShareActiveWorkspace(senderUsername, recipientUsername)) {
    removeUploadedFile(req.file.filename);
    appendAuditLog(senderUsername, "Dispatch Blocked");
    res.status(403).json({ error: "Recipient is not an active member of a shared workspace" });
    return;
  }
  
  console.log(`\n--- NEW FILE UPLOAD ---`);
  console.log(`Target Recipient: ${recipientUsername}`);
  console.log(`Encrypted Data Path: ${req.file.path} (Simulated Disk Storage)`);
  console.log(`Wrapped File Key (Hex): ${wrappedFileKey}`);
  console.log(`Ephemeral Sender PubKey: ${ephemeralPublicKey.slice(0, 30)}...`);
  console.log(`Used Recipient Pre-Key: ${usedPreKey.slice(0, 30)}...`);
  console.log(`-----------------------\n`);

  // Locate the specific private key data for Bob to decrypt later
  const matchingPreKey = getPreKey(recipientUsername, usedPreKey);
  
  const inboxFile: InboxRecord = {
    filepath: req.file.filename,
    originalFilename: originalFilename || "EncryptedFile.bin",
    fileSize: req.file.size,
    fileIv,
    wrappedFileKey,
    ephemeralPublicKey,
    usedPreKey,
    senderUsername,
    signature,
    encryptedPrivatePreKey: matchingPreKey ? matchingPreKey.encryptedPrivateKey : null,
    preKeyIv: matchingPreKey ? matchingPreKey.iv : null,
    timestamp: Date.now()
  };
  addInboxFile(recipientUsername, inboxFile);

  appendAuditLog(recipientUsername, "File Package Encrypted & Uploaded");

  res.json({ message: "File accurately packaged and securely uploaded!" });
});

app.get("/audit-log", requireAuth, (req, res) => {
  res.json(buildVisibleAuditView(res.locals.authUsername));
});

app.get("/audit-anchor", requireAuth, (req, res) => {
  const visibleEntries = buildVisibleAuditView(res.locals.authUsername);
  const summary = visibleAuditSummary(visibleEntries);
  const exportedAt = Date.now();
  const digestPayload = JSON.stringify([
    "crypshare-visible-audit-anchor-v1",
    res.locals.authUsername,
    summary.blockCount,
    summary.firstHash,
    summary.latestHash,
    summary.firstTimestamp,
    summary.latestTimestamp
  ]);
  const ledgerDigest = sha256Hex(digestPayload);

  res.json({
    version: 1,
    exportedAt,
    scope: "visible-user-and-admin-workspaces",
    ...summary,
    ledgerDigest
  });
});

app.get("/inbox/:username", requireAuth, requireSelf, (req, res) => {
  const { username } = req.params;
  const userRecord = getUser(username);
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({ inbox: listInbox(username), salt: userRecord.salt });
});

app.get("/download-file/:filename", requireAuth, (req, res) => {
  const authUsername = res.locals.authUsername as string;
  const inboxEntry = findInboxFile(authUsername, req.params.filename);

  if (!inboxEntry) {
    res.status(403).json({ error: "Not authorized to download this file" });
    return;
  }

  const filepath = path.join(UPLOAD_DIR, req.params.filename);
  if (!fs.existsSync(filepath)) {
    res.status(404).json({ error: "File not found" });
    return;
  }
  res.download(filepath);
});

app.use((err: unknown, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  const requestId = res.locals.requestId;
  if (err instanceof multer.MulterError) {
    const tooLarge = err.code === "LIMIT_FILE_SIZE" || err.code === "LIMIT_FIELD_VALUE";
    res.status(tooLarge ? 413 : 400).json({
      error: tooLarge ? "Encrypted upload exceeds configured size limits" : "Invalid encrypted upload package",
      requestId
    });
    return;
  }

  if (typeof err === "object" && err && "type" in err && err.type === "entity.too.large") {
    res.status(413).json({ error: "Request body exceeds configured size limits", requestId });
    return;
  }

  console.error(JSON.stringify({
    event: "unhandled_error",
    requestId,
    path: req.path,
    message: err instanceof Error ? err.message : "Unknown error"
  }));
  res.status(500).json({ error: "Internal server error", requestId });
});

const originalListen = app.listen.bind(app);
app.listen = ((...args: Parameters<typeof app.listen>) => {
  const server = originalListen(...args);
  attachP2PSignaling(server);
  return server;
}) as typeof app.listen;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
  });
}
