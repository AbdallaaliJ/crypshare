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
  getAuditLog,
  getAuditSummary,
  getLastAuditHash,
  getPreKey,
  getPreKeyStatus,
  getSessionByTokenHash,
  getUser,
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

const UPLOAD_DIR = path.join(__dirname, "../uploads");
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "256kb";
const DEFAULT_UPLOAD_FILE_LIMIT_BYTES = 15 * 1024 * 1024 * 1024;
const UPLOAD_FILE_LIMIT_BYTES = Number(process.env.UPLOAD_FILE_LIMIT_BYTES || DEFAULT_UPLOAD_FILE_LIMIT_BYTES);
const UPLOAD_FIELD_LIMIT_BYTES = Number(process.env.UPLOAD_FIELD_LIMIT_BYTES || 1024 * 256);
const GENERAL_RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 1000 * 60);
const GENERAL_RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 600);
const AUTH_RATE_LIMIT_WINDOW_MS = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 1000 * 60 * 5);
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX || 30);
const WORKSPACE_INVITE_TTL_MS = Math.max(Number(process.env.WORKSPACE_INVITE_TTL_MS || 1000 * 60 * 60 * 24 * 7), 1000 * 60 * 5);
const P2P_SESSION_TTL_MS = Math.max(Number(process.env.P2P_SESSION_TTL_MS || 1000 * 60 * 15), 1000 * 60);
const P2P_STUN_URLS = (process.env.P2P_STUN_URLS || "stun:stun.l.google.com:19302")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);
const P2P_TURN_URLS = (process.env.P2P_TURN_URLS || "")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);
const P2P_TURN_USERNAME = process.env.P2P_TURN_USERNAME || "";
const P2P_TURN_CREDENTIAL = process.env.P2P_TURN_CREDENTIAL || "";
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const uploadMiddleware = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: UPLOAD_FILE_LIMIT_BYTES,
    fieldSize: UPLOAD_FIELD_LIMIT_BYTES,
    files: 1,
    fields: 32
  }
});
export const app = express();
const PORT = Number(process.env.PORT || 3001);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 8);
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
app.use(cors({
  origin: CORS_ORIGINS.length > 0 ? CORS_ORIGINS : true
}));
app.use(requestContext);
app.use(securityHeaders);
app.use(createRateLimiter("general", GENERAL_RATE_LIMIT_WINDOW_MS, GENERAL_RATE_LIMIT_MAX));
app.use(requestLogger);
app.use(express.json({ limit: JSON_BODY_LIMIT }));

interface AuditEntry {
  timestamp: number;
  userId: string;
  action: string;
  previousHash: string;
  hash: string;
}

const GENESIS_HASH = "0".repeat(64);
const rateLimitBuckets = new Map<string, { count: number; resetAt: number }>();

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
  return { token, id, expiresAt };
}

function cleanupExpiredSessions() {
  cleanupExpiredSessionRecords();
}

function getBearerToken(req: express.Request) {
  const authHeader = req.headers.authorization;
  return authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length) : "";
}

function getSession(req: express.Request) {
  const token = getBearerToken(req);
  return getSessionFromToken(token);
}

function getSessionFromToken(token: string) {
  if (!token) return null;

  const tokenHash = sha256Hex(token);
  const session = getSessionByTokenHash(tokenHash);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    deleteSessionByTokenHash(tokenHash);
    return null;
  }

  return { token, tokenHash, session };
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

function appendAuditLog(userId: string, action: string) {
  const previousHash = getLastAuditHash() || GENESIS_HASH;
  const timestamp = Date.now();
  
  const payload = JSON.stringify([timestamp, userId, action]) + previousHash;
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  
  appendAuditEntry({ timestamp, userId, action, previousHash, hash });
  console.log(`[AUDIT LOG] ${action} -> [Hash: ${hash.substring(0, 8)}...]`);
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

    const token = requestUrl.searchParams.get("token") || "";
    const authSession = getSessionFromToken(token);
    if (!authSession) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    const userRecord = getUser(authSession.session.username);
    if (!userRecord || userRecord.revokedAt) {
      deleteSessionByTokenHash(authSession.tokenHash);
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    websocketServer.handleUpgrade(req, socket, head, (ws) => {
      websocketServer.emit("connection", ws, req, authSession.session.username);
    });
  });

  websocketServer.on("connection", (socket: WebSocket, _req: http.IncomingMessage, username: string) => {
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
        appendAuditLog(username, "P2P Invite Created");

        const delivered = routeP2PMessage(recipientUsername, {
          type: "p2p-invite",
          sessionId,
          senderUsername: username,
          relayAllowed: session.relayAllowed,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt
        });
        socket.send(JSON.stringify({
          type: "p2p-invite-created",
          sessionId,
          recipientUsername,
          delivered,
          relayAllowed: session.relayAllowed,
          expiresAt: session.expiresAt
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
          appendAuditLog(username, "P2P Declined");
          routeP2PMessage(session.senderUsername, {
            type: "p2p-declined",
            sessionId: session.id,
            recipientUsername: username
          });
          return;
        }

        appendAuditLog(username, "P2P Accepted");
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
          appendAuditLog(username, "P2P Completed");
          p2pSessions.delete(session.id);
        }
        if (signalType === "failed") {
          appendAuditLog(username, "P2P Failed");
          p2pSessions.delete(session.id);
        }

        const targetUsername = username === session.senderUsername ? session.recipientUsername : session.senderUsername;
        routeP2PMessage(targetUsername, {
          type: "p2p-signal",
          sessionId: session.id,
          fromUsername: username,
          signalType,
          payload: message.payload || null
        });
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
    mode: "single-request",
    note: "Current public-beta uploads are single encrypted multipart requests. Multi-terabyte files need resumable encrypted chunk upload."
  });
});

app.get("/p2p/ice-config", requireAuth, (_req, res) => {
  const iceServers: RTCIceServer[] = [];
  if (P2P_STUN_URLS.length > 0) {
    iceServers.push({ urls: P2P_STUN_URLS });
  }
  if (P2P_TURN_URLS.length > 0 && P2P_TURN_USERNAME && P2P_TURN_CREDENTIAL) {
    iceServers.push({
      urls: P2P_TURN_URLS,
      username: P2P_TURN_USERNAME,
      credential: P2P_TURN_CREDENTIAL
    });
  }

  res.json({
    iceServers,
    directOnlyIceServers: P2P_STUN_URLS.length > 0 ? [{ urls: P2P_STUN_URLS }] : [],
    turnConfigured: P2P_TURN_URLS.length > 0 && !!P2P_TURN_USERNAME && !!P2P_TURN_CREDENTIAL,
    sessionTtlMs: P2P_SESSION_TTL_MS,
    privacyNote: "CrypShare signaling does not store file bytes, file names, file types, or decrypted metadata."
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
  appendAuditLog(username, "Session Established");
  res.json(session);
});

app.get("/sessions", requireAuth, (req, res) => {
  res.json({
    sessions: listUserSessions(res.locals.authUsername, res.locals.authSessionId)
  });
});

app.delete("/sessions/current", requireAuth, (req, res) => {
  deleteSessionByTokenHash(res.locals.authTokenHash);
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
  appendAuditLog(res.locals.authUsername, "Workspace Created");
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

  appendAuditLog(res.locals.authUsername, "Workspace Join Requested");
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

  appendAuditLog(res.locals.authUsername, "Workspace Invite Rotated");
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

  appendAuditLog(req.params.username, "Workspace Member Approved");
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

  appendAuditLog(req.params.username, "Workspace Member Revoked");
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

  appendAuditLog(req.params.username, "Workspace Member Role Changed");
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
  const auditSummary = getAuditSummary();
  const files = listVaultFiles(res.locals.authUsername);

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
    }
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
  res.json(getAuditLog());
});

app.get("/audit-anchor", requireAuth, (req, res) => {
  const summary = getAuditSummary();
  const exportedAt = Date.now();
  const digestPayload = JSON.stringify([
    "crypshare-audit-anchor-v1",
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
