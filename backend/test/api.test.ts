import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import WebSocket from "ws";

let baseUrl = "";
let server: http.Server;
let tempDir = "";
let closeDatabase: (() => void) | undefined;

function sha256Hex(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function authHeaders(token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function cookieHeaderFromSetCookie(setCookie: string) {
  return setCookie
    .split(/,\s*(?=[^;,]+=)/)
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
}

function userPayload(username: string, authSecret = "correct-auth-secret") {
  return {
    username,
    salt: `${username}-salt`,
    authSalt: `${username}-auth-salt`,
    authVerifierHash: sha256Hex(authSecret),
    identityPublicKeyECDH: `${username}-identity-ecdh`,
    identityPublicKeyECDSA: `${username}-identity-ecdsa`,
    encryptedPrivateKeyECDH: `${username}-encrypted-ecdh`,
    ivECDH: `${username}-iv-ecdh`,
    encryptedPrivateKeyECDSA: `${username}-encrypted-ecdsa`,
    ivECDSA: `${username}-iv-ecdsa`
  };
}

function identityFingerprint(username: string) {
  const payload = userPayload(username);
  return sha256Hex([
    "crypshare-identity-v1",
    username,
    payload.identityPublicKeyECDH,
    payload.identityPublicKeyECDSA
  ].join(":"));
}

async function request(pathname: string, options: RequestInit = {}) {
  return fetch(`${baseUrl}${pathname}`, options);
}

async function requestJson(pathname: string, options: RequestInit = {}) {
  const res = await request(pathname, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await res.json();
  return { res, body };
}

async function register(username: string) {
  return requestJson("/register", {
    method: "POST",
    body: JSON.stringify(userPayload(username))
  });
}

async function login(username: string, authSecret = "correct-auth-secret") {
  const { res, body } = await requestJson("/sessions", {
    method: "POST",
    body: JSON.stringify({ username, authSecret })
  });
  assert.equal(res.status, 200);
  assert.equal(typeof body.token, "string");
  return body.token as string;
}

function createWsInbox(socket: WebSocket) {
  const queue: Record<string, unknown>[] = [];
  const waiters: Array<{
    resolve: (value: Record<string, unknown>) => void;
    reject: (reason?: unknown) => void;
    timer: NodeJS.Timeout;
  }> = [];

  socket.on("message", (data) => {
    const message = JSON.parse(data.toString()) as Record<string, unknown>;
    const waiter = waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(message);
      return;
    }
    queue.push(message);
  });

  return {
    next(timeoutMs = 2000) {
      const queued = queue.shift();
      if (queued) return Promise.resolve(queued);

      return new Promise<Record<string, unknown>>((resolve, reject) => {
        const waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            const index = waiters.indexOf(waiter);
            if (index >= 0) waiters.splice(index, 1);
            reject(new Error("Timed out waiting for WebSocket message."));
          }, timeoutMs)
        };
        waiters.push(waiter);
      });
    }
  };
}

async function openP2PSocket(token: string) {
  const ticket = await requestJson("/p2p/signaling-ticket", {
    method: "POST",
    headers: authHeaders(token)
  });
  assert.equal(ticket.res.status, 200);
  const wsUrl = baseUrl.replace("http://", "ws://");
  const socket = new WebSocket(`${wsUrl}/p2p/signaling?ticket=${encodeURIComponent(ticket.body.ticket)}`);
  const inbox = createWsInbox(socket);
  await new Promise<void>((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  const ready = await inbox.next();
  assert.equal(ready.type, "p2p-ready");
  return { socket, next: inbox.next };
}

before(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "crypshare-api-"));
  process.env.DATABASE_FILE = path.join(tempDir, "test.db");
  process.env.LEGACY_STATE_FILE = path.join(tempDir, "state.json");
  process.env.SESSION_TTL_MS = String(1000 * 60 * 60);
  process.env.SESSION_COOKIE_ENABLED = "true";
  process.env.SESSION_COOKIE_SECRET = "test-cookie-secret-that-is-long-enough-for-csrf";
  process.env.SESSION_COOKIE_SECURE = "false";
  process.env.USER_STORAGE_QUOTA_BYTES = "1000";

  const appModule = await import("../src/index");
  const databaseModule = await import("../src/database");
  closeDatabase = databaseModule.closeDatabase;

  server = appModule.app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));

  const address = server.address();
  assert.ok(address && typeof address === "object");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
  closeDatabase?.();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test("API enforces auth, authorization, pre-key state, and audit integrity", async () => {
  const root = await request("/");
  assert.equal(root.status, 200);
  assert.equal(root.headers.get("cache-control"), "no-store");
  const rootBody = await root.json();
  assert.equal(rootBody.name, "CrypShare API");

  const health = await request("/health");
  assert.equal(health.status, 200);
  assert.equal(health.headers.get("x-content-type-options"), "nosniff");
  assert.equal(health.headers.get("x-frame-options"), "DENY");
  assert.ok(health.headers.get("x-request-id"));
  assert.equal(health.headers.get("cache-control"), "no-store");

  const uploadLimits = await requestJson("/upload-limits");
  assert.equal(uploadLimits.res.status, 200);
  assert.equal(typeof uploadLimits.body.uploadFileLimitBytes, "number");
  assert.equal(typeof uploadLimits.body.vaultChunkUploadLimitBytes, "number");
  assert.equal(uploadLimits.body.mode, "resumable-encrypted-chunks");

  const oversizedBody = await requestJson("/register", {
    method: "POST",
    body: JSON.stringify({ payload: "x".repeat(300 * 1024) })
  });
  assert.equal(oversizedBody.res.status, 413);

  const anonymousAudit = await request("/audit-log");
  assert.equal(anonymousAudit.status, 401);
  const anonymousSummary = await request("/security-summary");
  assert.equal(anonymousSummary.status, 401);
  const anonymousStorage = await request("/storage-summary");
  assert.equal(anonymousStorage.status, 401);
  const anonymousUploadSession = await requestJson("/vault-file-upload-sessions", {
    method: "POST",
    body: JSON.stringify({})
  });
  assert.equal(anonymousUploadSession.res.status, 401);
  const anonymousP2PIce = await request("/p2p/ice-config");
  assert.equal(anonymousP2PIce.status, 401);
  const anonymousP2PTicket = await request("/p2p/signaling-ticket", { method: "POST" });
  assert.equal(anonymousP2PTicket.status, 401);
  const anonymousP2PIdentity = await request("/p2p/identity/alice");
  assert.equal(anonymousP2PIdentity.status, 401);

  const aliceRegister = await register("alice");
  assert.equal(aliceRegister.res.status, 200);
  assert.equal(aliceRegister.body.approved, true);
  assert.equal(aliceRegister.body.role, "admin");

  const duplicateAlice = await register("alice");
  assert.equal(duplicateAlice.res.status, 409);

  const material = await requestJson("/session-material/alice");
  assert.equal(material.res.status, 200);
  assert.equal(material.body.salt, "alice-salt");
  assert.equal(material.body.authSalt, "alice-auth-salt");

  const badSession = await requestJson("/sessions", {
    method: "POST",
    body: JSON.stringify({ username: "alice", authSecret: "wrong-secret" })
  });
  assert.equal(badSession.res.status, 401);

  let aliceToken = await login("alice");

  const cookieSession = await requestJson("/sessions", {
    method: "POST",
    body: JSON.stringify({ username: "alice", authSecret: "correct-auth-secret" })
  });
  assert.equal(cookieSession.res.status, 200);
  assert.equal(cookieSession.body.cookieSession, true);
  assert.equal(typeof cookieSession.body.csrfToken, "string");
  const setCookie = cookieSession.res.headers.get("set-cookie");
  assert.ok(setCookie?.includes("__Host-crypshare_session="));
  assert.ok(setCookie?.includes("__Host-crypshare_csrf="));
  const cookieHeader = cookieHeaderFromSetCookie(setCookie || "");

  const cookieGetSessions = await requestJson("/sessions", {
    headers: { Cookie: cookieHeader }
  });
  assert.equal(cookieGetSessions.res.status, 200);

  const cookiePostWithoutCsrf = await requestJson("/p2p/signaling-ticket", {
    method: "POST",
    headers: { Cookie: cookieHeader }
  });
  assert.equal(cookiePostWithoutCsrf.res.status, 403);

  const cookiePostWithCsrf = await requestJson("/p2p/signaling-ticket", {
    method: "POST",
    headers: {
      Cookie: cookieHeader,
      "X-CSRF-Token": cookieSession.body.csrfToken
    }
  });
  assert.equal(cookiePostWithCsrf.res.status, 200);

  const p2pIceConfig = await requestJson("/p2p/ice-config", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(p2pIceConfig.res.status, 200);
  assert.equal(Array.isArray(p2pIceConfig.body.iceServers), true);
  assert.equal(typeof p2pIceConfig.body.turnConfigured, "boolean");

  const p2pTicket = await requestJson("/p2p/signaling-ticket", {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(p2pTicket.res.status, 200);
  assert.equal(typeof p2pTicket.body.ticket, "string");
  assert.equal(typeof p2pTicket.body.expiresAt, "number");

  const aliceP2PIdentity = await requestJson("/p2p/identity/alice", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(aliceP2PIdentity.res.status, 200);
  assert.equal(aliceP2PIdentity.body.identityPublicKeyECDH, "alice-identity-ecdh");

  const anonymousIdentity = await request("/identity/alice");
  assert.equal(anonymousIdentity.status, 401);

  const aliceIdentity = await requestJson("/identity/alice", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(aliceIdentity.res.status, 200);
  assert.equal(aliceIdentity.body.encryptedPrivateKeyECDH, "alice-encrypted-ecdh");
  assert.equal(aliceIdentity.body.role, "admin");

  const aliceSecondToken = await login("alice");
  const aliceSessions = await requestJson("/sessions", {
    headers: authHeaders(aliceSecondToken)
  });
  assert.equal(aliceSessions.res.status, 200);
  assert.equal(aliceSessions.body.sessions.length, 3);
  assert.equal(aliceSessions.body.sessions.filter((session: { current: boolean }) => session.current).length, 1);

  const revokeOthers = await requestJson("/sessions/revoke-others", {
    method: "POST",
    headers: authHeaders(aliceSecondToken)
  });
  assert.equal(revokeOthers.res.status, 200);
  assert.equal(revokeOthers.body.revoked, 2);

  const revokedOldToken = await request("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(revokedOldToken.status, 401);
  aliceToken = aliceSecondToken;

  const anonymousVault = await request("/vault-files");
  assert.equal(anonymousVault.status, 401);

  const vaultForm = new FormData();
  vaultForm.append("encryptedMetadata", "encrypted-name-and-type");
  vaultForm.append("metadataIv", "metadata-iv");
  vaultForm.append("wrappedFileKey", "wrapped-file-key");
  vaultForm.append("wrappedFileKeyIv", "wrapped-file-key-iv");
  vaultForm.append("fileBlob", new Blob(["encrypted-vault-bytes"]), "cipher.bin");

  const vaultUpload = await request("/vault-files", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: vaultForm
  });
  const vaultUploadBody = await vaultUpload.json();
  assert.equal(vaultUpload.status, 200);
  assert.equal(vaultUploadBody.file.encryptedMetadata, "encrypted-name-and-type");

  const vaultList = await requestJson("/vault-files", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(vaultList.res.status, 200);
  assert.equal(vaultList.body.files.length, 1);
  assert.equal(vaultList.body.files[0].wrappedFileKey, "wrapped-file-key");

  const storageAfterVaultUpload = await requestJson("/storage-summary", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(storageAfterVaultUpload.res.status, 200);
  assert.equal(storageAfterVaultUpload.body.quotaBytes, 1000);
  assert.ok(storageAfterVaultUpload.body.usedBytes > 0);

  const quotaBlockedSession = await requestJson("/vault-file-upload-sessions", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      encryptedMetadata: "quota-meta",
      metadataIv: "quota-iv",
      wrappedFileKey: "quota-key",
      wrappedFileKeyIv: "quota-key-iv",
      expectedChunks: 1,
      expectedSize: 2000
    })
  });
  assert.equal(quotaBlockedSession.res.status, 413);
  assert.equal(quotaBlockedSession.body.error, "Encrypted storage quota exceeded");

  const chunkOne = new Blob(["encrypted-chunk-one"]);
  const chunkTwo = new Blob(["encrypted-chunk-two"]);
  const chunkSession = await requestJson("/vault-file-upload-sessions", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      encryptedMetadata: "chunked-meta",
      metadataIv: "chunked-iv",
      wrappedFileKey: "chunked-key",
      wrappedFileKeyIv: "chunked-key-iv",
      expectedChunks: 2,
      expectedSize: chunkOne.size + chunkTwo.size
    })
  });
  assert.equal(chunkSession.res.status, 200);
  assert.equal(typeof chunkSession.body.uploadSessionId, "string");

  const chunkOneForm = new FormData();
  chunkOneForm.append("chunk", chunkOne, "0.chunk");
  const chunkOneUpload = await request(`/vault-file-upload-sessions/${chunkSession.body.uploadSessionId}/chunks/0`, {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: chunkOneForm
  });
  assert.equal(chunkOneUpload.status, 200);

  const chunkSessionStatus = await requestJson(`/vault-file-upload-sessions/${chunkSession.body.uploadSessionId}`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(chunkSessionStatus.res.status, 200);
  assert.deepEqual(chunkSessionStatus.body.receivedChunks, [0]);

  const chunkTwoForm = new FormData();
  chunkTwoForm.append("chunk", chunkTwo, "1.chunk");
  const chunkTwoUpload = await request(`/vault-file-upload-sessions/${chunkSession.body.uploadSessionId}/chunks/1`, {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: chunkTwoForm
  });
  assert.equal(chunkTwoUpload.status, 200);

  const chunkComplete = await requestJson(`/vault-file-upload-sessions/${chunkSession.body.uploadSessionId}/complete`, {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(chunkComplete.res.status, 200);

  const chunkedDownload = await request(`/vault-files/${chunkComplete.body.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(chunkedDownload.status, 200);
  assert.equal(await chunkedDownload.text(), "encrypted-chunk-oneencrypted-chunk-two");

  const vaultMetadataUpdate = await requestJson(`/vault-files/${vaultUploadBody.file.id}/metadata`, {
    method: "PATCH",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      encryptedMetadata: "updated-encrypted-name-and-folder",
      metadataIv: "updated-metadata-iv",
      grantSignatures: []
    })
  });
  assert.equal(vaultMetadataUpdate.res.status, 200);
  assert.equal(vaultMetadataUpdate.body.file.encryptedMetadata, "updated-encrypted-name-and-folder");
  assert.equal(vaultMetadataUpdate.body.file.metadataIv, "updated-metadata-iv");

  const vaultDownload = await request(`/vault-files/${vaultUploadBody.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(vaultDownload.status, 200);
  assert.equal(await vaultDownload.text(), "encrypted-vault-bytes");

  const vaultDelete = await requestJson(`/vault-files/${vaultUploadBody.file.id}`, {
    method: "DELETE",
    headers: authHeaders(aliceToken)
  });
  assert.equal(vaultDelete.res.status, 200);
  assert.equal(typeof vaultDelete.body.file.deletedAt, "number");

  const deletedVaultDownload = await request(`/vault-files/${vaultUploadBody.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(deletedVaultDownload.status, 404);

  const trashedVaultList = await requestJson("/vault-files?trash=true", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(trashedVaultList.res.status, 200);
  assert.equal(trashedVaultList.body.files.some((file: { id: string }) => file.id === vaultUploadBody.file.id), true);

  const vaultRestore = await requestJson(`/vault-files/${vaultUploadBody.file.id}/restore`, {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(vaultRestore.res.status, 200);
  assert.equal(vaultRestore.body.file.deletedAt, null);

  const restoredVaultDownload = await request(`/vault-files/${vaultUploadBody.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(restoredVaultDownload.status, 200);
  assert.equal(await restoredVaultDownload.text(), "encrypted-vault-bytes");

  const vaultPermanentDelete = await requestJson(`/vault-files/${vaultUploadBody.file.id}/permanent`, {
    method: "DELETE",
    headers: authHeaders(aliceToken)
  });
  assert.equal(vaultPermanentDelete.res.status, 200);

  const permanentlyDeletedVaultDownload = await request(`/vault-files/${vaultUploadBody.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(permanentlyDeletedVaultDownload.status, 404);

  const bobRegister = await register("bob");
  assert.equal(bobRegister.res.status, 200);
  assert.equal(bobRegister.body.approved, true);
  assert.equal(bobRegister.body.role, "member");

  const bobMaterial = await requestJson("/session-material/bob");
  assert.equal(bobMaterial.res.status, 200);

  const bobToken = await login("bob");

  const aliceP2P = await openP2PSocket(aliceToken);
  const bobP2P = await openP2PSocket(bobToken);
  try {
    aliceP2P.socket.send(JSON.stringify({
      type: "p2p-invite",
      recipientUsername: "bob",
      recipientFingerprint: identityFingerprint("bob"),
      relayAllowed: false
    }));
    const createdInvite = await aliceP2P.next();
    assert.equal(createdInvite.type, "p2p-invite-created");
    assert.equal(createdInvite.recipientUsername, "bob");
    assert.equal(typeof createdInvite.sessionId, "string");
    const inviteSessionId = createdInvite.sessionId as string;

    const incomingInvite = await bobP2P.next();
    assert.equal(incomingInvite.type, "p2p-invite");
    assert.equal(incomingInvite.sessionId, inviteSessionId);
    assert.equal(incomingInvite.senderUsername, "alice");

    const deliveryNotice = await aliceP2P.next();
    assert.equal(deliveryNotice.type, "p2p-invite-delivery");
    assert.equal(deliveryNotice.sessionId, inviteSessionId);
    assert.equal(deliveryNotice.delivered, true);

    bobP2P.socket.send(JSON.stringify({ type: "p2p-accept", sessionId: inviteSessionId }));
    const acceptedNotice = await aliceP2P.next();
    assert.equal(acceptedNotice.type, "p2p-accepted");
    assert.equal(acceptedNotice.sessionId, inviteSessionId);

    aliceP2P.socket.send(JSON.stringify({
      type: "p2p-signal",
      sessionId: inviteSessionId,
      signalType: "offer",
      payload: { type: "offer", sdp: "fake-offer" }
    }));
    const offerSignal = await bobP2P.next();
    assert.equal(offerSignal.type, "p2p-signal");
    assert.equal(offerSignal.signalType, "offer");
    assert.equal(offerSignal.fromUsername, "alice");

    bobP2P.socket.send(JSON.stringify({
      type: "p2p-signal",
      sessionId: inviteSessionId,
      signalType: "answer",
      payload: { type: "answer", sdp: "fake-answer" }
    }));
    const answerSignal = await aliceP2P.next();
    assert.equal(answerSignal.type, "p2p-signal");
    assert.equal(answerSignal.signalType, "answer");
    assert.equal(answerSignal.fromUsername, "bob");

    bobP2P.socket.send(JSON.stringify({
      type: "p2p-signal",
      sessionId: inviteSessionId,
      signalType: "ice",
      payload: { candidate: "candidate:1 1 udp 1 127.0.0.1 9 typ host", sdpMid: "0", sdpMLineIndex: 0 }
    }));
    const iceSignal = await aliceP2P.next();
    assert.equal(iceSignal.type, "p2p-signal");
    assert.equal(iceSignal.signalType, "ice");
    assert.equal(iceSignal.fromUsername, "bob");
  } finally {
    aliceP2P.socket.close();
    bobP2P.socket.close();
  }

  const shortUsernameRegister = await register("aj");
  assert.equal(shortUsernameRegister.res.status, 200);
  const shortUsernameToken = await login("aj");

  const delegatedApprovalRegister = await register("cy");
  assert.equal(delegatedApprovalRegister.res.status, 200);
  const delegatedApprovalToken = await login("cy");

  const directoryBeforeWorkspace = await requestJson("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(directoryBeforeWorkspace.res.status, 200);
  assert.equal(directoryBeforeWorkspace.body.some((user: { username: string }) => user.username === "bob"), false);

  const workspaceCreate = await requestJson("/workspaces", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({ name: "Secure Research Lab" })
  });
  assert.equal(workspaceCreate.res.status, 200);
  assert.equal(workspaceCreate.body.workspace.role, "owner");
  assert.equal(typeof workspaceCreate.body.workspace.id, "string");
  assert.equal(typeof workspaceCreate.body.workspace.inviteCode, "string");
  assert.equal(typeof workspaceCreate.body.workspace.inviteExpiresAt, "number");

  const workspaceId = workspaceCreate.body.workspace.id as string;
  let inviteCode = workspaceCreate.body.workspace.inviteCode as string;

  const aliceWorkspaces = await requestJson("/workspaces", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(aliceWorkspaces.res.status, 200);
  assert.equal(aliceWorkspaces.body.workspaces.some((workspace: { id: string; role: string }) => workspace.id === workspaceId && workspace.role === "owner"), true);

  const crossIdentity = await request("/identity/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(crossIdentity.status, 403);

  const crossPreKeyUpload = await requestJson("/upload-prekeys", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      username: "bob",
      preKeys: [{ publicKeyHex: "blocked", encryptedPrivateKey: "blocked-private", iv: "blocked-iv" }]
    })
  });
  assert.equal(crossPreKeyUpload.res.status, 403);

  const preKeyUpload = await requestJson("/upload-prekeys", {
    method: "POST",
    headers: authHeaders(bobToken),
    body: JSON.stringify({
      username: "bob",
      preKeys: [
        { publicKeyHex: "bob-prekey-1", encryptedPrivateKey: "bob-private-1", iv: "bob-iv-1" },
        { publicKeyHex: "bob-prekey-2", encryptedPrivateKey: "bob-private-2", iv: "bob-iv-2" }
      ]
    })
  });
  assert.equal(preKeyUpload.res.status, 200);
  assert.equal(preKeyUpload.body.remaining, 2);

  const preKeyBeforeWorkspaceApproval = await request("/prekey/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(preKeyBeforeWorkspaceApproval.status, 403);

  const readinessBeforeWorkspaceApproval = await request("/share-readiness/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(readinessBeforeWorkspaceApproval.status, 403);

  const invalidJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
    method: "POST",
    headers: authHeaders(bobToken),
    body: JSON.stringify({ inviteCode: "wrong-code" })
  });
  assert.equal(invalidJoin.res.status, 400);

  const bobCannotRotateInvite = await requestJson(`/workspaces/${workspaceId}/invite/rotate`, {
    method: "POST",
    headers: authHeaders(bobToken)
  });
  assert.equal(bobCannotRotateInvite.res.status, 403);

  const rotateInvite = await requestJson(`/workspaces/${workspaceId}/invite/rotate`, {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(rotateInvite.res.status, 200);
  assert.equal(typeof rotateInvite.body.workspace.inviteCode, "string");
  assert.notEqual(rotateInvite.body.workspace.inviteCode, inviteCode);
  assert.equal(typeof rotateInvite.body.workspace.inviteExpiresAt, "number");
  assert.ok(rotateInvite.body.workspace.inviteExpiresAt > Date.now());

  const oldInviteJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
    method: "POST",
    headers: authHeaders(bobToken),
    body: JSON.stringify({ inviteCode })
  });
  assert.equal(oldInviteJoin.res.status, 403);
  inviteCode = rotateInvite.body.workspace.inviteCode as string;

  const bobJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
    method: "POST",
    headers: authHeaders(bobToken),
    body: JSON.stringify({ inviteCode })
  });
  assert.equal(bobJoin.res.status, 200);
  assert.equal(bobJoin.body.membership.status, "pending");

  const bobCannotApprove = await requestJson(`/workspaces/${workspaceId}/members/bob/approve`, {
    method: "POST",
    headers: authHeaders(bobToken)
  });
  assert.equal(bobCannotApprove.res.status, 403);

  const alicePendingMembers = await requestJson(`/workspaces/${workspaceId}/pending-members`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(alicePendingMembers.res.status, 200);
  assert.equal(alicePendingMembers.body.pending.some((member: { username: string }) => member.username === "bob"), true);

  const directoryWhilePending = await requestJson("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(directoryWhilePending.res.status, 200);
  assert.equal(directoryWhilePending.body.some((user: { username: string }) => user.username === "bob"), false);

  const shortUsernameJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
    method: "POST",
    headers: authHeaders(shortUsernameToken),
    body: JSON.stringify({ inviteCode })
  });
  assert.equal(shortUsernameJoin.res.status, 200);
  assert.equal(shortUsernameJoin.body.membership.status, "pending");

  const approveShortUsernameWorkspace = await requestJson(`/workspaces/${workspaceId}/members/aj/approve`, {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(approveShortUsernameWorkspace.res.status, 200);
  assert.equal(approveShortUsernameWorkspace.body.member.status, "active");
  assert.equal(approveShortUsernameWorkspace.body.member.username, "aj");

  const approveBobWorkspace = await requestJson(`/workspaces/${workspaceId}/members/bob/approve`, {
    method: "POST",
    headers: authHeaders(aliceToken)
  });
  assert.equal(approveBobWorkspace.res.status, 200);
  assert.equal(approveBobWorkspace.body.member.status, "active");
  assert.equal(approveBobWorkspace.body.member.approvedBy, "alice");

  const bobCannotChangeRoles = await requestJson(`/workspaces/${workspaceId}/members/aj/role`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(bobToken)
    },
    body: JSON.stringify({ role: "admin" })
  });
  assert.equal(bobCannotChangeRoles.res.status, 403);

  const promoteBobWorkspace = await requestJson(`/workspaces/${workspaceId}/members/bob/role`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(aliceToken)
    },
    body: JSON.stringify({ role: "admin" })
  });
  assert.equal(promoteBobWorkspace.res.status, 200);
  assert.equal(promoteBobWorkspace.body.member.role, "admin");

  const delegatedApprovalJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
    method: "POST",
    headers: authHeaders(delegatedApprovalToken),
    body: JSON.stringify({ inviteCode })
  });
  assert.equal(delegatedApprovalJoin.res.status, 200);
  assert.equal(delegatedApprovalJoin.body.membership.status, "pending");

  const bobApprovesDelegatedMember = await requestJson(`/workspaces/${workspaceId}/members/cy/approve`, {
    method: "POST",
    headers: authHeaders(bobToken)
  });
  assert.equal(bobApprovesDelegatedMember.res.status, 200);
  assert.equal(bobApprovesDelegatedMember.body.member.status, "active");
  assert.equal(bobApprovesDelegatedMember.body.member.approvedBy, "bob");

  const demoteBobWorkspace = await requestJson(`/workspaces/${workspaceId}/members/bob/role`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(aliceToken)
    },
    body: JSON.stringify({ role: "member" })
  });
  assert.equal(demoteBobWorkspace.res.status, 200);
  assert.equal(demoteBobWorkspace.body.member.role, "member");

  const workspaceMembers = await requestJson(`/workspaces/${workspaceId}/members`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(workspaceMembers.res.status, 200);
  assert.equal(workspaceMembers.body.members.some((member: { username: string }) => member.username === "bob"), true);

  const directoryAfterWorkspaceApproval = await requestJson("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(directoryAfterWorkspaceApproval.res.status, 200);
  assert.equal(directoryAfterWorkspaceApproval.body.some((user: { username: string }) => user.username === "bob"), true);

  const readinessAfterWorkspaceApproval = await requestJson("/share-readiness/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(readinessAfterWorkspaceApproval.res.status, 200);
  assert.equal(readinessAfterWorkspaceApproval.body.workspaceApproved, true);
  assert.equal(readinessAfterWorkspaceApproval.body.preKeysAvailable, true);
  assert.equal(readinessAfterWorkspaceApproval.body.availablePreKeys, 2);

  const bobPreKeyStatusBeforeReadiness = await requestJson("/prekeys/bob/status", {
    headers: authHeaders(bobToken)
  });
  assert.equal(bobPreKeyStatusBeforeReadiness.body.available, 2);

  const issuedPreKey = await requestJson("/prekey/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(issuedPreKey.res.status, 200);
  assert.equal(issuedPreKey.body.preKey.publicKeyHex, "bob-prekey-1");

  const sharedVaultForm = new FormData();
  sharedVaultForm.append("encryptedMetadata", "shared-encrypted-metadata");
  sharedVaultForm.append("metadataIv", "shared-metadata-iv");
  sharedVaultForm.append("wrappedFileKey", "owner-wrapped-key");
  sharedVaultForm.append("wrappedFileKeyIv", "owner-wrapped-key-iv");
  sharedVaultForm.append("fileBlob", new Blob(["shared-encrypted-vault-bytes"]), "shared-cipher.bin");

  const sharedVaultUpload = await request("/vault-files", {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: sharedVaultForm
  });
  const sharedVaultUploadBody = await sharedVaultUpload.json();
  assert.equal(sharedVaultUpload.status, 200);

  const blockedShare = await requestJson(`/vault-files/${sharedVaultUploadBody.file.id}/share`, {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      recipientUsername: "bob"
    })
  });
  assert.equal(blockedShare.res.status, 400);

  const shareGrant = await requestJson(`/vault-files/${sharedVaultUploadBody.file.id}/share`, {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      recipientUsername: "bob",
      wrappedFileKey: "bob-grant-wrapped-key",
      ephemeralPublicKey: "alice-ephemeral-public-key",
      usedPreKey: issuedPreKey.body.preKey.publicKeyHex,
      signature: "owner-signature"
    })
  });
  assert.equal(shareGrant.res.status, 200);
  assert.equal(shareGrant.body.grant.recipientUsername, "bob");

  const sharedMetadataUpdate = await requestJson(`/vault-files/${sharedVaultUploadBody.file.id}/metadata`, {
    method: "PATCH",
    headers: authHeaders(aliceToken),
    body: JSON.stringify({
      encryptedMetadata: "renamed-shared-encrypted-metadata",
      metadataIv: "renamed-shared-metadata-iv",
      grantSignatures: [
        {
          grantId: shareGrant.body.grant.id,
          signature: "renamed-shared-signature"
        }
      ]
    })
  });
  assert.equal(sharedMetadataUpdate.res.status, 200);
  assert.equal(sharedMetadataUpdate.body.file.metadataIv, "renamed-shared-metadata-iv");

  const ownerVaultAfterShare = await requestJson("/vault-files", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(ownerVaultAfterShare.res.status, 200);
  const sharedOwnerRecord = ownerVaultAfterShare.body.files.find((file: { id: string }) => file.id === sharedVaultUploadBody.file.id);
  assert.equal(sharedOwnerRecord.sharedWithCount, 1);

  const aliceSummary = await requestJson("/security-summary", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(aliceSummary.res.status, 200);
  assert.equal(aliceSummary.body.workspaces.active, 1);
  assert.equal(aliceSummary.body.workspaces.pending, 0);
  assert.equal(aliceSummary.body.files.owned, 2);
  assert.equal(aliceSummary.body.files.shared, 1);
  assert.equal(aliceSummary.body.storage.quotaBytes, 1000);
  assert.ok(aliceSummary.body.storage.usedBytes > 0);
  assert.equal(aliceSummary.body.preKeys.available, 0);
  assert.equal(aliceSummary.body.sessions.active, 1);
  assert.equal(typeof aliceSummary.body.audit.blocks, "number");

  const sharedWithBob = await requestJson("/shared-vault-files", {
    headers: authHeaders(bobToken)
  });
  assert.equal(sharedWithBob.res.status, 200);
  assert.equal(sharedWithBob.body.files.length, 1);
  assert.equal(sharedWithBob.body.files[0].ownerUsername, "alice");
  assert.equal(sharedWithBob.body.files[0].encryptedMetadata, "renamed-shared-encrypted-metadata");
  assert.equal(sharedWithBob.body.files[0].metadataIv, "renamed-shared-metadata-iv");
  assert.equal(sharedWithBob.body.files[0].signature, "renamed-shared-signature");
  assert.equal(sharedWithBob.body.files[0].encryptedPrivatePreKey, "bob-private-1");

  const sharedDownload = await request(`/shared-vault-files/${shareGrant.body.grant.id}/download`, {
    headers: authHeaders(bobToken)
  });
  assert.equal(sharedDownload.status, 200);
  assert.equal(await sharedDownload.text(), "shared-encrypted-vault-bytes");

  const rotationForm = new FormData();
  rotationForm.append("encryptedMetadata", "rotated-encrypted-metadata");
  rotationForm.append("metadataIv", "rotated-metadata-iv");
  rotationForm.append("wrappedFileKey", "rotated-owner-wrapped-key");
  rotationForm.append("wrappedFileKeyIv", "rotated-owner-wrapped-key-iv");
  rotationForm.append("grants", JSON.stringify([]));
  rotationForm.append("fileBlob", new Blob(["rotated-encrypted-vault-bytes"]), "rotated-cipher.bin");

  const rotateVault = await request(`/vault-files/${sharedVaultUploadBody.file.id}/rotate`, {
    method: "POST",
    headers: authHeaders(aliceToken),
    body: rotationForm
  });
  const rotateVaultBody = await rotateVault.json();
  assert.equal(rotateVault.status, 200);
  assert.equal(rotateVaultBody.file.encryptedMetadata, "rotated-encrypted-metadata");
  assert.equal(rotateVaultBody.grants.length, 0);

  const sharedAfterRotation = await requestJson("/shared-vault-files", {
    headers: authHeaders(bobToken)
  });
  assert.equal(sharedAfterRotation.res.status, 200);
  assert.equal(sharedAfterRotation.body.files.length, 0);

  const oldGrantDownload = await request(`/shared-vault-files/${shareGrant.body.grant.id}/download`, {
    headers: authHeaders(bobToken)
  });
  assert.equal(oldGrantDownload.status, 404);

  const rotatedOwnerDownload = await request(`/vault-files/${sharedVaultUploadBody.file.id}/download`, {
    headers: authHeaders(aliceToken)
  });
  assert.equal(rotatedOwnerDownload.status, 200);
  assert.equal(await rotatedOwnerDownload.text(), "rotated-encrypted-vault-bytes");

  const bobPreKeyStatus = await requestJson("/prekeys/bob/status", {
    headers: authHeaders(bobToken)
  });
  assert.equal(bobPreKeyStatus.res.status, 200);
  assert.deepEqual(bobPreKeyStatus.body, { total: 2, available: 1, consumed: 1 });

  const revokeBob = await requestJson("/identity/bob/revoke", {
    method: "POST",
    headers: authHeaders(bobToken),
    body: JSON.stringify({ reason: "test compromise" })
  });
  assert.equal(revokeBob.res.status, 200);
  assert.equal(revokeBob.body.message, "Identity revoked");
  assert.equal(revokeBob.body.revokedSessions, 1);

  const revokedBobToken = await request("/prekeys/bob/status", {
    headers: authHeaders(bobToken)
  });
  assert.equal(revokedBobToken.status, 401);

  const revokedBobMaterial = await request("/session-material/bob");
  assert.equal(revokedBobMaterial.status, 410);

  const bobRelogin = await requestJson("/sessions", {
    method: "POST",
    body: JSON.stringify({ username: "bob", authSecret: "correct-auth-secret" })
  });
  assert.equal(bobRelogin.res.status, 401);

  const directoryAfterRevocation = await requestJson("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(directoryAfterRevocation.res.status, 200);
  assert.equal(directoryAfterRevocation.body.some((user: { username: string }) => user.username === "bob"), false);

  const revokedBobPreKey = await request("/prekey/bob", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(revokedBobPreKey.status, 410);

  const audit = await requestJson("/audit-log", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(audit.res.status, 200);
  assert.ok(Array.isArray(audit.body));
  assert.ok(audit.body.length >= 5);
  assert.equal(audit.body.some((entry: { action: string }) => entry.action === "Vault Share Blocked"), true);

  let expectedPreviousHash = "0".repeat(64);
  for (const entry of audit.body) {
    assert.equal(entry.previousHash, expectedPreviousHash);
    const payload = JSON.stringify([
      entry.timestamp,
      entry.userId,
      entry.action,
      entry.actorId || entry.userId,
      entry.subjectId || entry.userId,
      entry.workspaceId || null,
      entry.visibility || "user"
    ]) + entry.previousHash;
    const computedHash = sha256Hex(payload);
    assert.equal(entry.hash, computedHash);
    expectedPreviousHash = computedHash;
  }

  const cyAudit = await requestJson("/audit-log", {
    headers: authHeaders(delegatedApprovalToken)
  });
  assert.equal(cyAudit.res.status, 200);
  assert.equal(cyAudit.body.some((entry: { action: string; actorId?: string }) => entry.action === "Vault File Uploaded" && entry.actorId === "alice"), false);

  const anchor = await requestJson("/audit-anchor", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(anchor.res.status, 200);
  assert.equal(anchor.body.version, 1);
  assert.equal(anchor.body.scope, "visible-user-and-admin-workspaces");
  assert.equal(anchor.body.blockCount, audit.body.length);
  assert.equal(anchor.body.firstHash, audit.body[0].hash);
  assert.equal(anchor.body.latestHash, expectedPreviousHash);
  assert.equal(typeof anchor.body.ledgerDigest, "string");

  const revokeCurrent = await requestJson("/sessions/current", {
    method: "DELETE",
    headers: authHeaders(aliceToken)
  });
  assert.equal(revokeCurrent.res.status, 200);

  const revokedCurrentToken = await request("/users", {
    headers: authHeaders(aliceToken)
  });
  assert.equal(revokedCurrentToken.status, 401);
});
