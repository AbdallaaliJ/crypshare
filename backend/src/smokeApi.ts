import assert from "node:assert/strict";
import crypto from "node:crypto";

const API_BASE_URL = (process.env.SMOKE_API_BASE_URL || "http://127.0.0.1:3001").replace(/\/$/, "");
const RUN_ID = crypto.randomBytes(5).toString("hex");
const AUTH_SECRET = `smoke-auth-${crypto.randomBytes(12).toString("hex")}`;

function sha256Hex(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function authHeaders(token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function userPayload(username: string) {
  return {
    username,
    salt: `${username}-salt`,
    authSalt: `${username}-auth-salt`,
    authVerifierHash: sha256Hex(AUTH_SECRET),
    identityPublicKeyECDH: `${username}-identity-ecdh`,
    identityPublicKeyECDSA: `${username}-identity-ecdsa`,
    encryptedPrivateKeyECDH: `${username}-encrypted-ecdh`,
    ivECDH: `${username}-iv-ecdh`,
    encryptedPrivateKeyECDSA: `${username}-encrypted-ecdsa`,
    ivECDSA: `${username}-iv-ecdsa`
  };
}

async function request(pathname: string, options: RequestInit = {}) {
  return fetch(`${API_BASE_URL}${pathname}`, options);
}

async function requestJson(pathname: string, options: RequestInit = {}) {
  const response = await request(pathname, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const body = await response.json();
  return { response, body };
}

async function register(username: string) {
  const result = await requestJson("/register", {
    method: "POST",
    body: JSON.stringify(userPayload(username))
  });
  assert.equal(result.response.status, 200, `register ${username}`);
  return result.body;
}

async function login(username: string) {
  const result = await requestJson("/sessions", {
    method: "POST",
    body: JSON.stringify({ username, authSecret: AUTH_SECRET })
  });
  assert.equal(result.response.status, 200, `login ${username}`);
  assert.equal(typeof result.body.token, "string", `login token for ${username}`);
  return result.body.token as string;
}

async function cleanupSession(token: string) {
  try {
    await requestJson("/sessions/current", {
      method: "DELETE",
      headers: authHeaders(token)
    });
  } catch {
    // Cleanup should not hide the smoke result.
  }
}

async function main() {
  console.log(`CrypShare API smoke test: ${API_BASE_URL}`);

  const ready = await requestJson("/ready");
  assert.equal(ready.response.status, 200, "ready endpoint");
  assert.equal(ready.body.ready, true, "deployment readiness");
  assert.equal(ready.body.database?.ready, true, "database readiness");
  assert.equal(ready.body.storage?.ready, true, "storage readiness");

  const alice = `smokea${RUN_ID}`;
  const bob = `smokeb${RUN_ID}`;

  await register(alice);
  await register(bob);
  const aliceToken = await login(alice);
  const bobToken = await login(bob);

  try {
    const iceConfig = await requestJson("/p2p/ice-config", {
      headers: authHeaders(aliceToken)
    });
    assert.equal(iceConfig.response.status, 200, "P2P ICE config");
    assert.equal(iceConfig.body.turnConfigured, true, "TURN configured");
    assert.equal(iceConfig.body.relayOnly, true, "P2P relay-only mode");
    assert.equal(iceConfig.body.credentialMode, "ephemeral", "P2P short-lived TURN credentials");
    assert.equal(typeof iceConfig.body.credentialExpiresAt, "string", "P2P TURN credential expiry");
    assert.equal(typeof iceConfig.body.credentialTtlMs, "number", "P2P TURN credential TTL");
    assert.ok(Array.isArray(iceConfig.body.iceServers), "ICE servers list");
    assert.ok(iceConfig.body.iceServers.length > 0, "ICE servers configured");

    const workspace = await requestJson("/workspaces", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({ name: `Smoke Workspace ${RUN_ID}` })
    });
    assert.equal(workspace.response.status, 200, "workspace create");
    const workspaceId = workspace.body.workspace.id as string;
    const inviteCode = workspace.body.workspace.inviteCode as string;

    const bobJoin = await requestJson(`/workspaces/${workspaceId}/join`, {
      method: "POST",
      headers: authHeaders(bobToken),
      body: JSON.stringify({ inviteCode })
    });
    assert.equal(bobJoin.response.status, 200, "workspace join");
    assert.equal(bobJoin.body.membership.status, "pending", "join status");

    const approveBob = await requestJson(`/workspaces/${workspaceId}/members/${bob}/approve`, {
      method: "POST",
      headers: authHeaders(aliceToken)
    });
    assert.equal(approveBob.response.status, 200, "workspace approve");
    assert.equal(approveBob.body.member.status, "active", "approved status");

    const preKeys = await requestJson("/upload-prekeys", {
      method: "POST",
      headers: authHeaders(bobToken),
      body: JSON.stringify({
        username: bob,
        preKeys: [
          { publicKeyHex: `${bob}-prekey-1`, encryptedPrivateKey: `${bob}-private-1`, iv: `${bob}-iv-1` }
        ]
      })
    });
    assert.equal(preKeys.response.status, 200, "pre-key upload");

    const readiness = await requestJson(`/share-readiness/${bob}`, {
      headers: authHeaders(aliceToken)
    });
    assert.equal(readiness.response.status, 200, "share readiness");
    assert.equal(readiness.body.workspaceApproved, true, "workspace share gate");
    assert.equal(readiness.body.preKeysAvailable, true, "pre-key share gate");

    const issuedPreKey = await requestJson(`/prekey/${bob}`, {
      headers: authHeaders(aliceToken)
    });
    assert.equal(issuedPreKey.response.status, 200, "pre-key issue");

    const uploadForm = new FormData();
    uploadForm.append("encryptedMetadata", `smoke-encrypted-metadata-${RUN_ID}`);
    uploadForm.append("metadataIv", `smoke-metadata-iv-${RUN_ID}`);
    uploadForm.append("wrappedFileKey", `smoke-owner-wrapped-key-${RUN_ID}`);
    uploadForm.append("wrappedFileKeyIv", `smoke-owner-key-iv-${RUN_ID}`);
    uploadForm.append("fileBlob", new Blob([`smoke-encrypted-file-${RUN_ID}`]), "smoke.bin");

    const upload = await request("/vault-files", {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: uploadForm
    });
    const uploadBody = await upload.json();
    assert.equal(upload.status, 200, "vault upload");
    const fileId = uploadBody.file.id as string;

    const share = await requestJson(`/vault-files/${fileId}/share`, {
      method: "POST",
      headers: authHeaders(aliceToken),
      body: JSON.stringify({
        recipientUsername: bob,
        wrappedFileKey: `smoke-bob-wrapped-key-${RUN_ID}`,
        ephemeralPublicKey: `smoke-ephemeral-${RUN_ID}`,
        usedPreKey: issuedPreKey.body.preKey.publicKeyHex,
        signature: `smoke-signature-${RUN_ID}`
      })
    });
    assert.equal(share.response.status, 200, "vault share");
    const grantId = share.body.grant.id as string;

    const shared = await requestJson("/shared-vault-files", {
      headers: authHeaders(bobToken)
    });
    assert.equal(shared.response.status, 200, "shared list");
    assert.equal(shared.body.files.some((file: { id: string }) => file.id === grantId), true, "shared grant visible");

    const sharedDownload = await request(`/shared-vault-files/${grantId}/download`, {
      headers: authHeaders(bobToken)
    });
    assert.equal(sharedDownload.status, 200, "shared download");
    assert.equal(await sharedDownload.text(), `smoke-encrypted-file-${RUN_ID}`, "shared encrypted bytes");

    const deleteFile = await requestJson(`/vault-files/${fileId}/permanent`, {
      method: "DELETE",
      headers: authHeaders(aliceToken)
    });
    assert.equal(deleteFile.response.status, 200, "smoke file cleanup");

    console.log("CrypShare API smoke test passed.");
  } finally {
    await cleanupSession(aliceToken);
    await cleanupSession(bobToken);
  }
}

main().catch((err) => {
  console.error("CrypShare API smoke test failed.");
  console.error(err);
  process.exitCode = 1;
});
