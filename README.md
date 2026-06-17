# CrypShare

CrypShare is a public-beta end-to-end encrypted secure drive for small trusted workspaces. The frontend generates and stores identity keys client-side, encrypts files and metadata locally, wraps file keys with an X3DH-style key agreement flow, signs share manifests with ECDSA, and lets recipients decrypt granted files without exposing plaintext to the server.

## Project Structure

- `frontend/` - React, TypeScript, Vite, Tailwind UI.
- `backend/` - Express API for identity records, one-time pre-keys, encrypted file blobs, workspace-scoped sharing controls, and scoped security activity.

## Main Flows

- Register an identity with local ECDH/ECDSA key generation.
- Start from an Overview checklist that shows workspace, file, contact, pre-key, and audit readiness.
- Create or join protected workspaces where owner/admin members approve collaboration.
- Delegate workspace administration by promoting trusted active members to admin, then demoting them when no longer needed.
- Copy secure workspace invite URLs that include workspace access details plus the inviter fingerprint.
- Store personal files in an encrypted owner vault.
- Organize vault files with encrypted folder labels, encrypted rename/move actions, and local decrypted search.
- Manage files in a clean drive-style table with upload, detail, sharing, and revocation actions.
- Review a Workspace Share area for common files shared with or by active members of the selected workspace.
- Move encrypted vault files to Trash, restore them, or permanently delete the encrypted blob.
- Check the active upload limit before encrypting large files.
- Share stored vault files through recipient-specific encrypted grants.
- Stay visible for P2P transfer invites while logged into the dashboard.
- See incoming P2P requests in the top-bar P2P inbox and accept or decline explicitly.
- Send one-time peer-to-peer files through TURN relay-only WebRTC without storing file bytes on the CrypShare server.
- Preview share readiness before creating a grant: workspace approval, fingerprint trust, and recipient pre-key availability.
- Revoke shared vault grants with local file-key rotation.
- Trust recipient identities by comparing stable public-key fingerprints before sharing.
- Upload one-time pre-keys for asynchronous file receipt.
- Refill low one-time pre-key inventory automatically after login, with manual refill still available in Security.
- Review and verify your visible security activity without exposing unrelated public users.
- Export a visible activity checkpoint for later comparison.
- Review an in-app privacy boundary that explains what is encrypted, what service metadata remains visible, and what users must verify out-of-band.
- Replenish one-time pre-keys automatically or manually from the Security page.
- Apply basic API hardening with rate limits, request IDs, security headers, and upload size limits.
- Enable optional HttpOnly session cookies with signed CSRF tokens for hardened public deployments while keeping bearer sessions for local compatibility.
- Use public-beta configuration defaults from `.env.example`.

## Sharing With A Friend

Both users need identities on the same CrypShare server.

1. Create a workspace in Workspace Admin, or use an existing workspace where you are an owner/admin.
2. Copy the secure workspace invite URL, then send it through a trusted channel before the invite expires.
3. Your friend registers, logs in, and requests to join that workspace with the ID and invite code.
4. A workspace owner/admin verifies your friend's identity fingerprint out-of-band, then approves the pending member.
5. Rotate the workspace invite code after sharing it broadly, after a suspected leak, or when the invite expires.
6. Your friend opens Contacts or Security and copies their identity invite URL.
7. You open or paste the invite URL in Contacts, preview the server-published fingerprint match, then mark the contact trusted only after confirming out-of-band.
8. CrypShare only lets you trust/share if the pasted fingerprint matches the public keys currently published by the server and both users are active members of at least one shared workspace.

The username is used for routing. The fingerprint is used to detect impersonation or public-key replacement.

An invite sent only inside the same untrusted app/server is convenient but not enough for high-security trust, because a malicious or compromised server could substitute public keys. For sensitive use, the fingerprint should be confirmed out-of-band. For defense-level deployments, this project would need organization-issued identity certificates, hardware-backed keys, enrollment approval, transparency logs, and external security review.

## Local Development

Install dependencies in each app:

```bash
cd backend && npm install
cd ../frontend && npm install
```

Start the API:

```bash
cd backend
npm run dev
```

Create a SQLite backup:

```bash
cd backend
npm run backup
```

Run backend regression tests:

```bash
cd backend
npm test
```

Start the frontend:

```bash
cd frontend
npm run dev
```

The frontend defaults to `http://localhost:3001` for the API. Override it with:

```bash
VITE_API_BASE_URL=http://localhost:3001 npm run dev
```

## Large File Uploads

CrypShare public beta defaults to a 15 GiB encrypted vault size limit through `UPLOAD_FILE_LIMIT_BYTES`.
The frontend reads `/upload-limits` and blocks files that would exceed the encrypted upload size before local encryption begins.

Vault uploads now use short-lived resumable upload sessions. The browser encrypts one fixed-size file slice at a time, uploads encrypted chunks independently, and the backend assembles those encrypted chunks into the same vault blob format used by existing download and sharing flows.

Storage is owner-paid: encrypted vault bytes count against `USER_STORAGE_QUOTA_BYTES`, including files in Trash because their encrypted blobs still occupy disk. Permanent deletion frees quota. Quota failures are audited without logging plaintext filenames.

This is a real improvement over one giant multipart upload, but it is still not a 5TB production architecture by itself. For 5TB-class files without weakening privacy, the app should continue toward:

- Durable object storage or a chunk-addressed blob store instead of local disk assembly.
- Resume-after-browser-restart using encrypted manifests.
- Per-user/workspace quotas and abuse controls.
- Background cleanup for expired partial upload sessions.
- Resumable/download streaming instead of building one huge browser Blob.
- Chunk hashes and verification before decrypting.
- Keep file-key sharing unchanged: recipients receive wrapped file keys, not plaintext.

## UI Direction

CrypShare now uses an enterprise secure-drive interface: clean sidebar navigation, professional tables, subtle borders, solid blue primary actions, teal/green security accents, and separate polished light/dark modes. The product should feel closer to Dropbox Business, Proton Drive, and a security admin console than to a cyberpunk or AI dashboard.

## Peer-To-Peer Transfers

P2P Transfer is an online-only, one-time send mode separate from Vault sharing.
The CrypShare server handles authenticated WebSocket signaling through short-lived one-time signaling tickets and minimal connection activity events, but it does not store or proxy file bytes, filenames, file types, or decrypted metadata.

- P2P uses TURN relay-only WebRTC DataChannels for a stronger privacy boundary than direct peer discovery.
- Direct STUN-assisted P2P is disabled in the app UI because it can expose peer network metadata directly between users.
- TURN can observe network metadata such as IPs, timing, and packet sizes, but CrypShare encrypts the transfer manifest and every file chunk before sending them over the WebRTC channel.
- Senders can choose a known approved workspace member or paste a CrypShare identity invite URL for an unknown user.
- Unknown-user P2P identity lookup requires the invite fingerprint, which reduces public username probing.
- Recipients must explicitly accept incoming transfers. Untrusted identities are shown with a fingerprint warning and can be accepted once or trusted for future transfers.
- Received files download to the recipient computer and are not added to Vault in v1.

### TURN Relay

If the P2P trace says `0 ICE candidates`, the browser did not get a usable TURN relay route. P2P cannot start in that state because CrypShare intentionally avoids direct peer routes for this mode.

Start the local TURN relay:

```bash
docker compose -f docker-compose.turn.yml up
```

For local testing, configure the backend with:

```bash
P2P_TURN_URLS=turn:127.0.0.1:3478?transport=udp,turn:127.0.0.1:3478?transport=tcp
P2P_TURN_USERNAME=crypshare
P2P_TURN_CREDENTIAL=change-this-turn-password
TURN_EXTERNAL_IP=127.0.0.1
```

Then restart the backend and send the P2P invite again. The app enforces TURN relay-only mode automatically.

For public deployment, run TURN on a reachable public host and replace `127.0.0.1` with the TURN domain or IP. Open UDP/TCP `3478` and the relay UDP port range configured in `docker-compose.turn.yml`. TURN can see IPs, timing, and packet sizes, but CrypShare encrypts the file manifest and every chunk before WebRTC sends them.

## Current Limitations

- Public beta means suitable for small trusted groups and senior-project evaluation, not certified high-security or defense deployment.
- Backend metadata is persisted to SQLite with schema migrations.
- Uploaded encrypted blobs are stored on local disk under the backend upload folder. Public deployments should move encrypted blob storage to durable object storage before serious use.
- P2P Transfer is online-only and depends on TURN relay reachability. Strict networks may still block TURN/WebRTC.
- P2P presence is session-scoped: users are online for transfer invites while logged into the dashboard, and offline after logout or connection loss.
- Vault uploads use browser-side encrypted chunks with short-lived upload sessions, then the server assembles the encrypted blob. This avoids one giant multipart request, but true 5TB-scale use still needs object storage, quotas, resumable downloads, and operational cleanup jobs.
- Files in Trash keep their encrypted blob until permanent deletion.
- File names and folder names live inside encrypted metadata; the backend cannot read labels or search terms.
- Shared-vault revocation rotates the file key from the owner's browser and requires fresh recipient pre-keys for any users who should keep access.
- Automatic pre-key refill runs in the browser after login and requires the active session key; users should still check Security if sharing is blocked.
- Identity trust decisions are stored in browser local storage for the current prototype. Users must compare/paste fingerprints out-of-band before trusting.
- Contacts are locally trusted by fingerprint. This is suitable for a senior-project trust-on-first-verify model, not a formal government PKI.
- Public accounts are self-serve. Sensitive discovery and sharing are gated by workspace membership approval.
- Workspace invite codes expire and can be rotated by workspace owners/admins, but they are still access hints, not identity proof.
- Workspace owners can promote or demote workspace admins. Admins can approve members and rotate invites, but only owners can change roles.
- The first registered identity still receives a legacy server `admin` role during migration, but public-ready collaboration should use workspace owner/admin roles instead of one global gatekeeper.
- The backend issues bearer sessions after password-derived authentication. Sessions are stored as hashes in SQLite and can be listed/revoked, but distributed deployments should move session/rate-limit state to a shared store.
- Internet-facing deployments can enable `SESSION_COOKIE_ENABLED=true` to set HttpOnly session cookies and signed CSRF tokens. For stricter browser auth, set `SESSION_RETURN_BEARER_TOKEN=false` and `VITE_SESSION_COOKIE_ENABLED=true` so the frontend authenticates with the HttpOnly cookie plus CSRF header instead of a readable bearer token. Leave `VITE_SESSION_COOKIE_ENABLED=false` for normal local bearer-token development.
- Backend rate limits and upload limits are in-memory process controls. They need Redis or an equivalent shared store before horizontal scaling.
- Activity shown to users is scoped to their own account plus workspace events they are allowed to administer; random public users should not see each other's activity.
- The internal audit log is hash-linked, and users can export visible activity checkpoints, but checkpoints still need to be stored externally by the user or an organization.
- This is a learning/prototype security project, not production-ready cryptographic infrastructure.

## Hardening Roadmap

1. Persist backend metadata and audit logs across restarts. Done, now backed by SQLite.
2. Add server-side authentication, sessions, and authorization checks. Done with password-derived auth secrets and bearer sessions.
3. Move persistence to a real database with migrations and backups. Done with SQLite, `schema_migrations`, and `npm run backup`.
4. Add API tests, crypto flow tests, and tamper/regression tests. Started with backend auth, authorization, pre-key, and audit-chain regression coverage.
5. Add key lifecycle controls: revocation, device management, recovery policy, and rotation design. Started with persistent active-session controls, hashed bearer sessions, and emergency identity revocation.
6. Add verified contact enrollment: invite import, fingerprint verification, and local trusted-contact management. Done for prototype use; formal deployments still need organization-issued identity certificates.
7. Add organization enrollment controls. Started with workspace creation, invite-code join requests, workspace admin approval, and member revocation.
8. Add operational hardening: rate limiting, structured logging, monitoring, retention, and deployment security. Started with request IDs, security headers, in-memory rate limits, JSON/upload bounds, stricter request validation, public-beta env defaults, and structured request logs.
9. Add audit anchoring/export for tamper evidence. Done with privacy-scoped activity views, authenticated checkpoint export, and in-app checkpoint comparison.
10. Harden browser session transport. Started with optional HttpOnly session cookies, signed CSRF double-submit tokens, production config checks, frontend CSRF header support, API cookie credentials, and cookie-only browser auth mode.
11. Commission external cryptographic and application security review before sensitive use.

## Product Roadmap

1. Encrypted personal drive vault. Done with owner-only encrypted file storage, encrypted metadata, encrypted rename/move, local decrypt/download, trash/restore, and permanent delete.
2. Shared-with-me vault grants for Drive-style sharing without exposing file keys to the server. Done with recipient-specific encrypted file-key grants.
3. Access revocation with file-key rotation. Done with owner-side re-encryption and atomic replacement of shared grants.
4. Identity trust/fingerprint UX. Done with local trust records, fingerprint display, and trust gates before dispatch/vault sharing.
5. Contacts and invite import. Done with copyable identity invites, verified invite import, trusted-contact management, and changed-key warnings.
6. Encrypted folders and client-side search index. Done with encrypted folder metadata, vault folder filters, and local decrypted search for owner/shared vault views.
7. Public-ready workspace model. Started with self-serve accounts, workspace invite requests, owner/admin approval, workspace-scoped discovery, and workspace-gated sharing.
8. Clean secure drive UX. Started with Files/Shared/Workspace Share/Contacts/Security Activity/Workspace Admin/Security navigation, a drive-style Files table, detail/share drawer, dedicated Workspace Admin page, and dedicated Security page.
9. Share readiness checks. Done with a non-consuming readiness endpoint and UI gates for workspace approval, fingerprint trust, and recipient pre-key availability.
10. Product consolidation. Started with an Overview dashboard, legacy Dispatch/Inbox route redirects, functional global file search, Activity filters, and Security/Workspace Admin ownership of old settings flows.
11. Workspace invite lifecycle. Started with expiring invite codes, admin-only invite rotation, UI expiry visibility, and audit logging for rotations.
12. Workspace governance. Started with owner-only admin promotion/demotion, delegated member approval, role-change audit events, and Workspace Admin UI controls.
13. Invite and trust UX. Started with secure workspace invite URLs, invite paste/open auto-fill, and two-step contact fingerprint verification.
14. Pre-key health automation. Started with low-inventory detection, browser-side automatic refill, shared refill helpers, and clearer Security status copy.
15. Trash and restore. Started with soft-delete vault files, restore, permanent purge, active/shared filtering, and Files Trash UI.
16. Encrypted metadata editing. Started with owner-side rename and folder moves that re-encrypt metadata locally and refresh shared grant signatures.
17. Large file readiness. Started with a 15 GiB configurable encrypted upload limit, `/upload-limits`, encrypted-size preflight checks, short-lived encrypted chunk upload sessions, owner-paid storage quotas, chunk retry/status checks, and documented object-storage work for 5TB-class deployments.
18. Peer-to-peer transfer. Started with short-lived signaling tickets, TURN relay-only WebRTC DataChannel transfer, encrypted manifests/chunks, explicit recipient acceptance, unknown-user invite fingerprint checks, and browser TURN self-test diagnostics.
19. Privacy and UX consolidation. Started with simplified workspace labels, invite-link continuity through login, hidden advanced invite details, Security privacy-boundary copy, and P2P diagnostics moved behind an advanced trace.
20. Deployment hardening. Started with optional secure cookie sessions, CSRF guardrails, explicit cookie configuration, production validation for cookie secrets, and `SESSION_RETURN_BEARER_TOKEN=false` support for cookie-only browser sessions.

## Legacy Compatibility

- Legacy dispatch and inbox APIs remain only for compatibility with earlier prototype data.
- The public-beta product surface now prefers Files, Shared, and Workspace Share because they support the secure-drive model, revocable grants, share readiness checks, and workspace-scoped collaboration.

## Security References

- OWASP ASVS provides a verification baseline for web application controls: https://owasp.org/www-project-application-security-verification-standard/
- NIST CSF 2.0 frames governance, protection, detection, response, and recovery work: https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20
- CISA Secure by Design supports safer defaults and secure-by-default product choices: https://www.cisa.gov/securebydesign
