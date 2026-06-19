# CrypShare Public Beta Release Checklist

Use this checklist before making the repository or deployment public.

## Repository Hygiene

- Confirm `.env`, `.env.production`, databases, uploads, logs, and build output are ignored.
- Commit only example environment files with placeholder values.
- Do not commit real PostgreSQL, MinIO/S3, session, cookie, TURN, or TLS secrets.
- Review `git status --short` before publishing.
- Keep `node_modules`, `frontend/dist`, `backend/dist`, `backend/data`, and `backend/uploads` out of Git.

## Required Public-Beta Runtime

- PostgreSQL for metadata with `DATABASE_DRIVER=postgres`.
- MinIO/S3-compatible storage for encrypted vault blobs with `STORAGE_DRIVER=s3`.
- HTTPS in front of both frontend and backend.
- Strict `CORS_ORIGINS` set only to the real frontend origin.
- Secure HttpOnly cookie sessions:
  - `SESSION_COOKIE_ENABLED=true`
  - `SESSION_RETURN_BEARER_TOKEN=false`
  - `SESSION_COOKIE_SECURE=true`
  - `VITE_SESSION_COOKIE_ENABLED=true`
- TURN relay reachable from user browsers.
- Short-lived TURN credentials generated from `P2P_TURN_SHARED_SECRET`.

## Required Verification

Run these before a release candidate:

```bash
cd backend
npm run build
npm test
DEPLOYMENT_ENV_FILE=.env.production npm run check:deploy
SMOKE_API_BASE_URL=https://your-backend.example npm run smoke:api
```

```bash
cd frontend
npm run build
npm run lint
```

For local P2P relay checks:

```bash
docker compose -f docker-compose.turn.yml up -d
cd backend
npm run check:turn
```

Then run the in-app P2P TURN self-test from a browser. The backend TCP check only proves the relay port is reachable; the browser test proves WebRTC can gather relay candidates.

## Security Boundaries To Keep

- No public unauthenticated file links in the public-beta model.
- No plaintext filenames, folder names, file bytes, file keys, or P2P file metadata on the server.
- Workspace approval is organizational access only, not proof of real-world identity.
- Fingerprints still need out-of-band verification before trusting contacts.
- Activity views must remain scoped to the current user and workspace-admin visibility, never global public activity.
- TURN can see network metadata, but not plaintext file content when CrypShare client-side encryption is working correctly.

## Public-Beta Limitations To Disclose

- CrypShare is suitable for small trusted groups and senior-project/public-beta evaluation.
- It is not certified for defense, government, healthcare, finance, or regulated high-security use.
- External penetration testing and cryptographic review are still required before sensitive production use.
- Local trusted contacts are browser-local records, not formal PKI.
- TURN/WebRTC may still fail on restrictive networks.
- Operational monitoring, backups, TLS, abuse handling, and incident response are deployment responsibilities.
