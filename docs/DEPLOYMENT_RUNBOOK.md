# CrypShare Public-Beta Deployment Runbook

This runbook is for a small trusted public-beta deployment. It is not a certification checklist for defense, government, healthcare, or regulated production use.

## Required Services

- Frontend static web server or the bundled Nginx frontend container.
- Backend API container.
- PostgreSQL for metadata.
- MinIO or another S3-compatible object store for encrypted blobs.
- A reachable TURN relay for P2P transfer.
- TLS termination in front of the frontend/API.

## Preflight

1. Create a production environment file from the strict template:

   ```bash
   cp .env.public-beta.example .env.production
   ```

2. Replace every placeholder value. Use long random values for database, S3, session, and TURN secrets.

3. Run the deployment checker:

   ```bash
   cd backend
   DEPLOYMENT_ENV_FILE=.env.production npm run check:deploy
   ```

4. Build and test before deploying:

   ```bash
   cd backend && npm run build && npm test
   cd ../frontend && npm run build && npm run lint
   ```

5. Validate Docker configuration:

   ```bash
   docker compose --env-file .env.production -f docker-compose.public-beta.yml config
   ```

## Public-Beta Security Defaults

- `CRYPSHARE_PUBLIC_DEPLOYMENT=true`
- `NODE_ENV=production`
- `TRUST_PROXY=true` when behind Nginx, a load balancer, or another reverse proxy.
- `DATABASE_DRIVER=postgres`
- `STORAGE_DRIVER=s3`
- `SESSION_COOKIE_ENABLED=true`
- `SESSION_RETURN_BEARER_TOKEN=false`
- `SESSION_COOKIE_SECURE=true`
- `VITE_SESSION_COOKIE_ENABLED=true`
- `CORS_ORIGINS` set only to the real HTTPS frontend origin.
- `P2P_TURN_URLS` set to a real public TURN server, not localhost.
- `P2P_TURN_SHARED_SECRET` set to the same long random secret as coturn `static-auth-secret`.
- `P2P_TURN_USERNAME` and `P2P_TURN_CREDENTIAL` left blank so browsers receive short-lived relay credentials only.

## Startup

```bash
docker compose --env-file .env.production -f docker-compose.public-beta.yml up -d --build
```

Then verify readiness:

```bash
curl -fsS https://your-domain.example/api/ready
cd backend
DEPLOYMENT_ENV_FILE=.env.production DEPLOYMENT_CHECK_READY_URL=https://your-domain.example/api/ready npm run check:deploy
SMOKE_API_BASE_URL=https://your-domain.example/api npm run smoke:api
```

The readiness response should report:

- `ready: true`
- `database.driver: postgres`
- `database.ready: true`
- `storage.ready: true`

The smoke test creates uniquely named throwaway identities and a workspace, uploads one encrypted test blob, shares it, verifies shared download, deletes the smoke file, and revokes the smoke sessions. The throwaway user/workspace metadata remains as audit evidence unless you remove it manually from a test environment.

## Backups

- PostgreSQL: use `pg_dump`, managed database snapshots, or volume snapshots.
- MinIO/S3: enable bucket versioning or object-store backups.
- Keep database and encrypted blob backups from the same time window.
- Test restore regularly on a separate environment.

## Monitoring

Watch for:

- Repeated `429` responses.
- Repeated failed sessions or sharing attempts.
- P2P signaling failures or TURN relay candidate failures.
- `/ready` returning `503`.
- PostgreSQL storage growth.
- MinIO/S3 bucket growth.
- Low disk space on Docker volumes.

## Incident Response

If a secret leaks:

1. Rotate the leaked secret immediately.
2. Restart affected services.
3. Revoke active sessions if session or cookie secrets may be exposed.
4. Rotate workspace invite codes that may be affected.
5. Review visible activity and server logs.
6. Preserve logs before cleaning systems.

If a user identity key is compromised:

1. Revoke the identity from Security.
2. Revoke workspace membership where needed.
3. Re-share sensitive files only to a new verified identity.
4. Confirm fingerprints out-of-band before trusting the replacement identity.

## Deployment Blockers

Do not deploy publicly if any of these are true:

- `npm run check:deploy` fails.
- `/ready` is not healthy.
- TLS is not configured.
- Placeholder secrets remain.
- CORS contains `*`.
- TURN points to localhost.
- The app uses readable bearer tokens for browser auth in public deployment.
- PostgreSQL or MinIO backups are not planned.
