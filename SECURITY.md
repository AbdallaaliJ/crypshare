# Security Policy

CrypShare is a public-beta secure sharing project for small trusted groups. It uses client-side encryption, workspace-scoped access, fingerprint verification, PostgreSQL metadata, S3-compatible encrypted blob storage, and relay-only P2P transfer.

It is not certified for defense, government, healthcare, financial, or other regulated high-security use without external security review and additional organizational controls.

## Supported Security Expectations

- Public-beta deployments should use the production template in `.env.public-beta.example`.
- Run `cd backend && DEPLOYMENT_ENV_FILE=.env.production npm run check:deploy` before deployment.
- Use HTTPS, secure HttpOnly cookies, strict CORS, PostgreSQL, S3-compatible storage, and a reachable TURN relay.
- Use short-lived TURN credentials generated from `P2P_TURN_SHARED_SECRET`; do not expose permanent TURN passwords to browsers.
- Verify identity fingerprints out-of-band before trusting contacts.
- Rotate workspace invite codes after broad sharing or suspected leakage.

## Reporting Vulnerabilities

If you find a vulnerability, do not publish exploit details publicly before the maintainer has time to respond.

Include:

- A clear description of the issue.
- Steps to reproduce.
- Impact and affected flows.
- Whether file metadata, encrypted blobs, identity keys, sessions, workspace membership, or P2P signaling are affected.
- Suggested fix, if known.

## Sensitive Data Boundaries

The server should not store plaintext file bytes, plaintext vault filenames, plaintext folder names, plaintext file keys, or P2P file metadata.

The server may necessarily see:

- Account usernames.
- Workspace membership records.
- Encrypted blob object keys.
- Session records.
- Audit event labels.
- P2P signaling metadata such as usernames, timing, and session IDs.
- TURN/network metadata when P2P relay is used.

## Known Public-Beta Limitations

- Browser local storage is still used for local trusted-contact records.
- Formal enterprise identity certificates and hardware-backed keys are not implemented.
- Rate limits are process-local unless moved to a shared store.
- External penetration testing and cryptographic review have not been completed.
- Backups, monitoring, alerting, and TLS termination are deployment responsibilities.
