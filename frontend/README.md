# CrypShare Frontend

React + TypeScript frontend for the CrypShare public-beta secure drive.

The app surface includes Files, Shared with Me, Workspace Share, P2P Transfer, Contacts, Activity, Workspace Admin, Security, and Settings. Logged-in dashboard sessions keep a P2P signaling connection open so users can receive transfer invites from the top-bar P2P inbox without sitting on the P2P page.

```bash
npm install
npm run dev
```

Set `VITE_API_BASE_URL` when the backend is not running at `http://localhost:3001`.
Set `VITE_SESSION_COOKIE_ENABLED=true` only when the backend also has `SESSION_COOKIE_ENABLED=true`; otherwise local bearer-token auth should leave it unset or `false`.
