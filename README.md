# Adnexa API server

The Express server handles Google OAuth callbacks, keeps OAuth tokens off the browser, and queries accessible Google Ads accounts.

## Configure Google Cloud

In the OAuth client, keep the supplied client ID, revoke the exposed client secret and create a replacement. Add `http://localhost:5173` to **Authorized JavaScript origins** for the React Google sign-in button. Google sign-in posts an ID token to this server for verification and does not use a redirect URI. The separate Google Ads consent flow uses `GOOGLE_REDIRECT_URI`; for local development, add `http://localhost:4000/api/v1/auth/google/callback/` to **Authorized redirect URIs**. The client ID in `frontend/.env.local` and `server/.env` must match.

Enable the Google Ads API in the same Google Cloud project that owns the OAuth client. Google ended developer tokens on September 9, 2026; API access is managed on the Google Cloud project. Test access can call test accounts only. For production accounts, apply for Explorer access on the project's Google Ads API Overview page. This app's account-listing request does not need a developer token or a manager customer ID.

## Environment and start

Copy `.env.example` to `.env`, replace `GOOGLE_CLIENT_SECRET` and `SESSION_SECRET`, then run `npm install` at the workspace root and `npm run dev` there. The frontend runs at port 5173 and this API at port 4000.

The API routes are:

- `POST /api/v1/auth/google/login` (Google Identity Services ID token) and `GET /api/v1/auth/google/callback` (Google Ads consent callback)
- `GET /api/v1/auth/me` and `POST /api/v1/auth/logout`
- `POST /api/v1/google-ads/connect`
- `GET /api/v1/google-ads/status`

OAuth sessions and refresh tokens currently live in memory to keep local setup self-contained. This means a server restart clears sessions, and it is not suitable for a multi-instance deployment. Use a persistent database and encrypted token storage before deploying.
