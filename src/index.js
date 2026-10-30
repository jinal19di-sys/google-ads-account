import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { OAuth2Client } from 'google-auth-library';

const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'SESSION_SECRET'];
const missing = required.filter((name) => !process.env[name]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const app = express();
const port = Number(process.env.PORT || 4000);
const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const oauth = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI,
});
const loginScopes = ['openid', 'email', 'profile'];
const adsScopes = [...loginScopes, 'https://www.googleapis.com/auth/adwords'];

// This in-memory store is suitable only for local development. Replace it with
// a database-backed session/token store before deploying multiple instances.
const sessions = new Map();
const pendingStates = new Map();

app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' } }));
app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use(express.json());

function sign(value) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
}

function appendCookie(res, value) {
  const current = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', current ? [...(Array.isArray(current) ? current : [current]), value] : value);
}

function setSessionCookie(res, sessionId) {
  const value = `${sessionId}.${sign(sessionId)}`;
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const sameSite = process.env.COOKIE_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'None' : 'Lax');
  appendCookie(res, `adnexa_session=${value}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=604800${secure}`);
}

function cookieValue(req, name) {
  return req.headers.cookie?.split(';').map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))?.slice(name.length + 1) || null;
}

function setGoogleNonceCookie(res, nonce) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const sameSite = process.env.COOKIE_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'None' : 'Lax');
  appendCookie(res, `adnexa_google_nonce=${nonce}.${sign(`google-login:${nonce}`)}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=300${secure}`);
}

function clearGoogleNonceCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const sameSite = process.env.COOKIE_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'None' : 'Lax');
  appendCookie(res, `adnexa_google_nonce=; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=0${secure}`);
}

function getSession(req) {
  const raw = req.headers.cookie?.split(';').map((item) => item.trim()).find((item) => item.startsWith('adnexa_session='))?.slice('adnexa_session='.length);
  if (!raw) return null;
  const [sessionId, signature] = raw.split('.');
  if (!sessionId || !signature) return null;
  const actual = Buffer.from(signature);
  const expected = Buffer.from(sign(sessionId));
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  return sessions.get(sessionId) || null;
}

function requireSession(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ message: 'Sign in with Google to continue.' });
  req.session = session;
  return next();
}

function authUrl(state, prompt = 'select_account', includeAdsScope = false) {
  return oauth.generateAuthUrl({
    access_type: 'offline',
    include_granted_scopes: true,
    prompt,
    scope: includeAdsScope ? adsScopes : loginScopes,
    state,
  });
}

function createPendingState(returnUrl, purpose) {
  const state = crypto.randomBytes(32).toString('base64url');
  pendingStates.set(state, { purpose, returnUrl, createdAt: Date.now() });
  return state;
}

function safeReturnUrl(value) {
  try {
    const url = new URL(value || frontendOrigin);
    if (url.origin !== frontendOrigin) return frontendOrigin;
    return url.toString();
  } catch {
    return frontendOrigin;
  }
}

function describeOAuthFailure(error) {
  const providerCode = error.response?.data?.error || error.code || error.message || 'unknown_error';
  if (String(providerCode).toLowerCase().includes('invalid_client')) {
    return 'Google rejected the backend OAuth client credentials. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to the matching active Web application client, then restart the Node server.';
  }
  if (String(providerCode).toLowerCase().includes('invalid_grant')) {
    return 'Google rejected the expired or already-used authorization code. Start Connect account again.';
  }
  return String(error.response?.data?.error_description || error.message || providerCode).slice(0, 220);
}

app.get('/api/v1/health', (_req, res) => res.json({
  ok: true,
  message: "Node.js server is running successfully",
  oauthClientId: process.env.GOOGLE_CLIENT_ID,
  oauthRedirectUri: process.env.GOOGLE_REDIRECT_URI,
}));

app.get('/api/v1/auth/google/nonce', (_req, res) => {
  const nonce = crypto.randomBytes(32).toString('base64url');
  setGoogleNonceCookie(res, nonce);
  res.setHeader('Cache-Control', 'no-store');
  return res.json({ nonce });
});

app.post('/api/v1/auth/google/login', async (req, res) => {
  const credential = req.body?.credential;
  const nonce = req.body?.nonce;
  const nonceCookie = cookieValue(req, 'adnexa_google_nonce');
  clearGoogleNonceCookie(res);
  if (typeof credential !== 'string' || !credential || typeof nonce !== 'string' || !nonce || !nonceCookie) {
    return res.status(400).json({ message: 'Google sign-in expired. Please try again.' });
  }
  const [cookieNonce, cookieSignature] = nonceCookie.split('.');
  const signature = Buffer.from(cookieSignature || '');
  const expectedSignature = Buffer.from(sign(`google-login:${cookieNonce || ''}`));
  if (cookieNonce !== nonce || signature.length !== expectedSignature.length || !crypto.timingSafeEqual(signature, expectedSignature)) {
    return res.status(403).json({ message: 'Google sign-in verification expired. Please try again.' });
  }
  try {
    const ticket = await oauth.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const profile = ticket.getPayload();
    if (!profile?.sub || profile.email_verified !== true || profile.nonce !== nonce) {
      return res.status(401).json({ message: 'Google did not return a verified account.' });
    }
    const sessionId = crypto.randomBytes(32).toString('base64url');
    const user = {
      id: profile.sub,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
    };
    sessions.set(sessionId, { user, loginTokens: null, adsTokens: null, adsConnected: false });
    setSessionCookie(res, sessionId);
    return res.json({ user });
  } catch (loginError) {
    console.error('Google ID token verification failed:', loginError.message);
    return res.status(401).json({ message: 'Google sign-in verification failed. Check the Google client ID and authorized JavaScript origin.' });
  }
});

app.get('/api/v1/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const pending = typeof state === 'string' ? pendingStates.get(state) : null;
  if (!pending || Date.now() - pending.createdAt > 10 * 60 * 1000) {
    if (typeof state === 'string') pendingStates.delete(state);
    return res.redirect(`${frontendOrigin}?error=invalid_oauth_state`);
  }
  pendingStates.delete(state);
  if (error || typeof code !== 'string') {
    const destination = new URL(pending.returnUrl);
    destination.searchParams.set('error', String(error || 'missing_authorization_code'));
    return res.redirect(destination.toString());
  }
  if (pending.purpose !== 'ads' || !pending.sessionId || !sessions.has(pending.sessionId)) {
    return res.redirect(`${pending.returnUrl}?error=google_ads_session_expired`);
  }
  try {
    const { tokens } = await oauth.getToken(code);
    const session = sessions.get(pending.sessionId);
    session.adsTokens = {
      ...session.adsTokens,
      ...tokens,
      refresh_token: tokens.refresh_token || session.adsTokens?.refresh_token,
    };
    session.adsConnected = Boolean(session.adsTokens.access_token || session.adsTokens.refresh_token);
    setSessionCookie(res, pending.sessionId);
    const destination = new URL(pending.returnUrl);
    destination.searchParams.set('google_ads_connected', 'true');
    return res.redirect(destination.toString());
  } catch (callbackError) {
    console.error('Google OAuth callback failed:', callbackError.message);
    const destination = new URL(pending.returnUrl);
    destination.searchParams.set('error', 'google_ads_connection_failed');
    destination.searchParams.set('error_description', describeOAuthFailure(callbackError));
    return res.redirect(destination.toString());
  }
});

app.get('/api/v1/auth/me', requireSession, (req, res) => res.json({ user: req.session.user }));

app.post('/api/v1/auth/logout', (req, res) => {
  const session = getSession(req);
  if (session) {
    const raw = req.headers.cookie?.split(';').map((item) => item.trim()).find((item) => item.startsWith('adnexa_session='))?.slice('adnexa_session='.length);
    const sessionId = raw?.split('.')[0];
    if (sessionId) sessions.delete(sessionId);
  }
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const sameSite = process.env.COOKIE_SAME_SITE || (process.env.NODE_ENV === 'production' ? 'None' : 'Lax');
  res.setHeader('Set-Cookie', `adnexa_session=; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=0${secure}`);
  res.status(204).end();
});

app.post('/api/v1/google-ads/connect', requireSession, (req, res) => {
  const state = createPendingState(safeReturnUrl(req.body?.returnUrl), 'ads');
  const pending = pendingStates.get(state);
  pending.sessionId = req.headers.cookie?.split(';').map((item) => item.trim()).find((item) => item.startsWith('adnexa_session='))?.slice('adnexa_session='.length)?.split('.')[0];
  res.json({ authorizationUrl: authUrl(state, 'consent select_account', true) });
});

app.get('/api/v1/google-ads/status', requireSession, async (req, res) => {
  if (!req.session.adsConnected || !req.session.adsTokens) return res.json({ connected: false, accounts: [] });
  try {
    const accountOAuth = new OAuth2Client({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI,
    });
    accountOAuth.setCredentials(req.session.adsTokens);
    const tokenResponse = await accountOAuth.getAccessToken();
    req.session.adsTokens = accountOAuth.credentials;
    const accessToken = typeof tokenResponse === 'string' ? tokenResponse : tokenResponse.token;
    const headers = {
      Authorization: `Bearer ${accessToken}`,
    };
    const response = await fetch('https://googleads.googleapis.com/v26/customers:listAccessibleCustomers', {
      method: 'GET',
      headers,
    });
    const data = await response.json();
    if (!response.ok) {
      const serializedError = JSON.stringify(data);
      if (serializedError.includes('NOT_ADS_USER')) {
        return res.json({ connected: true, noAdsAccount: true, accounts: [] });
      }
      if (serializedError.includes('CLOUD_PROJECT_NOT_APPROVED_FOR_PRODUCTION')) {
        throw new Error('This Google Cloud project does not have production access to Google Ads API. Open Google Cloud Console > Google Ads API > Overview and apply for Explorer access.');
      }
      const details = data.error?.message || `Google Ads returned ${response.status}.`;
      throw new Error(details);
    }
    const accounts = (data.resourceNames || []).map((resourceName) => ({
      customerId: resourceName.split('/').at(-1),
      name: `Google Ads account ${resourceName.split('/').at(-1)}`,
    }));
    return res.json({ connected: true, accounts });
  } catch (statusError) {
    console.error('Google Ads status request failed:', statusError.message);
    return res.status(502).json({ message: statusError.message || 'Google Ads account lookup failed.' });
  }
});

app.listen(port, () => {
  console.log(`Adnexa API listening on http://localhost:${port}`);
  console.log(`Google OAuth callback: ${process.env.GOOGLE_REDIRECT_URI}`);
});
