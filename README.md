# @rakettitiede/mcp-oauth-proxy

> Express middleware and router that bridges Custom GPT's OAuth expectations to Google as the identity provider, with API-key fallback.

Extracted from Rakettitiede's MCP servers where identical copies of this code lived in two places. Published so both consumers can depend on a single source of truth — and so external projects with the same pattern can use it too.

## What it does

Custom GPT Actions require OAuth 2.0, but most Express apps don't want to run a full OAuth provider. This package provides a minimal proxy that:

1. Accepts Custom GPT's OAuth dance (`/authorize`, `/callback`, `/token`)
2. Delegates identity to Google (existing IdP, existing consent screen)
3. Returns Google's tokens directly — no custom JWT minting, no session layer
4. Validates incoming Bearer tokens via Google's tokeninfo endpoint
5. Falls back to API key auth for programmatic / service-to-service calls

Two separate factories — use either or both.

## Install

```bash
npm install @rakettitiede/mcp-oauth-proxy
```

Requires Node.js ≥ 20. Express 4 or 5 as a peer dependency.

## Quick start

```javascript
import express from 'express';
import {
  createRequireAuth,
  createOAuthRouter,
} from '@rakettitiede/mcp-oauth-proxy';

const app = express();

const requireAuth = createRequireAuth({
  apiKey: process.env.API_KEY,
  googleClientId: process.env.GOOGLE_CLIENT_ID,
});

const { oauthRouter, oauthMeta } = createOAuthRouter({
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
});

app.use('/oauth', oauthRouter);
app.use('/api', requireAuth, yourProtectedRoutes);

app.listen(8080, () => console.log(oauthMeta.startupLog));
```

## `createRequireAuth(config)`

Returns an Express middleware that authenticates requests via Bearer token (Google-issued) OR API key. On success, `req.user` is populated; on failure, responds with 401.

### Config

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `apiKey` | string | ✅ | — | The API key to accept. Throws at factory time if missing. |
| `googleClientId` | string | | — | Optional. Your Google OAuth 2.0 client ID (used to validate the `aud` claim on OAuth access tokens). When omitted, the OAuth access token validation path is disabled and non-JWT Bearer tokens fall through to API key or 401. Use this if you do not need Custom GPT integration. |
| `googleTokeninfoUrl` | string | — | `https://oauth2.googleapis.com/tokeninfo` | Google's tokeninfo endpoint. Override for testing. |
| `logger` | object | — | `console` | Any object with `.log()` and `.error()`. |
| `nodeEnv` | string | — | `process.env.NODE_ENV` | Controls log verbosity. Non-production logs more. |

### Authentication flow

The middleware evaluates these in order and uses the first that succeeds:

1. **JWT-shaped Bearer token** → validated as a Google IAM identity token (service-to-service via workload identity). Must have email ending in `@developer.gserviceaccount.com`.
2. **Non-JWT Bearer token** → validated as a Google OAuth access token. Must have `aud` equal to the configured `googleClientId`.
3. **API key** → accepted from `X-API-Key` header or `api_key` query parameter, matched against the configured `apiKey`.
4. **Fallback** → `401 Unauthorized`.

If `googleClientId` is not provided, step 2 (OAuth access token validation) is skipped entirely. Use this when the consumer only needs IAM identity tokens + API key (e.g. service-to-service Cloud Run with no Custom GPT integration).

### `req.user` shape

```
{
  id: string,              // Google sub, or 'api-key'
  email: string | null,
  authMethod: 'iam' | 'oauth' | 'api-key',
}
```

## `createOAuthRouter(config)`

Returns `{ oauthRouter, oauthMeta }`:

- **`oauthRouter`** — The Express Router. Mount with `app.use('/oauth', oauthRouter)`.
- **`oauthMeta`** — A frozen metadata object describing what this router mounts:
  - `oauthMeta.startupLog` — string suitable for printing in your `app.listen` callback (e.g. `"🔐 OAuth: GET /oauth/authorize, ..."`)
  - `oauthMeta.endpoints` — `{ authorize, callback, token }` map of route paths

Use `oauthMeta` to compose your server's startup logs without hardcoding OAuth route paths in consumer code.

### Endpoints

The router contains three endpoints that together form an OAuth 2.0 authorization server, delegating the actual authentication to Google. Mount wherever you want the OAuth endpoints to live (conventionally `/oauth`).

### Config

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `googleClientId` | string | ✅ | — | Your Google OAuth 2.0 client ID. |
| `googleClientSecret` | string | ✅ | — | Your Google OAuth 2.0 client secret. |
| `tokenStore` | object | — | in-memory Map | Storage for the short-lived code↔tokens mapping. See below. |
| `tokenTtlMs` | number | — | `300_000` (5 min) | How long stored codes are valid. |
| `logger` | object | — | `console` | Any object with `.log()` and `.error()`. |

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/authorize` | Redirects the user to Google OAuth, encoding client's `redirect_uri` and `state` into Google's `state` param. |
| GET | `/callback` | Google redirects back here; the router exchanges the code for tokens, stores them under a fresh one-time code, and redirects the client with that code. |
| POST | `/token` | Exchanges a previously-issued code for Google's tokens. One-time use. |

### Google OAuth setup

You'll need a Google OAuth 2.0 client from the Google Cloud Console with:

- Authorized redirect URI: `https://<your-domain>/oauth/callback` (or wherever you mount the router)
- Scopes: `openid email profile` (the router requests these automatically)

## `TokenStore` contract

Storage for the short-lived code↔tokens mapping during the OAuth dance. The default is an in-memory `Map` that lazy-expires on `get`. For multi-instance deployments or anything requiring persistence, implement this interface:

```javascript
const tokenStore = {
  // Return the stored entry, or undefined. May lazy-expire.
  async get(code) { /* returns { tokens, expiresAt } | undefined */ },

  // Store an entry.
  async set(code, entry) { /* entry = { tokens, expiresAt } */ },

  // Remove an entry (called after successful /token).
  async delete(code) {},
};
```

All methods may be sync or async — the router awaits both.

### Example: Firestore-backed store

```javascript
import { Firestore } from '@google-cloud/firestore';

function createFirestoreTokenStore({ collection = 'oauth-codes' } = {}) {
  const db = new Firestore();
  const col = db.collection(collection);

  return {
    async get(code) {
      const doc = await col.doc(code).get();
      if (!doc.exists) return undefined;
      const entry = doc.data();
      if (entry.expiresAt < Date.now()) {
        await col.doc(code).delete();
        return undefined;
      }
      return entry;
    },
    async set(code, entry) {
      await col.doc(code).set(entry);
    },
    async delete(code) {
      await col.doc(code).delete();
    },
  };
}
```

## API-key-only mode

If you're not using OAuth, just don't mount the OAuth router and omit `googleClientId`:

```javascript
const requireAuth = createRequireAuth({
  apiKey: process.env.API_KEY,
});

app.use('/api', requireAuth, yourRoutes);
```

## What this package deliberately doesn't do

- **No custom JWT signing** — Google's tokens are returned directly, by design.
- **No PKCE** — server-to-server OAuth doesn't need it.
- **No token refresh** — Google handles that at the token's own lifecycle.
- **No session management** — stateless by design.
- **No user info endpoint** — clients get Google's ID token and can decode it themselves.
- **No consent screen** — Google provides that.

## Limitations

- The default `createMemoryTokenStore` is per-process. In a multi-instance deployment (Cloud Run with `--min-instances > 1`, Kubernetes with replicas > 1, etc.), an OAuth dance that lands on a different instance than it started on will fail. Use a persistent `TokenStore` implementation (Firestore, Redis, etc.) for multi-instance setups.
- Bearer token validation hits Google's tokeninfo endpoint on every request. No local caching. For high-throughput services, consider adding a cache layer around the middleware.

## Development

```bash
git clone https://github.com/rakettitiede/mcp-oauth-proxy.git
cd mcp-oauth-proxy
npm install
npm test
```

31 tests across four suites (auth middleware, OAuth router, oauthMeta, in-memory token store), using `node:test` — no external runner.

## License

MIT © 2026 Rakettitiede Oy
