---
name: mcp-oauth-proxy
version: 1.0.0
description: How to add authentication to an MCP server using @rakettitiede/mcp-oauth-proxy. Covers createRequireAuth (API key + GCP IAM tokens + OAuth bearer), createOAuthRouter (Google OAuth proxy for Custom GPT), auth model, and middleware mounting. Standalone — does not require @rakettitiede/mcp-server-kit.
---

# @rakettitiede/mcp-oauth-proxy

Express middleware and router for MCP server authentication. Supports three auth mechanisms independently or together: API key, GCP IAM identity tokens, and Google OAuth bearer tokens.

Works with any Express server — not tied to `@rakettitiede/mcp-server-kit`. See its [skill](https://github.com/rakettitiede/mcp-server-kit/blob/main/skill/SKILL.md) for MCP transport and domain function setup.

## Installation

```bash
npm install @rakettitiede/mcp-oauth-proxy
```

## What this package owns

- `createRequireAuth` — Express middleware that validates incoming requests
- `createOAuthRouter` — Express router that proxies Google OAuth for Custom GPT integration

## Auth mechanisms

Three mechanisms, any combination:

| Mechanism | Header | Use case |
|---|---|---|
| API key | `X-API-Key: <key>` or `?api_key=<key>` | Local dev, admin scripts |
| GCP IAM identity token | `Authorization: Bearer <google-jwt>` | Service-to-service (Slack bots → MCP) |
| OAuth bearer token | `Authorization: Bearer <oauth-token>` | Custom GPT via OAuth flow |

## `createRequireAuth`

```js
import { createRequireAuth } from "@rakettitiede/mcp-oauth-proxy";

const requireAuth = createRequireAuth({
  apiKey: process.env.API_KEY,                    // required — fallback key
  googleClientId: process.env.GOOGLE_CLIENT_ID,  // optional — enables OAuth bearer validation
  googleTokeninfoUrl: "https://oauth2.googleapis.com/tokeninfo",  // optional, has default
  nodeEnv: process.env.NODE_ENV,                 // optional — skips auth in "development"
});

// Mount before routes you want to protect
app.use("/api/v1", requireAuth);
app.use("/sse", requireAuth);
app.use("/mcp", requireAuth);
```

When `nodeEnv` is `"development"`, all requests pass through without auth checks — safe for local dev, never in production.

When `googleClientId` is omitted, OAuth bearer validation is disabled. Service-to-service-only services (no Custom GPT plans) omit it entirely.

GCP IAM identity tokens are JWT tokens issued by GCP for service accounts. They are validated by checking the token issuer and audience — no extra config needed beyond omitting `googleClientId`.

## `createOAuthRouter` — Google OAuth proxy for Custom GPT

Custom GPT requires an OAuth2 endpoint at `/oauth/authorize` and `/oauth/token`. This router proxies those requests to Google as the IdP.

```js
import { createOAuthRouter } from "@rakettitiede/mcp-oauth-proxy";

const { oauthRouter, oauthMeta } = createOAuthRouter({
  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
});

app.use("/oauth", oauthRouter);
console.log(oauthMeta.startupLog);
```

Routes registered:
- `GET /oauth/authorize` → redirects to Google OAuth consent
- `GET /oauth/callback` → exchanges code for tokens, stores temporarily
- `POST /oauth/token` → returns stored tokens to Custom GPT

OAuth codes are stored in-memory with a 5-minute TTL. `/callback` and `/token` must hit the same Cloud Run instance — works reliably for low-traffic usage.

## Service-to-service only (no Custom GPT)

When a service has no Custom GPT integration, skip `createOAuthRouter` entirely and omit `googleClientId` from `createRequireAuth`:

```js
const requireAuth = createRequireAuth({
  apiKey: process.env.API_KEY,
  nodeEnv: process.env.NODE_ENV,
  // no googleClientId — IAM tokens + API key only
});

// No oauthRouter needed
```

Do not pass sentinel strings or empty values — just omit the fields.

## Full example with both packages

```js
import express from "express";
import { createRequireAuth, createOAuthRouter } from "@rakettitiede/mcp-oauth-proxy";
import { createMcpRouters } from "@rakettitiede/mcp-server-kit";

import { doSearch } from "./do-search.mjs";
import { doFetch } from "./do-fetch.mjs";
import { openapi } from "./openapi.mjs";
import { SERVER_NAME, SERVER_VERSION, PORT, API_KEY, NODE_ENV,
         GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from "./constants.mjs";

const requireAuth = createRequireAuth({
  apiKey: API_KEY,
  googleClientId: GOOGLE_CLIENT_ID,
  nodeEnv: NODE_ENV,
});

const { oauthRouter } = createOAuthRouter({
  googleClientId: GOOGLE_CLIENT_ID,
  googleClientSecret: GOOGLE_CLIENT_SECRET,
});

const { sseRouter, streamableHttpRouter, apiRouter } = createMcpRouters({
  name: SERVER_NAME,
  version: SERVER_VERSION,
  search: doSearch,
  fetch: doFetch,
  openapi,
});

const app = express();
app.use(express.json());

app.use("/oauth", oauthRouter);          // public — Custom GPT OAuth flow
app.use("/sse", requireAuth);            // protected
app.use("/mcp", requireAuth);            // protected
app.use("/api/v1", requireAuth);         // protected

app.use(sseRouter);
app.use(streamableHttpRouter);
app.use(apiRouter);

app.listen(PORT, "0.0.0.0");
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | Yes | API key for local dev and admin use |
| `GOOGLE_CLIENT_ID` | Only for OAuth | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Only for OAuth | Google OAuth client secret |
| `NODE_ENV` | Recommended | Set to `production` in prod |
