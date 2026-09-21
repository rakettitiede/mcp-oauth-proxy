import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import express from 'express';
import { createOAuthRouter } from '../src/oauth-router.mjs';
import { createMemoryTokenStore } from '../src/memory-token-store.mjs';

// TODO: integration test for /oauth/callback — skipped for v0.1.0 unit tests
// because it requires outbound calls to oauth2.googleapis.com/token.

const silentLogger = { log() {}, error() {} };

const baseConfig = {
  googleClientId: 'test-client-id.apps.googleusercontent.com',
  googleClientSecret: 'test-client-secret',
  logger: silentLogger,
};

async function startApp(routerConfig) {
  const app = express();
  app.use('/oauth', createOAuthRouter(routerConfig).oauthRouter);
  const server = createServer(app);
  await new Promise(r => server.listen(0, r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const close = () => new Promise(r => server.close(r));
  return { base, close };
}

describe('createOAuthRouter — config validation', () => {
  it('throws when googleClientId is missing', () => {
    assert.throws(
      () => createOAuthRouter({ googleClientSecret: 'x' }),
      /googleClientId is required/
    );
  });

  it('throws when googleClientSecret is missing', () => {
    assert.throws(
      () => createOAuthRouter({ googleClientId: 'x' }),
      /googleClientSecret is required/
    );
  });
});

describe('GET /oauth/authorize', () => {
  let base, close;

  before(async () => {
    ({ base, close } = await startApp(baseConfig));
  });

  after(async () => {
    await close();
  });

  it('returns 400 when redirect_uri is missing', async () => {
    const res = await fetch(`${base}/oauth/authorize`);
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error, 'redirect_uri is required');
  });

  it('redirects to Google OAuth with correct params', async () => {
    const redirectUri = 'https://example.com/callback';
    const state = 'custom-gpt-state-abc';
    const url = `${base}/oauth/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;

    const res = await fetch(url, { redirect: 'manual' });
    assert.strictEqual(res.status, 302);

    const location = res.headers.get('location');
    assert.ok(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));

    const parsed = new URL(location);
    assert.strictEqual(parsed.searchParams.get('client_id'), 'test-client-id.apps.googleusercontent.com');
    assert.strictEqual(parsed.searchParams.get('response_type'), 'code');
    assert.strictEqual(parsed.searchParams.get('access_type'), 'offline');
    assert.ok(parsed.searchParams.get('scope').includes('openid'));

    // Decode state and verify it round-trips
    const encodedState = parsed.searchParams.get('state');
    const stateData = JSON.parse(Buffer.from(encodedState, 'base64url').toString());
    assert.strictEqual(stateData.redirectUri, redirectUri);
    assert.strictEqual(stateData.originalState, state);
    assert.ok(stateData.nonce);
  });
});

describe('POST /oauth/token', () => {
  let base, close, tokenStore;

  before(async () => {
    tokenStore = createMemoryTokenStore();
    ({ base, close } = await startApp({ ...baseConfig, tokenStore }));
  });

  after(async () => {
    await close();
  });

  it('returns 400 for wrong grant_type', async () => {
    const res = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&code=abc',
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error, 'unsupported_grant_type');
  });

  it('returns 400 when code is missing', async () => {
    const res = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code',
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error, 'invalid_request');
  });

  it('returns 400 for unknown/expired code', async () => {
    const res = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&code=nonexistent-code',
    });
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error, 'invalid_grant');
  });

  it('happy path: exchanges a valid code for tokens (one-time use)', async () => {
    const fakeTokens = { access_token: 'fake-access-tok', id_token: null };
    tokenStore.set('valid-code-1', {
      tokens: fakeTokens,
      expiresAt: Date.now() + 300_000,
    });

    // First call — success
    const res1 = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&code=valid-code-1',
    });
    assert.strictEqual(res1.status, 200);
    const body1 = await res1.json();
    assert.strictEqual(body1.access_token, 'fake-access-tok');

    // Second call with same code — invalid_grant (one-time use)
    const res2 = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&code=valid-code-1',
    });
    assert.strictEqual(res2.status, 400);
    const body2 = await res2.json();
    assert.strictEqual(body2.error, 'invalid_grant');
  });
});

describe('POST /oauth/token — refresh_token grant', () => {
  it('returns 400 when refresh_token is missing', async () => {
    const { base, close } = await startApp(baseConfig);
    try {
      const res = await fetch(`${base}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=refresh_token',
      });
      assert.strictEqual(res.status, 400);
      assert.deepStrictEqual(await res.json(), {
        error: 'invalid_request',
        error_description: 'refresh_token is required',
      });
    } finally {
      await close();
    }
  });

  it('forwards the refresh grant to Google and returns its tokens', async () => {
    let request;
    const fetchImpl = async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify({
        access_token: 'new-access-token',
        expires_in: 3600,
        token_type: 'Bearer',
        refresh_token: 'rotated-refresh-token',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };
    const { base, close } = await startApp({ ...baseConfig, fetchImpl });

    try {
      const res = await fetch(`${base}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=refresh_token&refresh_token=original-refresh-token',
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual((await res.json()).access_token, 'new-access-token');
      assert.strictEqual(request.url, 'https://oauth2.googleapis.com/token');
      assert.deepStrictEqual(Object.fromEntries(request.options.body), {
        client_id: baseConfig.googleClientId,
        client_secret: baseConfig.googleClientSecret,
        refresh_token: 'original-refresh-token',
        grant_type: 'refresh_token',
      });
    } finally {
      await close();
    }
  });

  it('surfaces a Google OAuth error as a 400 response', async () => {
    const fetchImpl = async () => new Response(JSON.stringify({
      error: 'invalid_grant',
      error_description: 'Token has been revoked.',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
    const { base, close } = await startApp({ ...baseConfig, fetchImpl });

    try {
      const res = await fetch(`${base}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=refresh_token&refresh_token=revoked-token',
      });
      assert.strictEqual(res.status, 400);
      assert.strictEqual((await res.json()).error, 'invalid_grant');
    } finally {
      await close();
    }
  });
});

describe('oauthMeta', () => {
  it('startupLog is the expected string', () => {
    const { oauthMeta } = createOAuthRouter(baseConfig);
    assert.strictEqual(
      oauthMeta.startupLog,
      '🔐 OAuth: GET /oauth/authorize, GET /oauth/callback, POST /oauth/token',
    );
  });

  it('endpoints matches the expected object', () => {
    const { oauthMeta } = createOAuthRouter(baseConfig);
    assert.deepStrictEqual(oauthMeta.endpoints, {
      authorize: '/oauth/authorize',
      callback: '/oauth/callback',
      token: '/oauth/token',
    });
  });

  it('oauthMeta is frozen', () => {
    const { oauthMeta } = createOAuthRouter(baseConfig);
    assert.ok(Object.isFrozen(oauthMeta));
  });

  it('oauthMeta.endpoints is frozen', () => {
    const { oauthMeta } = createOAuthRouter(baseConfig);
    assert.ok(Object.isFrozen(oauthMeta.endpoints));
  });

  it('separate calls return the same oauthMeta shape', () => {
    const { oauthMeta: meta1 } = createOAuthRouter(baseConfig);
    const { oauthMeta: meta2 } = createOAuthRouter(baseConfig);
    assert.deepStrictEqual(meta1, meta2);
  });
});
