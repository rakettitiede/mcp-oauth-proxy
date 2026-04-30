import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createRequireAuth } from '../src/require-auth.mjs';

function mockReq({ headers = {}, query = {} } = {}) {
  return { headers, query };
}

function mockRes() {
  const res = {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(b) { this.body = b; return this; }
  };
  return res;
}

function makeNext() {
  let called = false;
  const fn = () => { called = true; };
  fn.wasCalled = () => called;
  return fn;
}

const silentLogger = { log() {}, error() {} };

const baseConfig = {
  apiKey: 'test-api-key-secret',
  googleClientId: 'test-client-id.apps.googleusercontent.com',
  logger: silentLogger,
  nodeEnv: 'test',
};

describe('createRequireAuth — config validation', () => {
  it('throws when called with empty config', () => {
    assert.throws(() => createRequireAuth({}), /apiKey is required/);
  });

  it('throws when apiKey is missing', () => {
    assert.throws(
      () => createRequireAuth({ googleClientId: 'x' }),
      /apiKey is required/
    );
  });

  it('does not throw with apiKey only', () => {
    assert.doesNotThrow(() => createRequireAuth({ apiKey: 'x', logger: silentLogger }));
  });

  it('does not throw when both params provided', () => {
    assert.doesNotThrow(() => createRequireAuth(baseConfig));
  });
});

describe('createRequireAuth — no auth → 401', () => {
  it('returns 401 with empty headers and query', async () => {
    const mw = createRequireAuth(baseConfig);
    const req = mockReq();
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
    assert.deepStrictEqual(res.body, { error: 'Unauthorized' });
    assert.strictEqual(next.wasCalled(), false);
  });
});

describe('createRequireAuth — API key paths', () => {
  it('valid key in x-api-key header → api-key auth, next called', async () => {
    const mw = createRequireAuth(baseConfig);
    const req = mockReq({ headers: { 'x-api-key': 'test-api-key-secret' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'api-key');
  });

  it('valid key in api_key query param → api-key auth, next called', async () => {
    const mw = createRequireAuth(baseConfig);
    const req = mockReq({ query: { api_key: 'test-api-key-secret' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'api-key');
  });

  it('wrong key in header → 401, next not called', async () => {
    const mw = createRequireAuth(baseConfig);
    const req = mockReq({ headers: { 'x-api-key': 'wrong-key' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(next.wasCalled(), false);
  });
});

describe('createRequireAuth — Bearer token paths', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('IAM identity token happy path (JWT-shaped token)', async () => {
    globalThis.fetch = async (url) => {
      if (url.includes('id_token=')) {
        return {
          ok: true,
          json: async () => ({
            sub: 'sub-iam-1',
            email: 'service-account@developer.gserviceaccount.com',
          }),
        };
      }
      return { ok: false };
    };

    const mw = createRequireAuth(baseConfig);
    // JWT-shaped: exactly 2 dots
    const req = mockReq({ headers: { authorization: 'Bearer header.payload.signature' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'iam');
    assert.strictEqual(req.user.email, 'service-account@developer.gserviceaccount.com');
    assert.strictEqual(req.user.id, 'sub-iam-1');
  });

  it('OAuth access_token happy path (non-JWT token)', async () => {
    globalThis.fetch = async (url) => {
      if (url.includes('access_token=')) {
        return {
          ok: true,
          json: async () => ({
            sub: 'sub-oauth-1',
            email: 'user@example.com',
            aud: 'test-client-id.apps.googleusercontent.com',
          }),
        };
      }
      return { ok: false };
    };

    const mw = createRequireAuth(baseConfig);
    // No dots → not JWT-shaped → skips IAM path, goes straight to OAuth
    const req = mockReq({ headers: { authorization: 'Bearer opaque-access-token' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'oauth');
    assert.strictEqual(req.user.email, 'user@example.com');
    assert.strictEqual(req.user.id, 'sub-oauth-1');
  });

  it('Bearer token with wrong aud → falls through to 401', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        sub: 'sub-wrong',
        email: 'user@example.com',
        aud: 'wrong-client-id',
      }),
    });

    const mw = createRequireAuth(baseConfig);
    const req = mockReq({ headers: { authorization: 'Bearer opaque-access-token' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(next.wasCalled(), false);
  });

  it('fetch throws → falls through to 401 when no valid api key', async () => {
    globalThis.fetch = async () => { throw new Error('network error'); };

    const mw = createRequireAuth(baseConfig);
    const req = mockReq({ headers: { authorization: 'Bearer opaque-access-token' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(next.wasCalled(), false);
  });

  it('fetch throws → falls through to api-key when valid key also present', async () => {
    globalThis.fetch = async () => { throw new Error('network error'); };

    const mw = createRequireAuth(baseConfig);
    const req = mockReq({
      headers: {
        authorization: 'Bearer opaque-access-token',
        'x-api-key': 'test-api-key-secret',
      },
    });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'api-key');
  });
});

describe('createRequireAuth — OAuth path disabled when googleClientId missing', () => {
  let originalFetch;
  const noOAuthConfig = {
    apiKey: 'test-api-key-secret',
    logger: silentLogger,
    nodeEnv: 'test',
  };

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('non-JWT Bearer token → 401 when no googleClientId and no API key', async () => {
    let fetchCalls = 0;
    globalThis.fetch = async () => { fetchCalls++; return { ok: false }; };

    const mw = createRequireAuth(noOAuthConfig);
    const req = mockReq({ headers: { authorization: 'Bearer opaque-access-token' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(next.wasCalled(), false);
    assert.strictEqual(fetchCalls, 0, 'fetch should never be called when googleClientId is missing and token is not JWT');
  });

  it('non-JWT Bearer token → API key fallback when key present', async () => {
    let fetchCalls = 0;
    globalThis.fetch = async () => { fetchCalls++; return { ok: false }; };

    const mw = createRequireAuth(noOAuthConfig);
    const req = mockReq({
      headers: {
        authorization: 'Bearer opaque-access-token',
        'x-api-key': 'test-api-key-secret',
      },
    });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'api-key');
    assert.strictEqual(fetchCalls, 0, 'fetch should never be called for OAuth path when googleClientId is missing');
  });

  it('JWT-shaped Bearer token → IAM validation still works without googleClientId', async () => {
    globalThis.fetch = async (url) => {
      if (url.includes('id_token=')) {
        return {
          ok: true,
          json: async () => ({
            sub: 'sub-iam-no-oauth',
            email: 'svc@developer.gserviceaccount.com',
          }),
        };
      }
      throw new Error('access_token fetch should not be called');
    };

    const mw = createRequireAuth(noOAuthConfig);
    const req = mockReq({ headers: { authorization: 'Bearer header.payload.signature' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(next.wasCalled(), true);
    assert.strictEqual(req.user.authMethod, 'iam');
    assert.strictEqual(req.user.email, 'svc@developer.gserviceaccount.com');
  });

  it('tokeninfo access_token endpoint is NEVER called when googleClientId is missing', async () => {
    globalThis.fetch = async (url) => {
      if (url.includes('access_token=')) {
        throw new Error('access_token fetch must not be called when googleClientId is missing');
      }
      return { ok: false };
    };

    const mw = createRequireAuth(noOAuthConfig);
    const req = mockReq({ headers: { authorization: 'Bearer opaque-token' } });
    const res = mockRes();
    const next = makeNext();
    await mw(req, res, next);
    assert.strictEqual(res.statusCode, 401);
  });
});
