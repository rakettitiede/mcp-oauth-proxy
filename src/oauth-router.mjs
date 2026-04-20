/**
 * Factory that returns an Express Router implementing the OAuth proxy flow
 * for bridging Custom GPT's OAuth expectations to Google as IdP.
 *
 * Endpoints:
 *   GET  /authorize  — Redirects user to Google OAuth consent screen
 *   GET  /callback   — Receives Google's auth code, exchanges for tokens,
 *                       stores them, redirects back to Custom GPT
 *   POST /token      — Custom GPT exchanges our temporary code for Google tokens
 *
 * @param {object}  config
 * @param {string}  config.googleClientId      - Required. Google OAuth client ID.
 * @param {string}  config.googleClientSecret   - Required. Google OAuth client secret.
 * @param {object}  [config.tokenStore]         - Default: in-memory Map with lazy expiry.
 * @param {number}  [config.tokenTtlMs]         - Default: 5 * 60 * 1000 (5 minutes).
 * @param {object}  [config.logger]             - Default: console.
 * @returns {import('express').Router}
 */

import { Router, urlencoded } from 'express';
import crypto from 'node:crypto';
import { createMemoryTokenStore } from './memory-token-store.mjs';

// Generate a short-lived code
function generateCode() {
  return crypto.randomBytes(32).toString('hex');
}

// Extract email from Google's id_token (JWT) for logging
function extractEmailFromIdToken(idToken) {
  if (!idToken) return null;
  try {
    const payload = idToken.split('.')[1];
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return decoded.email || null;
  } catch {
    return null;
  }
}

export function createOAuthRouter({
  googleClientId,
  googleClientSecret,
  tokenStore,
  tokenTtlMs = 5 * 60 * 1000,
  logger = console,
} = {}) {
  if (!googleClientId) {
    throw new Error('createOAuthRouter: googleClientId is required');
  }
  if (!googleClientSecret) {
    throw new Error('createOAuthRouter: googleClientSecret is required');
  }

  if (!tokenStore) {
    tokenStore = createMemoryTokenStore();
  }

  const router = Router();

  /**
   * GET /oauth/authorize
   *
   * Custom GPT redirects user here. We redirect to Google.
   * Query params from Custom GPT:
   *   - redirect_uri: where Custom GPT wants the final redirect
   *   - state: Custom GPT's state (we pass through)
   *   - response_type: "code" (we ignore, always use code)
   *   - client_id: Custom GPT's client_id (we ignore, use our Google client_id)
   */
  router.get('/authorize', (req, res) => {
    const { redirect_uri, state } = req.query;
    logger.log(`🔐 GET /oauth/authorize`);

    if (!redirect_uri) {
      logger.log(`🔐 /oauth/authorize failed: missing redirect_uri`);
      return res.status(400).json({ error: 'redirect_uri is required' });
    }

    // Build our callback URL (where Google will redirect back)
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const ourCallbackUrl = `${protocol}://${host}/oauth/callback`;

    // Store Custom GPT's redirect_uri and state so we can use them in callback
    // We encode this in Google's state parameter
    const oauthState = Buffer.from(JSON.stringify({
      redirectUri: redirect_uri,
      originalState: state || '',
      nonce: crypto.randomBytes(16).toString('hex')
    })).toString('base64url');

    // Redirect to Google OAuth
    const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    googleAuthUrl.searchParams.set('client_id', googleClientId);
    googleAuthUrl.searchParams.set('redirect_uri', ourCallbackUrl);
    googleAuthUrl.searchParams.set('response_type', 'code');
    googleAuthUrl.searchParams.set('scope', 'openid email profile');
    googleAuthUrl.searchParams.set('state', oauthState);
    googleAuthUrl.searchParams.set('access_type', 'offline');
    googleAuthUrl.searchParams.set('prompt', 'consent');

    logger.log(`🔐 /oauth/authorize redirecting to Google OAuth`);
    res.redirect(googleAuthUrl.toString());
  });

  /**
   * GET /oauth/callback
   *
   * Google redirects here after user authenticates.
   * We exchange Google's code for tokens, store them, redirect to Custom GPT.
   */
  router.get('/callback', async (req, res) => {
    const { code, state, error } = req.query;
    logger.log(`🔑 GET /oauth/callback`);

    if (error) {
      logger.error(`🔑 /oauth/callback failed: Google OAuth error: ${error}`);
      return res.status(400).json({ error: `Google OAuth error: ${error}` });
    }

    if (!code || !state) {
      logger.error(`🔑 /oauth/callback failed: missing code or state`);
      return res.status(400).json({ error: 'Missing code or state' });
    }

    // Decode state to get Custom GPT's redirect_uri
    let stateData;
    try {
      stateData = JSON.parse(Buffer.from(state, 'base64url').toString());
    } catch {
      logger.error(`🔑 /oauth/callback failed: invalid state parameter`);
      return res.status(400).json({ error: 'Invalid state parameter' });
    }

    const { redirectUri, originalState } = stateData;

    // Build our callback URL for token exchange
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const ourCallbackUrl = `${protocol}://${host}/oauth/callback`;

    // Exchange code for tokens with Google
    try {
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: googleClientId,
          client_secret: googleClientSecret,
          redirect_uri: ourCallbackUrl,
          grant_type: 'authorization_code'
        })
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        logger.error(`🔑 /oauth/callback failed: Google token exchange failed`);
        return res.status(502).json({ error: 'Failed to exchange code with Google' });
      }

      const tokens = await tokenResponse.json();

      // Generate our temporary code and store the tokens
      const tempCode = generateCode();
      await tokenStore.set(tempCode, {
        tokens,
        expiresAt: Date.now() + tokenTtlMs
      });

      // Redirect to Custom GPT with our temporary code
      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set('code', tempCode);
      if (originalState) {
        redirectUrl.searchParams.set('state', originalState);
      }

      const email = extractEmailFromIdToken(tokens.id_token);
      logger.log(`🔑 /oauth/callback success: ${email || 'unknown user'} authenticated`);
      res.redirect(redirectUrl.toString());
    } catch (err) {
      logger.error(`🔑 /oauth/callback error:`, err.message);
      return res.status(500).json({ error: 'Internal server error during OAuth' });
    }
  });

  /**
   * POST /oauth/token
   *
   * Custom GPT calls this to exchange our temporary code for tokens.
   * We return Google's tokens directly.
   */
  router.post('/token', urlencoded({ extended: false }), async (req, res) => {
    const { code, grant_type } = req.body;
    logger.log(`🎫 POST /oauth/token`);

    if (grant_type !== 'authorization_code') {
      logger.log(`🎫 /oauth/token failed: unsupported grant_type`);
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    if (!code) {
      logger.log(`🎫 /oauth/token failed: missing code`);
      return res.status(400).json({ error: 'invalid_request', error_description: 'code is required' });
    }

    const pending = await tokenStore.get(code);

    if (!pending) {
      logger.log(`🎫 /oauth/token failed: code expired or invalid`);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired or invalid' });
    }

    // Remove the code (one-time use)
    await tokenStore.delete(code);

    const email = extractEmailFromIdToken(pending.tokens.id_token);
    logger.log(`🎫 /oauth/token success: tokens exchanged for ${email || 'unknown user'}`);
    // Return Google's tokens to Custom GPT
    res.json(pending.tokens);
  });

  return router;
}
