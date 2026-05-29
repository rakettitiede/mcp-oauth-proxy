/**
 * Factory that returns an Express authentication middleware.
 *
 * Supports three auth methods (tried in order):
 *   1. Google IAM identity token (JWT with service-account email)
 *   2. Google OAuth access token (aud must match googleClientId)
 *   3. Static API key (x-api-key header or api_key query param)
 *
 * @param {object}  config
 * @param {string}  config.apiKey              - Required. Static API key to accept.
 * @param {string}  [config.googleClientId]    - Optional. Expected `aud` for OAuth access tokens. When omitted, the OAuth access token validation path is disabled and non-JWT Bearer tokens fall through to API key or 401.
 * @param {string}  [config.googleTokeninfoUrl] - Default 'https://oauth2.googleapis.com/tokeninfo'.
 * @param {object}  [config.logger]            - Default `console`. Must expose `.log()` and `.error()`.
 * @param {string}  [config.nodeEnv]           - Default `process.env.NODE_ENV`.
 * @returns {function} async requireAuth(req, res, next)
 */
export function createRequireAuth({
  apiKey,
  googleClientId,
  googleTokeninfoUrl = 'https://oauth2.googleapis.com/tokeninfo',
  logger = console,
  nodeEnv = process.env.NODE_ENV,
} = {}) {
  if (!apiKey) {
    throw new Error('createRequireAuth: apiKey is required');
  }
  async function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      logger.log(`[DEBUG] Bearer token received, length: ${token.length}`);

      const looksLikeJwt = (token.match(/\./g) || []).length === 2;
      logger.log(`[DEBUG] Token looks like JWT: ${looksLikeJwt}`);

      // If token looks like a JWT, try IAM identity token validation first
      if (looksLikeJwt) {
        try {
          logger.log('[DEBUG] Attempting IAM identity token validation...');
          const response = await fetch(
            `${googleTokeninfoUrl}?id_token=${token}`
          );
          logger.log(`[DEBUG] IAM tokeninfo response status: ${response.status}`);

          if (response.ok) {
            const tokenInfo = await response.json();
            logger.log(`[DEBUG] IAM token claims: email=${tokenInfo.email}, sub=${tokenInfo.sub}`);

            if (tokenInfo.email?.endsWith('@developer.gserviceaccount.com')) {
              req.user = {
                id: tokenInfo.sub,
                email: tokenInfo.email,
                authMethod: 'iam'
              };
              logger.log(`🛡️ IAM identity token authentication (service: ${tokenInfo.email})`);
              return next();
            } else {
              logger.log(`[DEBUG] IAM token email does not end with @developer.gserviceaccount.com: ${tokenInfo.email}`);
            }
          } else {
            const errorBody = await response.text();
            logger.log(`[DEBUG] IAM tokeninfo failed (${response.status}): ${errorBody}`);
          }
        } catch (err) {
          logger.log('[DEBUG] IAM identity token validation error:', err.message);
        }
      }

      // Try OAuth access_token validation (only when googleClientId is configured)
      if (googleClientId) {
        logger.log(`[DEBUG] Attempting OAuth access token validation with googleClientId: ${googleClientId}`);
        try {
          const response = await fetch(
            `${googleTokeninfoUrl}?access_token=${token}`
          );
          logger.log(`[DEBUG] OAuth tokeninfo response status: ${response.status}`);

          if (response.ok) {
            const tokenInfo = await response.json();
            logger.log(`[DEBUG] OAuth token claims: aud=${tokenInfo.aud}, email=${tokenInfo.email}, sub=${tokenInfo.sub}`);

            if (tokenInfo.aud === googleClientId) {
              req.user = {
                id: tokenInfo.sub,
                email: tokenInfo.email,
                authMethod: 'oauth'
              };
              logger.log(`🛡️ OAuth authentication (user: ${tokenInfo.email})`);
              return next();
            } else {
              logger.log(`[DEBUG] OAuth token aud mismatch: expected ${googleClientId}, got ${tokenInfo.aud}`);
            }
          } else {
            const errorBody = await response.text();
            logger.log(`[DEBUG] OAuth tokeninfo failed (${response.status}): ${errorBody}`);
          }
        } catch (err) {
          logger.log('[DEBUG] OAuth access token validation error:', err.message);
        }
      } else {
        logger.log('[DEBUG] OAuth validation skipped: googleClientId not configured');
      }
    } else {
      logger.log(`[DEBUG] No Bearer token in Authorization header. Header: ${authHeader ? authHeader.substring(0, 50) : 'MISSING'}`);
    }

    const reqApiKey = req.headers['x-api-key'] || req.query.api_key;
    logger.log(`[DEBUG] Checking API key. Present: ${!!reqApiKey}, source: ${req.headers['x-api-key'] ? 'x-api-key header' : 'api_key query'}`);

    if (nodeEnv === "production") {
      logger.log(`🔑 API key authentication ${reqApiKey ? '[PRESENT]' : '[MISSING]'}`);
    }

    if (reqApiKey === apiKey) {
      req.user = { id: 'api-key', email: null, authMethod: 'api-key' };
      return next();
    }

    logger.log('[DEBUG] Authentication failed - rejecting with 401. Tried: Bearer token, API key');
    return res.status(401).json({ error: "Unauthorized" });
  }

  return requireAuth;
}
