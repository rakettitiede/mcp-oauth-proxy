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

      const looksLikeJwt = (token.match(/\./g) || []).length === 2;

      // If token looks like a JWT, try IAM identity token validation first
      if (looksLikeJwt) {
        try {
          const response = await fetch(
            `${googleTokeninfoUrl}?id_token=${token}`
          );

          if (!response.ok) {
            logger.log(`❌ IAM token validation failed: tokeninfo returned ${response.status}`);
          } else {
            const tokenInfo = await response.json();
            const expectedAudience = `${req.get('x-forwarded-proto') || 'https'}://${req.get('x-forwarded-host') || req.get('host')}`;

            if (tokenInfo.aud === expectedAudience) {
              logger.log(`🛡️ IAM Bearer auth: ${tokenInfo.email}`);
              req.user = { authMethod: 'iam', email: tokenInfo.email };
              return next();
            } else {
              logger.log(`🎯 IAM token audience mismatch: got ${tokenInfo.aud}, expected ${expectedAudience}`);
            }
          }
        } catch (e) {
          logger.log(`💥 IAM token validation error: ${e.message}`);
        }
      }

      // Try OAuth access_token validation (only when googleClientId is configured)
      if (googleClientId) {
        try {
          const response = await fetch(
            `${googleTokeninfoUrl}?access_token=${token}`
          );

          if (response.ok) {
            const tokenInfo = await response.json();

            if (tokenInfo.aud === googleClientId) {
              req.user = {
                id: tokenInfo.sub,
                email: tokenInfo.email,
                authMethod: 'oauth'
              };
              logger.log(`🛡️ OAuth authentication (user: ${tokenInfo.email})`);
              return next();
            }
          }
        } catch (err) {
          // OAuth validation failed, fall through to API key
        }
      }
    }

    const reqApiKey = req.headers['x-api-key'] || req.query.api_key;

    if (reqApiKey === apiKey) {
      req.user = { id: 'api-key', email: null, authMethod: 'api-key' };
      return next();
    }

    return res.status(401).json({ error: "Unauthorized" });
  }

  return requireAuth;
}
