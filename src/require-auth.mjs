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
 * @param {string}  config.googleClientId      - Required. Expected `aud` for OAuth tokens.
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
  if (!googleClientId) {
    throw new Error('createRequireAuth: googleClientId is required');
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

          if (response.ok) {
            const tokenInfo = await response.json();

            if (tokenInfo.email?.endsWith('@developer.gserviceaccount.com')) {
              req.user = {
                id: tokenInfo.sub,
                email: tokenInfo.email,
                authMethod: 'iam'
              };
              logger.log(`🛡️ IAM identity token authentication (service: ${tokenInfo.email})`);
              return next();
            }
          }
        } catch (err) {
          if (nodeEnv !== 'production') {
            logger.log('IAM identity token validation failed:', err.message);
          }
        }
      }

      // Try OAuth access_token validation
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
        if (nodeEnv !== 'production') {
          logger.log('Bearer token validation failed:', err.message);
        }
      }
    }

    const reqApiKey = req.headers['x-api-key'] || req.query.api_key;

    if (nodeEnv === "production") {
      logger.log(`🔑 API key authentication ${reqApiKey ? '[PRESENT]' : '[MISSING]'}`);
    }

    if (reqApiKey === apiKey) {
      req.user = { id: 'api-key', email: null, authMethod: 'api-key' };
      return next();
    }

    return res.status(401).json({ error: "Unauthorized" });
  }

  return requireAuth;
}
