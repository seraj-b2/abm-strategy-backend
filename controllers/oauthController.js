const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const OAuthClient = require('../models/OAuthClient');
const AuthorizationCode = require('../models/AuthorizationCode');
const McpToken = require('../models/McpToken');
const User = require('../models/User');

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = new OAuth2Client(googleClientId);

const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

function getBaseUrl(req) {
  // nginx strips the /api prefix before proxying to this service, so the
  // externally-visible base URL (including /api) cannot be derived from the
  // request itself and must be configured explicitly.
  return process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

/**
 * GET /.well-known/oauth-authorization-server
 * RFC 8414 authorization server metadata
 */
const getAuthorizationServerMetadata = (req, res) => {
  const baseUrl = getBaseUrl(req);
  return res.status(200).json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none']
  });
};

/**
 * POST /oauth/register
 * RFC 7591 Dynamic Client Registration - open registration
 */
const registerClient = async (req, res) => {
  try {
    const { redirect_uris: redirectUris, client_name: clientName } = req.body;

    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      return res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: 'redirect_uris is required and must be a non-empty array'
      });
    }

    const { clientId, clientSecret } = OAuthClient.generateCredentials();
    const clientSecretHash = OAuthClient.hashSecret(clientSecret);

    await OAuthClient.create({
      clientId,
      clientSecretHash,
      clientName: clientName || 'MCP Client',
      redirectUris
    });

    return res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
      client_name: clientName || 'MCP Client',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'client_secret_post',
      grant_types: ['authorization_code'],
      response_types: ['code']
    });
  } catch (error) {
    console.error('[OAuth Register Error]', error);
    return res.status(500).json({ error: 'server_error', error_description: error.message });
  }
};

function renderLoginPage({ error } = {}) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Sign in to ABM Strategy MCP</title>
  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <style>
    body { font-family: system-ui, sans-serif; background: #0B0F17; color: #e2e8f0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #111827; padding: 2.5rem; border-radius: 12px; text-align: center; max-width: 360px; }
    h1 { font-size: 1.25rem; margin-bottom: 1.5rem; }
    .error { color: #f87171; margin-bottom: 1rem; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in to connect to ABM Strategy MCP</h1>
    ${error ? `<div class="error">${error}</div>` : ''}
    <div id="g_id_onload"
      data-client_id="${googleClientId}"
      data-callback="handleCredentialResponse">
    </div>
    <div class="g_id_signin" data-type="standard"></div>
  </div>
  <form id="submitForm" method="POST" style="display:none">
    <input type="hidden" name="credential" id="credentialInput" />
  </form>
  <script>
    function handleCredentialResponse(response) {
      document.getElementById('credentialInput').value = response.credential;
      document.getElementById('submitForm').submit();
    }
  </script>
</body>
</html>`;
}

/**
 * GET /oauth/authorize
 * Serves a Google Sign-In page; the form POSTs back to this same endpoint.
 */
const showAuthorizePage = async (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, state, response_type: responseType } = req.query;

  if (responseType !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  const client = await OAuthClient.findOne({ clientId });
  if (!client || !client.redirectUris.includes(redirectUri)) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id or redirect_uri' });
  }

  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(renderLoginPage());
};

/**
 * POST /oauth/authorize
 * Handles the Google credential submitted from the login page, issues an
 * authorization code, and redirects back to the client's redirect_uri.
 */
const submitAuthorizePage = async (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, state, code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod } = req.query;
  const { credential } = req.body;

  const client = await OAuthClient.findOne({ clientId });
  if (!client || !client.redirectUris.includes(redirectUri)) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id or redirect_uri' });
  }

  try {
    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: googleClientId });
      payload = ticket.getPayload();
    } catch (verifyError) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(400).send(renderLoginPage({ error: 'Sign-in failed. Please try again.' }));
    }

    const { sub: googleId, email, name, given_name, family_name, picture } = payload;

    let user = await User.findOne({ $or: [{ googleId }, { googleSub: googleId }, { email }] });
    if (user) {
      user.googleId = googleId || user.googleId;
      user.googleSub = googleId || user.googleSub;
      user.name = name || user.name;
      user.givenName = given_name || user.givenName;
      user.familyName = family_name || user.familyName;
      user.picture = picture || user.picture;
      user.lastLoginAt = new Date();
      await user.save();
    } else {
      user = await User.create({
        googleId,
        googleSub: googleId,
        email,
        name: name || email.split('@')[0],
        givenName: given_name || '',
        familyName: family_name || '',
        picture: picture || '',
        lastLoginAt: new Date()
      });
    }

    const rawCode = AuthorizationCode.generateRawCode();
    await AuthorizationCode.create({
      codeHash: AuthorizationCode.hashCode(rawCode),
      clientId,
      userId: user._id,
      redirectUri,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || null,
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS)
    });

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set('code', rawCode);
    if (state) redirectUrl.searchParams.set('state', state);

    return res.redirect(302, redirectUrl.toString());
  } catch (error) {
    console.error('[OAuth Authorize Error]', error);
    return res.status(500).json({ error: 'server_error', error_description: error.message });
  }
};

function verifyPkce(codeChallenge, codeChallengeMethod, codeVerifier) {
  if (!codeChallenge) return true;
  if (!codeVerifier) return false;

  if (codeChallengeMethod === 'plain') {
    return codeVerifier === codeChallenge;
  }

  const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return computed === codeChallenge;
}

/**
 * POST /oauth/token
 * Exchanges an authorization code for an mcp_live_ access token.
 */
const issueToken = async (req, res) => {
  try {
    const {
      grant_type: grantType,
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: codeVerifier
    } = req.body;

    if (grantType !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const client = await OAuthClient.findOne({ clientId });
    if (!client) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    if (clientSecret && OAuthClient.hashSecret(clientSecret) !== client.clientSecretHash) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    const codeHash = AuthorizationCode.hashCode(code || '');
    const authCode = await AuthorizationCode.findOne({ codeHash, clientId });

    if (!authCode || authCode.used || authCode.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' });
    }

    if (authCode.redirectUri !== redirectUri) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }

    if (!verifyPkce(authCode.codeChallenge, authCode.codeChallengeMethod, codeVerifier)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }

    authCode.used = true;
    await authCode.save();

    const { rawToken } = McpToken.generateRawToken();
    const tokenHash = McpToken.hashToken(rawToken);

    await McpToken.create({
      userId: authCode.userId,
      name: `OAuth (${client.clientName})`,
      tokenHash,
      tokenPrefix: `${rawToken.substring(0, 14)}...${rawToken.substring(rawToken.length - 4)}`,
      scopes: ['abm:read', 'abm:write', 'mcp:execute']
    });

    return res.status(200).json({
      access_token: rawToken,
      token_type: 'bearer'
    });
  } catch (error) {
    console.error('[OAuth Token Error]', error);
    return res.status(500).json({ error: 'server_error', error_description: error.message });
  }
};

module.exports = {
  getAuthorizationServerMetadata,
  registerClient,
  showAuthorizePage,
  submitAuthorizePage,
  issueToken
};
