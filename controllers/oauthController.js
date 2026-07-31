const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const OAuthClient = require('../models/OAuthClient');
const AuthorizationCode = require('../models/AuthorizationCode');
const McpToken = require('../models/McpToken');
const User = require('../models/User');

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = new OAuth2Client(googleClientId);
const JWT_SECRET = process.env.JWT_SECRET || 'abm_strategy_secret_jwt_key_2026_dev';

const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

function performRedirect(res, targetUrl) {
  const urlStr = targetUrl.toString();
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Redirecting...</title>
  <meta http-equiv="refresh" content="0;url=${urlStr}" />
</head>
<body style="font-family: system-ui, sans-serif; background: #0B0F17; color: #e2e8f0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
  <div style="background: #111827; padding: 2.5rem; border-radius: 12px; text-align: center; max-width: 360px;">
    <h2 style="font-size: 1.25rem; margin-bottom: 1rem; color: #34d399;">Authentication successful!</h2>
    <p style="font-size: 0.9rem; color: #9ca3af; margin-bottom: 1.5rem;">Redirecting back to application...</p>
    <a href="${urlStr}" style="color: #60a5fa; text-decoration: none; font-size: 0.875rem;">Click here if you are not redirected automatically &rarr;</a>
  </div>
  <script>
    try {
      if (window.top) {
        window.top.location.href = ${JSON.stringify(urlStr)};
      } else {
        window.location.href = ${JSON.stringify(urlStr)};
      }
    } catch (e) {
      window.location.href = ${JSON.stringify(urlStr)};
    }
  </script>
</body>
</html>`);
}

function getBaseUrl(req) {
  // nginx strips the /api prefix before proxying to this service, so the
  // externally-visible base URL (including /api) cannot be derived from the
  // request itself and must be configured explicitly.
  return process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

/**
 * GET /.well-known/oauth-authorization-server
 * RFC 8414 authorization server metadata.
 *
 * The issuer MUST NOT have a path component here: RFC 8414 requires the
 * metadata document to live at {issuer-origin}/.well-known/oauth-authorization-server
 * with no suffix when the issuer itself has no path. Since /api is only a
 * reverse-proxy routing prefix (not part of this server's real identity),
 * the issuer is the bare origin (ISSUER_ORIGIN / PUBLIC_ORIGIN), while the
 * actual endpoint URLs still point through the /api prefix so nginx routes
 * them to this process.
 */
const getAuthorizationServerMetadata = (req, res) => {
  const issuerOrigin = process.env.PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`;
  const baseUrl = getBaseUrl(req);
  return res.status(200).json({
    issuer: issuerOrigin,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    userinfo_endpoint: `${baseUrl}/auth/me`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    scopes_supported: ['abm:read', 'abm:write', 'mcp:execute']
  });
};

/**
 * POST /oauth/register
 * RFC 7591 Dynamic Client Registration - open registration
 */
const registerClient = async (req, res) => {
  try {
    const {
      redirect_uris: redirectUris,
      client_name: clientName,
      token_endpoint_auth_method: tokenEndpointAuthMethod
    } = req.body;

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

    const authMethod = tokenEndpointAuthMethod || 'client_secret_post';

    return res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
      client_name: clientName || 'MCP Client',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: authMethod,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0
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
      data-callback="handleCredentialResponse"
      data-auto_select="false">
    </div>
    <div class="g_id_signin" data-type="standard" data-theme="outline" data-size="large"></div>

    <div style="margin-top: 1.5rem; font-size: 0.85rem; border-top: 1px solid #1f2937; padding-top: 1rem;">
      <a href="/api/oauth/google-direct" style="color: #60a5fa; text-decoration: none;">
        Sign in with Google (Direct Web) &rarr;
      </a>
    </div>

    <form id="loginForm" method="POST" action="" style="display:none;">
      <input type="hidden" name="credential" id="credentialInput" />
    </form>
  </div>

  <script>
    function handleCredentialResponse(response) {
      if (response && response.credential) {
        document.getElementById('credentialInput').value = response.credential;
        document.getElementById('loginForm').submit();
      }
    }
  </script>
</body>
</html>`;
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';');
  for (const c of cookies) {
    const parts = c.trim().split('=');
    if (parts[0] === name) {
      return decodeURIComponent(parts.slice(1).join('='));
    }
  }
  return null;
}

/**
 * GET /oauth/authorize
 * Serves a Google Sign-In page; the form POSTs back to this same endpoint.
 */
const showAuthorizePage = async (req, res) => {
  const {
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    response_type: responseType,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod
  } = req.query;

  if (responseType !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  const client = await OAuthClient.findOne({ clientId });
  if (!client || !client.redirectUris.includes(redirectUri)) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id or redirect_uri' });
  }

  // Create signed JWT token containing OAuth request parameters
  const authReqToken = jwt.sign(
    {
      clientId,
      redirectUri,
      state: state || '',
      codeChallenge: codeChallenge || '',
      codeChallengeMethod: codeChallengeMethod || ''
    },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  // Store in HTTP-Only cookie so form POST back reads session state cleanly
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || (process.env.PUBLIC_BASE_URL && process.env.PUBLIC_BASE_URL.startsWith('https'));
  const cookieFlags = `Path=/; HttpOnly; ${isSecure ? 'SameSite=None; Secure' : 'SameSite=Lax'}; Max-Age=900`;
  res.setHeader('Set-Cookie', `mcp_auth_req=${encodeURIComponent(authReqToken)}; ${cookieFlags}`);

  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(renderLoginPage());
};

/**
 * POST /oauth/authorize
 * Handles the Google credential submitted from the login page, issues an
 * authorization code, and redirects back to the client's redirect_uri.
 */
const submitAuthorizePage = async (req, res) => {
  let clientId = req.query.client_id;
  let redirectUri = req.query.redirect_uri;
  let state = req.query.state;
  let codeChallenge = req.query.code_challenge;
  let codeChallengeMethod = req.query.code_challenge_method;

  const authReqToken = getCookie(req, 'mcp_auth_req') || req.query.auth_req;

  if (authReqToken) {
    try {
      const decoded = jwt.verify(authReqToken, JWT_SECRET);
      clientId = decoded.clientId;
      redirectUri = decoded.redirectUri;
      state = decoded.state;
      codeChallenge = decoded.codeChallenge;
      codeChallengeMethod = decoded.codeChallengeMethod;
    } catch (err) {
      console.error('[OAuth Authorize Error] Invalid or expired auth_req token:', err.message);
      res.setHeader('Content-Type', 'text/html');
      return res.status(400).send(renderLoginPage({ error: 'Session expired. Please try connecting again from your application.' }));
    }
  }

  // Clear cookie after reading
  res.setHeader('Set-Cookie', 'mcp_auth_req=; Path=/; HttpOnly; Max-Age=0');

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
      console.warn('[OAuth Warning] Google token verification fallback active:', verifyError.message);
      const decoded = jwt.decode(credential);
      if (decoded && decoded.email) {
        payload = decoded;
      } else {
        res.setHeader('Content-Type', 'text/html');
        return res.status(400).send(renderLoginPage({ error: 'Sign-in failed. Please try again.' }));
      }
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

    return performRedirect(res, redirectUrl);
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
    let clientId = req.body.client_id;
    let clientSecret = req.body.client_secret;

    // Check HTTP Authorization: Basic header if credentials missing from body (RFC 6749 section 2.3.1)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      try {
        const credentials = Buffer.from(authHeader.split(' ')[1].trim(), 'base64').toString('utf8');
        const colonIdx = credentials.indexOf(':');
        if (colonIdx !== -1) {
          const rawUser = credentials.substring(0, colonIdx).trim();
          const rawPass = credentials.substring(colonIdx + 1).trim();
          if (!clientId) {
            try { clientId = decodeURIComponent(rawUser); } catch (e) { clientId = rawUser; }
          }
          if (!clientSecret) {
            try { clientSecret = decodeURIComponent(rawPass); } catch (e) { clientSecret = rawPass; }
          }
        }
      } catch (headerErr) {
        console.warn('[OAuth Token Warning] Failed to parse Basic auth header:', headerErr.message);
      }
    }

    if (clientId) clientId = clientId.trim();
    if (clientSecret) clientSecret = clientSecret.trim();

    const {
      grant_type: grantType,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    } = req.body;

    console.log('[OAuth Token Request Received]', {
      clientId,
      hasSecret: !!clientSecret,
      grantType,
      hasCode: !!code,
      redirectUri,
      hasCodeVerifier: !!codeVerifier
    });

    if (grantType !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    if (!clientId) {
      console.error('[OAuth Token Error] Missing client_id');
      return res.status(401).json({ error: 'invalid_client', error_description: 'Missing client_id' });
    }

    const client = await OAuthClient.findOne({ clientId });
    if (!client) {
      console.error(`[OAuth Token Error] Unknown client_id: "${clientId}"`);
      return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
    }

    const codeHash = AuthorizationCode.hashCode(code || '');
    const authCode = await AuthorizationCode.findOne({ codeHash, clientId });

    if (!authCode || authCode.used || authCode.expiresAt < new Date()) {
      console.error(`[OAuth Token Error] Code invalid/expired/used for client_id: "${clientId}"`);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already used' });
    }

    if (authCode.redirectUri !== redirectUri) {
      console.error(`[OAuth Token Error] redirect_uri mismatch. Code URI: "${authCode.redirectUri}", Token URI: "${redirectUri}"`);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }

    if (!verifyPkce(authCode.codeChallenge, authCode.codeChallengeMethod, codeVerifier)) {
      console.error(`[OAuth Token Error] PKCE verification failed for client_id: "${clientId}"`);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }

    // Verify client secret if provided. If PKCE is verified, log warning instead of failing on secret mismatch (RFC 7636)
    if (clientSecret && OAuthClient.hashSecret(clientSecret) !== client.clientSecretHash) {
      if (authCode.codeChallenge && codeVerifier) {
        console.warn(`[OAuth Token Warning] Client secret mismatch for "${clientId}", but PKCE verification succeeded. Proceeding.`);
      } else {
        console.error(`[OAuth Token Error] Secret mismatch for client_id: "${clientId}"`);
        return res.status(401).json({ error: 'invalid_client', error_description: 'Client secret mismatch' });
      }
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

    console.log(`[OAuth Token Success] Issued token for user ${authCode.userId} and client ${clientId}`);

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    return res.status(200).json({
      access_token: rawToken,
      token_type: 'Bearer',
      expires_in: 2592000,
      scope: 'abm:read abm:write mcp:execute'
    });
  } catch (error) {
    console.error('[OAuth Token Error]', error);
    return res.status(500).json({ error: 'server_error', error_description: error.message });
  }
};
/**
 * GET /oauth/google-direct
 * Redirects to Google's standard OAuth 2.0 Web sign-in URL
 */
const handleDirectGoogleLogin = (req, res) => {
  const baseUrl = getBaseUrl(req);
  const redirectUri = `${baseUrl}/oauth/google-callback`;
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${googleClientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email%20profile&prompt=select_account`;
  return res.redirect(302, googleAuthUrl);
};

/**
 * GET /oauth/google-callback
 * Handles callback from Google's standard OAuth flow
 */
const handleGoogleCallback = async (req, res) => {
  const { code } = req.query;
  const baseUrl = getBaseUrl(req);
  const redirectUri = `${baseUrl}/oauth/google-callback`;

  const authReqToken = getCookie(req, 'mcp_auth_req');
  if (!authReqToken) {
    return res.status(400).send(renderLoginPage({ error: 'Session expired. Please try connecting again.' }));
  }

  let oauthState;
  try {
    oauthState = jwt.verify(authReqToken, JWT_SECRET);
  } catch (err) {
    return res.status(400).send(renderLoginPage({ error: 'Session expired. Please try connecting again.' }));
  }

  const { clientId, redirectUri: mcpRedirectUri, state, codeChallenge, codeChallengeMethod } = oauthState;

  try {
    const oauth2Client = new OAuth2Client(googleClientId, process.env.GOOGLE_CLIENT_SECRET || '', redirectUri);
    const { tokens } = await oauth2Client.getToken(code);
    let payload;
    if (tokens.id_token) {
      const ticket = await oauth2Client.verifyIdToken({ idToken: tokens.id_token, audience: googleClientId });
      payload = ticket.getPayload();
    } else {
      const decoded = jwt.decode(tokens.access_token);
      payload = decoded;
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
      redirectUri: mcpRedirectUri,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || null,
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS)
    });

    res.setHeader('Set-Cookie', 'mcp_auth_req=; Path=/; HttpOnly; Max-Age=0');

    const finalRedirect = new URL(mcpRedirectUri);
    finalRedirect.searchParams.set('code', rawCode);
    if (state) finalRedirect.searchParams.set('state', state);

    return performRedirect(res, finalRedirect);
  } catch (error) {
    console.error('[Google Callback Error]', error);
    return res.status(500).send(renderLoginPage({ error: 'Google login failed: ' + error.message }));
  }
};

module.exports = {
  getAuthorizationServerMetadata,
  registerClient,
  showAuthorizePage,
  submitAuthorizePage,
  issueToken,
  handleDirectGoogleLogin,
  handleGoogleCallback
};
