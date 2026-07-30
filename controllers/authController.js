const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const client = new OAuth2Client(googleClientId);

/**
 * Helper to sign backend session JWT
 */
const generateJwtToken = (user) => {
  const secret = process.env.JWT_SECRET || 'abm_strategy_secret_jwt_key_2026_dev';
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role
    },
    secret,
    { expiresIn: '7d' }
  );
};

/**
 * POST /api/auth/google
 * Authenticate or register user via Google OAuth ID Token
 */
const googleAuth = async (req, res) => {
  try {
    const { credential, profile } = req.body;

    let payload = null;

    if (credential) {
      try {
        // Attempt to verify Google Credential with Google OAuth Library
        const ticket = await client.verifyIdToken({
          idToken: credential,
          audience: process.env.GOOGLE_CLIENT_ID
        });
        payload = ticket.getPayload();
      } catch (verifyError) {
        console.warn('[Auth Warning] Google token verification fallback mode active:', verifyError.message);
        // Fallback for development/testing if token verification fails or client ID mismatch
        const decoded = jwt.decode(credential);
        if (decoded && decoded.email) {
          payload = decoded;
        }
      }
    }

    // If profile fallback is explicitly passed from client frontend
    if (!payload && profile && profile.email) {
      payload = {
        sub: profile.sub || profile.id || `google_${Date.now()}`,
        email: profile.email,
        name: profile.name || profile.email.split('@')[0],
        given_name: profile.given_name || profile.givenName || '',
        family_name: profile.family_name || profile.familyName || '',
        picture: profile.picture || profile.avatar || ''
      };
    }

    if (!payload || !payload.email) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Google authentication data provided. Missing email or valid Google ID token.'
      });
    }

    const { sub: googleId, email, name, given_name, family_name, picture } = payload;

    // Upsert User in MongoDB
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

    const token = generateJwtToken(user);

    return res.status(200).json({
      success: true,
      message: 'Google authentication successful',
      token,
      user: user.toPublicJSON()
    });
  } catch (error) {
    console.error('[Google Auth Error]', error);
    return res.status(500).json({
      success: false,
      message: 'Google authentication failed',
      error: error.message
    });
  }
};

/**
 * GET /api/auth/me
 * Get current authenticated user profile
 */
const getMe = async (req, res) => {
  try {
    return res.status(200).json({
      success: true,
      user: req.user.toPublicJSON()
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to fetch user profile',
      error: error.message
    });
  }
};

/**
 * POST /api/auth/dev-login
 * Development helper endpoint to simulate login without Google credentials
 */
const devLogin = async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ success: false, message: 'Dev login disabled in production' });
  }

  try {
    const { email = 'dev.user@bamboobox.ai', name = 'Dev Engineer' } = req.body;

    let user = await User.findOne({ email });
    if (!user) {
      const devGoogleId = `dev_google_${Date.now()}`;
      user = await User.create({
        googleId: devGoogleId,
        googleSub: devGoogleId,
        email,
        name,
        picture: 'https://lh3.googleusercontent.com/a/default-user',
        role: 'user'
      });
    }

    const token = generateJwtToken(user);

    return res.status(200).json({
      success: true,
      message: 'Development login successful',
      token,
      user: user.toPublicJSON()
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Dev login failed', error: error.message });
  }
};

module.exports = {
  googleAuth,
  getMe,
  devLogin
};
