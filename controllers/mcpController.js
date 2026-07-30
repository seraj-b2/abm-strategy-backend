const McpToken = require('../models/McpToken');

/**
 * POST /api/mcp/verify-token
 * Public endpoint for MCP servers to verify incoming user tokens
 */
const verifyToken = async (req, res) => {
  try {
    let rawToken = req.body.token;

    // Check authorization header if token body parameter is missing
    if (!rawToken && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      rawToken = req.headers.authorization.split(' ')[1];
    }

    if (!rawToken) {
      return res.status(400).json({
        valid: false,
        message: 'Token is required either in request body ({ token }) or Bearer header'
      });
    }

    if (!rawToken.startsWith('mcp_live_')) {
      return res.status(400).json({
        valid: false,
        message: 'Invalid token format. Must start with mcp_live_'
      });
    }

    const tokenHash = McpToken.hashToken(rawToken);
    const tokenRecord = await McpToken.findOne({ tokenHash }).populate('userId');

    if (!tokenRecord) {
      return res.status(401).json({
        valid: false,
        message: 'Token invalid or revoked'
      });
    }

    if (tokenRecord.expiresAt && new Date() > new Date(tokenRecord.expiresAt)) {
      return res.status(401).json({
        valid: false,
        message: 'Token has expired'
      });
    }

    // Update lastUsedAt timestamp
    tokenRecord.lastUsedAt = new Date();
    await tokenRecord.save().catch((err) => console.error('[MCP Token Warning] Failed to update lastUsedAt:', err.message));

    const user = tokenRecord.userId;

    return res.status(200).json({
      valid: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      },
      tokenInfo: {
        id: tokenRecord._id,
        name: tokenRecord.name,
        scopes: tokenRecord.scopes,
        createdAt: tokenRecord.createdAt
      }
    });
  } catch (error) {
    console.error('[MCP Token Verification Error]', error);
    return res.status(500).json({
      valid: false,
      message: 'Token verification service failure',
      error: error.message
    });
  }
};

module.exports = {
  verifyToken
};
