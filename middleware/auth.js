const jwt = require('jsonwebtoken');
const User = require('../models/User');
const McpToken = require('../models/McpToken');

/**
 * Middleware for dashboard user JWT authentication
 */
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication token missing or invalid' });
    }

    const jwtSecret = process.env.JWT_SECRET || 'abm_strategy_secret_jwt_key_2026_dev';
    const decoded = jwt.verify(token, jwtSecret);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'User associated with token not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid or expired authentication token', error: error.message });
  }
};

/**
 * Middleware / helper for verifying MCP integration tokens
 */
const authenticateMcpToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'MCP Authorization header missing or malformed' });
    }

    const rawToken = authHeader.split(' ')[1];
    if (!rawToken.startsWith('mcp_live_')) {
      return res.status(401).json({ success: false, message: 'Invalid MCP Token format' });
    }

    const tokenHash = McpToken.hashToken(rawToken);
    const mcpTokenRecord = await McpToken.findOne({ tokenHash }).populate('userId');

    if (!mcpTokenRecord) {
      return res.status(401).json({ success: false, message: 'MCP Integration Token is invalid or revoked' });
    }

    if (mcpTokenRecord.expiresAt && new Date() > new Date(mcpTokenRecord.expiresAt)) {
      return res.status(401).json({ success: false, message: 'MCP Integration Token has expired' });
    }

    // Update lastUsedAt timestamp asynchronously
    mcpTokenRecord.lastUsedAt = new Date();
    await mcpTokenRecord.save().catch((err) => console.error('Failed to update token lastUsedAt:', err));

    req.mcpToken = mcpTokenRecord;
    req.user = mcpTokenRecord.userId;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'MCP Token validation failed', error: error.message });
  }
};

module.exports = {
  authenticateUser,
  authenticateMcpToken
};
