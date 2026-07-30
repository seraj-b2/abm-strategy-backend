const McpToken = require('../models/McpToken');

/**
 * POST /api/tokens/generate
 * Generate a new MCP integration token for the authenticated user
 */
const generateToken = async (req, res) => {
  try {
    const { name = 'MCP Integration Token', scopes = ['abm:read', 'abm:write', 'mcp:execute'], expiresInDays } = req.body;

    const { rawToken, prefix } = McpToken.generateRawToken();
    const tokenHash = McpToken.hashToken(rawToken);

    let expiresAt = null;
    if (expiresInDays && Number(expiresInDays) > 0) {
      expiresAt = new Date(Date.now() + Number(expiresInDays) * 24 * 60 * 60 * 1000);
    }

    const newMcpToken = await McpToken.create({
      userId: req.user._id,
      name,
      tokenHash,
      tokenPrefix: prefix,
      scopes,
      expiresAt
    });

    return res.status(201).json({
      success: true,
      message: 'MCP Integration token generated successfully. Store this token securely as it will not be shown again.',
      token: rawToken, // Returned ONCE to client
      tokenInfo: {
        id: newMcpToken._id,
        name: newMcpToken.name,
        prefix: newMcpToken.tokenPrefix,
        scopes: newMcpToken.scopes,
        expiresAt: newMcpToken.expiresAt,
        createdAt: newMcpToken.createdAt
      }
    });
  } catch (error) {
    console.error('[Generate Token Error]', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to generate MCP integration token',
      error: error.message
    });
  }
};

/**
 * GET /api/tokens
 * List active MCP tokens for the authenticated user
 */
const listTokens = async (req, res) => {
  try {
    const tokens = await McpToken.find({ userId: req.user._id })
      .select('name tokenPrefix scopes lastUsedAt expiresAt createdAt')
      .sort({ createdAt: -1 });

    const formattedTokens = tokens.map((t) => ({
      id: t._id,
      name: t.name,
      prefix: t.tokenPrefix,
      scopes: t.scopes,
      lastUsedAt: t.lastUsedAt,
      expiresAt: t.expiresAt,
      createdAt: t.createdAt
    }));

    return res.status(200).json({
      success: true,
      count: formattedTokens.length,
      tokens: formattedTokens
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve MCP tokens',
      error: error.message
    });
  }
};

/**
 * DELETE /api/tokens/:id
 * Revoke/delete an MCP token
 */
const revokeToken = async (req, res) => {
  try {
    const { id } = req.params;

    const tokenRecord = await McpToken.findOneAndDelete({
      _id: id,
      userId: req.user._id
    });

    if (!tokenRecord) {
      return res.status(404).json({
        success: false,
        message: 'Token not found or does not belong to user'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'MCP token revoked successfully',
      revokedTokenId: id
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Failed to revoke token',
      error: error.message
    });
  }
};

module.exports = {
  generateToken,
  listTokens,
  revokeToken
};
