const mongoose = require('mongoose');
const crypto = require('crypto');

const mcpTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    name: {
      type: String,
      required: true,
      trim: true,
      default: 'MCP Integration Token'
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    tokenPrefix: {
      type: String,
      required: true
    },
    scopes: {
      type: [String],
      default: ['abm:read', 'abm:write', 'mcp:execute']
    },
    lastUsedAt: {
      type: Date,
      default: null
    },
    expiresAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

// Helper static method to hash raw token
mcpTokenSchema.statics.hashToken = function (rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
};

// Helper static method to generate raw token & prefix
mcpTokenSchema.statics.generateRawToken = function () {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const rawToken = `mcp_live_${randomBytes}`;
  const prefix = `${rawToken.substring(0, 14)}...${rawToken.substring(rawToken.length - 4)}`;
  return { rawToken, prefix };
};

module.exports = mongoose.model('McpToken', mcpTokenSchema);
