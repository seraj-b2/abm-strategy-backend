const mongoose = require('mongoose');
const crypto = require('crypto');

const oauthClientSchema = new mongoose.Schema(
  {
    clientId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    clientSecretHash: {
      type: String,
      required: true
    },
    clientName: {
      type: String,
      default: 'MCP Client'
    },
    redirectUris: {
      type: [String],
      required: true
    }
  },
  {
    timestamps: true
  }
);

oauthClientSchema.statics.hashSecret = function (rawSecret) {
  return crypto.createHash('sha256').update(rawSecret).digest('hex');
};

oauthClientSchema.statics.generateCredentials = function () {
  const clientId = `mcp_client_${crypto.randomBytes(16).toString('hex')}`;
  const clientSecret = `mcp_secret_${crypto.randomBytes(24).toString('hex')}`;
  return { clientId, clientSecret };
};

module.exports = mongoose.model('OAuthClient', oauthClientSchema);
