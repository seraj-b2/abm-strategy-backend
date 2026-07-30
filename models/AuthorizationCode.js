const mongoose = require('mongoose');
const crypto = require('crypto');

const authorizationCodeSchema = new mongoose.Schema(
  {
    codeHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    clientId: {
      type: String,
      required: true,
      index: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    redirectUri: {
      type: String,
      required: true
    },
    codeChallenge: {
      type: String,
      default: null
    },
    codeChallengeMethod: {
      type: String,
      default: null
    },
    used: {
      type: Boolean,
      default: false
    },
    expiresAt: {
      type: Date,
      required: true
    }
  },
  {
    timestamps: true
  }
);

authorizationCodeSchema.statics.hashCode = function (rawCode) {
  return crypto.createHash('sha256').update(rawCode).digest('hex');
};

authorizationCodeSchema.statics.generateRawCode = function () {
  return crypto.randomBytes(32).toString('hex');
};

module.exports = mongoose.model('AuthorizationCode', authorizationCodeSchema);
