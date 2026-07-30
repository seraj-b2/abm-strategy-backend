const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    googleId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    googleSub: {
      type: String,
      sparse: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    name: {
      type: String,
      required: true
    },
    givenName: {
      type: String,
      default: ''
    },
    familyName: {
      type: String,
      default: ''
    },
    picture: {
      type: String,
      default: ''
    },
    role: {
      type: String,
      enum: ['user', 'admin', 'creator'],
      default: 'user'
    },
    lastLoginAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

// Method to return clean public user JSON without sensitive internals
userSchema.methods.toPublicJSON = function () {
  return {
    id: this._id,
    googleId: this.googleId,
    email: this.email,
    name: this.name,
    givenName: this.givenName,
    familyName: this.familyName,
    picture: this.picture,
    role: this.role,
    createdAt: this.createdAt,
    lastLoginAt: this.lastLoginAt
  };
};

module.exports = mongoose.model('User', userSchema);
