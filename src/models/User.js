const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  displayName: { type: String },
  passwordHash: { type: String, required: true },
  roles: { type: [String], default: ['viewer'] },
  banned: { type: Boolean, default: false },
  settings: {
    theme: { type: String, default: 'dark' },
    notifications: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now }
});

UserSchema.methods.verifyPassword = function (password) {
  return bcrypt.compare(password, this.passwordHash);
};

UserSchema.statics.createWithPassword = async function (username, password, extra = {}) {
  const saltRounds = 12;
  const hash = await bcrypt.hash(password, saltRounds);
  return this.create({ username, passwordHash: hash, ...extra });
};

module.exports = mongoose.model('User', UserSchema);
