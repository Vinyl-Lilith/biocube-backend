const mongoose = require('mongoose');
const AuditSchema = new mongoose.Schema({
  deviceId: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  action: String,
  meta: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Audit', AuditSchema);
