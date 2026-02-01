const mongoose = require('mongoose');
const CommandSchema = new mongoose.Schema({
  deviceId: String,
  payload: mongoose.Schema.Types.Mixed,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['pending','sent','executed','failed'], default: 'pending' },
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  executedAt: Date,
  executedByPi: Boolean
});
module.exports = mongoose.model('Command', CommandSchema);
