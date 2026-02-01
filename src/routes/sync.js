const express = require('express');
const router = express.Router();
const Command = require('../models/Command');
const Audit = require('../models/AuditLog');
const { thresholdsSchema } = require('../utils/validate');

// simple auth for Pi device (optional enhancement later: HMAC)
const DEVICE_KEY = process.env.DEVICE_KEY || null;

router.post('/sync', async (req, res) => {
  const body = req.body || {};
  const deviceId = body.device_id || body.deviceId || 'unknown_device';

  // If Pi told us a last-executed command id, mark it executed
  if (body.last_executed_command_id) {
    try {
      const id = body.last_executed_command_id;
      const cmd = await Command.findById(id);
      if (cmd) {
        cmd.status = 'executed';
        cmd.executedAt = new Date();
        cmd.executedByPi = true;
        await cmd.save();
        await Audit.create({ username: 'raspi', action: 'command_executed', meta: { cmdId: id, deviceId } });
      }
    } catch (e) { console.error('mark-executed', e); }
  }

  // Server decides if there's a pending manual command for this device
  const pending = await Command.findOne({ deviceId, status: 'pending' }).sort({ createdAt: 1 });
  const out = {};
  if (pending) {
    // Return the payload plus the command id so the Pi can report execution back to server.
    const payload = pending.payload || {};
    payload._id = pending._id.toString();
    out.manual_command = payload;
    // mark as sent (but still pending until Pi ack)
    pending.status = 'sent';
    pending.attempts = (pending.attempts || 0) + 1;
    await pending.save();
    await Audit.create({ username: 'server', action: 'command_sent', meta: { cmdId: pending._id, deviceId } });
  }

  // server-side settings example: return settings (auto_mode + thresholds) if client requests
  // In real app, load per-device or per-account settings
  out.settings = { auto_mode: true, thresholds: {} };

  res.json(out);
});

module.exports = router;
