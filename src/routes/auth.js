const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { registerSchema } = require('../utils/validate');

router.post('/register', async (req, res) => {
  const { error, value } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  const existing = await User.findOne({ username: value.username });
  if (existing) return res.status(409).json({ error: 'username-taken' });

  // Is this the first user in DB? If so make admin
  const total = await User.countDocuments();
  const roles = total === 0 ? ['admin'] : ['viewer'];

  const user = await User.createWithPassword(value.username, value.password, { displayName: value.displayName, roles });

  const token = jwt.sign({ sub: user._id, roles: user.roles, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, username: user.username, roles: user.roles } });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'invalid' });
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'invalid' });
  if (user.banned) return res.status(403).json({ error: 'banned' });
  const ok = await user.verifyPassword(password);
  if (!ok) return res.status(401).json({ error: 'invalid' });
  const token = jwt.sign({ sub: user._id, roles: user.roles, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, username: user.username, roles: user.roles, settings: user.settings } });
});

module.exports = router;
