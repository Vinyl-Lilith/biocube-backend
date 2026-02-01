const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Audit = require('../models/AuditLog');
const requireRole = require('../middleware/requireRole');

router.use(requireRole('admin'));

router.get('/users', async (req, res) => {
  const users = await User.find({}, 'username displayName roles banned settings createdAt').lean();
  res.json(users);
});

router.post('/users/:id/promote', async (req, res) => {
  const u = await User.findById(req.params.id);
  if (!u) return res.status(404).end();
  if (!u.roles.includes('admin')) u.roles.push('admin');
  await u.save();
  await Audit.create({ userId: req.user.id, username: req.user.username, action: 'promote_user', meta: { targetId: u._id } });
  res.json({ ok: true });
});

router.post('/users/:id/ban', async (req,res) => {
  const u = await User.findById(req.params.id);
  if(!u) return res.status(404).end();
  u.banned = true; await u.save();
  await Audit.create({userId: req.user.id, username:req.user.username, action:'ban_user', meta:{targetId:u._id}});
  res.json({ok:true});
});

router.get('/audit', async (req,res)=>{
  const q = await Audit.find({}).sort({createdAt:-1}).limit(500).lean();
  res.json(q);
});

module.exports = router;
