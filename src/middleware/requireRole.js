module.exports = function requireRole(role) {
  return function (req, res, next) {
    const roles = (req.user && req.user.roles) || [];
    if (roles.includes(role)) return next();
    return res.status(403).json({ error: 'forbidden' });
  };
};
