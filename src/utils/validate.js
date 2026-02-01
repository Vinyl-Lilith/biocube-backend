const Joi = require('joi');

const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(32).required(),
  password: Joi.string().min(8).required(),
  displayName: Joi.string().max(64).allow('', null)
});

const thresholdsSchema = Joi.object({
  temp: Joi.number().min(5).max(40),
  soil: Joi.number().min(0).max(1023),
  n: Joi.number().min(0).max(1000),
  p: Joi.number().min(0).max(1000),
  k: Joi.number().min(0).max(1000)
});

module.exports = { registerSchema, thresholdsSchema };
