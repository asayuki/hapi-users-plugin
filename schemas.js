'use strict';

const Joi = require('joi');

const createSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

module.exports = {
  createSchema,
  loginSchema
};