'use strict';

const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Mongoose = require('mongoose');
const Schema = Mongoose.Schema;
const User = require('./usermodel');
//const { createSchema, loginSchema } = require('./schemas');
const { verifyCredentials, verifyUniqueUser, hashPassword } = require('./utils');
const { badImplementation } = require('boom');

/**
 * Export plugin
 */
exports.register = (server, options, next) => {

  /**
   * Set url for plugin
   */
  let apiurl = options.url || '/api/users';

  /**
   * Set scopes
   */
  let scopes = ['user'];
  let adminScope = ['user'];

  if (options.scopes && (Array.isArray(options.scopes) && options.scopes.length > 1)) {
    scopes = options.scopes;
    adminScope = options.scopes[0];
  }

  /**
   * Create schemas
   */
  const createSchema = Joi.object().keys({
    username: Joi.string().required(),
    password: Joi.string().required(),
    scope: Joi.array().items(Joi.string().valid(scopes)).default(['user']),
    options: Joi.object().unknown()
  });
  
  const loginSchema = Joi.object().keys({
    username: Joi.string().required(),
    password: Joi.string().required()
  });
  

  /**
   * Plugin routes
   */
  server.route([

    /**
     * Login
     * @param {Object} request.payload
     * @param {String} request.payload.username
     * @param {String} request.payload.password
     * @returns {Object} response
     * @returns {Boolean} response.loggedin
     * @returns {String=} response.error
     */
    {
      method: 'POST',
      path: apiurl + '/login',
      config: {
        validate: {
          payload: loginSchema
        },
        pre: [
          {
            method: verifyCredentials,
            assign: 'user'
          }
        ],
        auth: {
          mode: 'try',
          strategies: ['session']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          }
        },
        handler: (request, response) => {
          let cache = request.server.app.cache;
          let cacheId = request.pre.user.username.toLowerCase() + '' + request.pre.user._id;

          cache.set(cacheId, {
            account: request.pre.user
          }, null, (error) => {
            if (error) {
              return response(badImplementation('Could not login.'));
            }

            request.cookieAuth.set({
              sid: cacheId
            });

            return response({
              loggedin: true
            }).code(200);
          });
        }
      }
    },

    /**
     * Create user
     * @param {String} request.payload.username
     * @param {String} request.payload.password
     * @returns {Object} response
     * @returns {Boolean} response.userCreated
     * @returns {String} response.userId
     * @returns {String=} response.error
     */
    {
      method: 'POST',
      path: apiurl,
      config: {
        validate: {
          payload: createSchema
        },
        pre: [
          {
            method: verifyUniqueUser
          }
        ],
        auth: {
          mode: 'required',
          strategies: ['session'],
          scope: adminScope
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          }
        },
        handler: (request, response) => {
          let payload = request.payload;
          hashPassword(payload.password, (error, hash) => {
            if (error) {
              return response(badImplementation('Something went wrong.'))
            }

            payload.password = hash;
            
            let user = new User();
            Object.assign(user, payload);

            user.save().then((newUser) => {
              return response({
                userCreated: true,
                userId: newUser._id
              }).code(201);
            });
          }, (error) => {
            return response(badImplementation('Could not create user.'))
          });
        }
      }
    }
  ]);

  next();

};

exports.register.attributes = {
  name: 'hapi-users-plugin',
  version: '2.0.0',
  description: 'Users plugin for Hapi.JS',
  main: 'index.js',
  author: 'neme <neme@whispered.se>',
  license: 'MIT'
};