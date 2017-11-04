'use strict';

const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createSchema, loginSchema } = require('./schemas');
const { verifyCredentials, verifyUniqueUser } = require('./utils');
const { badImplementation } = require('boom');

exports.register = (server, options, next) => {

  let apiurl = options.url || '/api/users';

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
          strategies: ['session']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          }
        },
        handler: (request, response) => {
          return response({bajs: true});
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