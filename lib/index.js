'use strict';

const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { badImplementation } = require('boom');
const User = require('./usermodel');
const { verifyCredentials, createToken } = require('./utils');

exports.register = (server, options, next) => {

    /**
     * Register auth-jwt and setup
     */
    const cache = server.cache({segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
    server.app.cache = cache;

    server.register([require('hapi-auth-jwt2')], (error) => {
        
    });

    server.auth.strategy('jwt', 'jwt', {
        key: process.env.TOKEN_SECRET,
        validateFunc: (request, session, callback) => {
            console.log(request);
            console.log('were validating');
            cache.get(session.id, (error, cached) => {
                console.log(cached);
              if (error) {
                  console.log(error);
                return callback(error, false);
              }
      
              if (!cached) {
                  console.log('unchached');
                return callback(null, false);
              }
              console.log('hello!');
              return callback(null, true, cached.account);
            });
        },
        verifyOptions: { algorithms: ['HS256'] }
    });

    /**
     * Create schemas
     */
    const authenticateSchema = Joi.object().keys({
        username: Joi.string().required(),
        password: Joi.string().required()
    });

    /**
     * Set api-url for plugin
     */
    let apiurl = options.url || '/api/users';

    /**
     * Plugin routes
     */
    server.route([
        // Authenticate
        {
            method: 'POST',
            path: apiurl + '/authenticate',
            config: {
                pre: [
                    {
                        method: verifyCredentials,
                        assign: 'user'
                    }
                ],
                validate: {
                    payload: authenticateSchema
                },
                handler: (request, response) => {
                    console.log(request.pre.user);
                    cache.set(request.pre.user._id, {
                        account: request.pre.user
                    }, null, (error) => {
                        console.log(error);
                        if (error) {
                            throw error;
                        }

                        return response({
                            token: createToken(request.pre.user)
                        }).code(201);
                    });
                }
            }
        },
        // Unauthenticate

        // Create user

        // Update user

        // Delete user

        // Get user

        // Get users (with search params)
        {
            method: 'GET',
            path: apiurl,
            config: {
                handler: (request, response) => {
                    return response({});
                },
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
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