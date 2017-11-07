'use strict';
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const redis = require('redis-connection')();
const User = require('./usermodel');
const { verifyCredentials, createToken, createTokenObject, hashPassword } = require('./utils');
const { badImplementation, unauthorized } = require('boom');

exports.register = (server, options, next) => {
    /**
     * Register auth-jwt and setup
     */
    server.auth.strategy('jwt', 'jwt', {
        key: process.env.TOKEN_SECRET,
        validateFunc: (decoded, request, callback) => {
            redis.get(decoded.id, (error, cached) => {
                if (error) {
                    return callback('Could not validate token', false);
                }

                let session;
                if (cached) {
                    try {
                        session = JSON.parse(cached);
                    } catch (e) {
                        return callback(badImplementation('Could not validate token'), false);
                    }
                } else {
                    return callback(unauthorized(), false);
                }
                
                return callback(null, true);
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

    const AuthorizationSchema = Joi.object({
        "authorization": Joi.string().required()
    }).options({ allowUnknown: true });

    const getUsersSchema = Joi.object({
        from: Joi.string(),
        limit: Joi.number()
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
                    redis.set(request.pre.user._id.toString(), createTokenObject(request.pre.user));
                    let token = createToken(request.pre.user);

                    return response({
                        loggedin: true
                    }).header('Authorization', token);
                }
            }
        },

        // Unauthenticate
        {
            method: ['GET', 'POST'],
            path: apiurl +  '/unauthenticate',
            config: {
                validate: {
                    headers: AuthorizationSchema
                },
                auth: {
                    strategy: 'jwt'
                },
                handler: (request, response) => {
                    redis.del(request.auth.credentials.id, (error) => {
                        if (error) {
                            return response(badImplementation('Something went wrong.'));
                        }

                        return response({
                            loggedout: true
                        }).code(200);
                    });
                }
            }
        },

        // Create user

        // Update user

        // Delete user

        // Get user

        // Get users (with search params)
        {
            method: 'GET',
            path: apiurl,
            config: {
                validate: {
                    headers: AuthorizationSchema,
                    query: getUsersSchema
                },
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                },
                handler: (request, response) => {

                    let query = {};

                    if (typeof request.query.from !== 'undefined') {
                        query._id = {
                            $gt: request.query.from
                        };
                    }

                    User.find(query)
                    .limit((request.query.limit ? parseInt(request.query.limit) : 20))
                    .select('-password -__v').exec().then((users) => {
                        return response({users: users}).code(200);
                    }).catch((error) => {
                        if (error) {
                            return response(badImplementation('Could not fetch users.'));
                        }
                    });
                },
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