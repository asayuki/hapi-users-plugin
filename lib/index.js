'use strict';
const Joi = require('joi');
Joi.objectId = require('joi-objectid')(Joi);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const redis = require('redis').createClient(process.env.REDIS);
const User = require('./usermodel');
const { verifyCredentials, verifyUniqueUser, createToken, createTokenObject, preUpdateUser, preDeleteUser, hashPassword } = require('./utils');
const { badImplementation, unauthorized, badRequest } = require('boom');

exports.register = (server, options, next) => {
    /**
     * Register auth-jwt and setup
     */

    const validateFunc = (decoded, request, callback) => {
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

            if (session.iat !== decoded.iat) {
                return callback(unauthorized(), false);
            }
            
            return callback(null, true);
        });
    };

    server.auth.strategy('jwt', 'jwt', {
        key: process.env.TOKEN_SECRET,
        validateFunc: options.validateFunc || validateFunc,
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

    const createUserSchema = Joi.object().keys({
        username: Joi.string().required(),
        password: Joi.string().required(),
        admin: Joi.boolean().default(false)
    });

    const updateUserSchema = Joi.object().keys({
        id: Joi.objectId(),
        username: Joi.string(),
        password: Joi.string(),
        admin: Joi.boolean()
    });

    const deleteUserSchema = Joi.object().keys({
        id: Joi.objectId().required()
    });

    const getUsersSchema = Joi.object().keys({
        from: Joi.objectId(),
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
                    let userdata = request.pre.user;
                    userdata.iat = Date.now();

                    redis.set(request.pre.user._id.toString(), createTokenObject(userdata));
                    let token = createToken(userdata);

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
        {
            method: 'POST',
            path: apiurl,
            config: {
                validate: {
                    headers: AuthorizationSchema,
                    payload: createUserSchema
                },
                pre: [{
                    method: verifyUniqueUser
                }],
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                },
                handler: (request, response) => {
                    let payload = request.payload;
                    hashPassword(payload.password, (error, passwordHash) => {
                        if (error) {
                            return response(badImplementation('Could not hash password'));
                        }

                        payload.password = passwordHash;

                        let user = new User();
                        Object.assign(user, payload);

                        user.save().then((newUser) => {
                            return response({
                                userCreated: true,
                                userId: newUser._id.toString()
                            }).code(201);
                        }, (error) => {
                            return response(badImplementation(error));
                        });
                    });
                }
            }
        },


        // Update user
        {
            method: 'PUT',
            path: apiurl,
            config: {
                validate: {
                    headers: AuthorizationSchema,
                    payload: updateUserSchema
                },
                pre: [{
                    method: preUpdateUser
                }],
                auth: {
                    strategy: 'jwt'
                },
                handler: (request, response) => {
                    let payload = request.payload;
                    let userId = payload.id || request.auth.credentials.id;
                    delete payload.id;

                    function passwordUpdate () {
                        return new Promise((resolve, reject) => {
                            if (payload.password) {
                                hashPassword(payload.password, (error, passwordHash) => {
                                    if (error) {
                                        return reject(badImplementation('Something went wrong when hashing password'));
                                    }

                                    payload.password = passwordHash;
                                    return resolve(true);
                                });
                            } else {
                                return resolve(true);
                            }
                        });
                    }

                    function usernameUpdate () {
                        return new Promise((resolve, reject) => {
                            if (payload.username) {
                                const query = User.findOne({username: payload.username});
                                query.exec().then((user) => {
                                    if (user) {
                                        return reject(badRequest('Username taken.'));
                                    }
                                    return resolve(true);
                                }, (error) => {
                                    return reject(badImplementation('Something went wrong when controlling if username was unique'));
                                });
                            } else {
                                return resolve(true);
                            }
                        });
                    }

                    passwordUpdate().then(usernameUpdate).then(() => {
                        User.findByIdAndUpdate({
                            _id: userId
                        }, {
                            $set: payload
                        }, {new: true}).then((updatedUser) => {

                            redis.del(userId, (error) => {
                                if (error) {
                                    return response(badImplementation('Couldnt remove userid from redis'));
                                }

                                if (userId === request.auth.credentials.id) {
                                    let userdata = updatedUser;
                                    userdata.iat = Date.now();
                                    redis.set(request.auth.credentials.id.toString(), createTokenObject(userdata));
                                    let token = createToken(userdata);

                                    return response({
                                        userUpdated: true,
                                        newToken: true
                                    }).header('Authorization', token).code(200);
                                } else {
                                    return response({
                                        userUpdated: true
                                    }).code(200);
                                }
                            });
                        }).catch((error) => {
                            return response(badImplementation(error));
                        });
                    }).catch((error) => {
                        return response(error);
                    });
                }
            }
        },

        // Delete user
        {
            method: 'DELETE',
            path: apiurl,
            config: {
                validate: {
                    headers: AuthorizationSchema,
                    payload: deleteUserSchema
                },
                pre: [{
                    method: preDeleteUser
                }],
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                },
                handler: (request, response) => {
                    User.remove({_id: request.payload.id}).then(() => {
                        return response({
                            userRemoved: true
                        }).code(200);
                    }).catch((error) => {
                        return response(badImplementation(error));
                    });
                }
            }
        },

        // Get user
        {
            method: 'GET',
            path: apiurl + '/{username}',
            config: {
                validate: {
                    headers: AuthorizationSchema
                },
                auth: {
                    strategy: 'jwt'
                },
                handler: (request, response) => {
                    User.findOne({username: request.params.username}).select('-password -__v').exec().then((user) => {
                        if (!user) {
                            return response(badRequest('No user found.'));
                        }

                        return response({user: user}).code(200);
                    }).catch((error) => {
                        return response(badImplementation(error));
                    });
                }
            }
        },

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
                    strategy: 'jwt'
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
                            return response(badRequest('Could not fetch users.'));
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