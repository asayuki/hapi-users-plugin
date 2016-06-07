'use strict';
const
  Joi = require('joi'),
  bcrypt = require('bcrypt'),
  jwt = require('jsonwebtoken'),
  extend = require('util')._extend;

exports.register = (server, options, next) => {

  const cache = server.cache({
    cache: options.cache_name,
    expiresIn: (typeof options.expire !== 'undefined') ? options.expire : 2147483647
  });

  // Bind cache to application
  server.app.cache = cache;
  server.bind({
    cache: server.app.cache
  });

  var create_payload = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().required()
  });

  var update_payload = Joi.object({
    id: Joi.string(),
    username: Joi.string(),
    password: Joi.string()
  });

  if (typeof options.create_extra_fields !== 'undefined') {
    create_payload = create_payload.keys(options.create_extra_fields);
  }
  if (typeof options.update_extra_fields !== 'undefined') {
    update_payload = update_payload.keys(options.update_extra_fields);
  }


  // Expose cache for other plugins
  server.expose('getCache', () => {
    return cache;
  });

  if (typeof options.session !== 'undefined' && options.session === true) {
    // Setup session & cookie strategy
    server.auth.strategy('session', 'cookie', {
      password: options.session_private_key,
      cookie: options.cookie_name,
      redirectTo: '/',
      ttl: (typeof options.expire !== 'undefined') ? options.expire : 2147483647,
      isSecure: false,
      clearInvalid: true,
      keepAlive: true,
      validateFunc: (request, session, callback) => {
        cache.get(session.sid, (error, cached) => {
          if (error) {
            return callback(error, false);
          }

          if (!cached) {
            return callback(null, false);
          }

          return callback(null, true, cached.account);
        });
      }
    });
  }

  if (typeof options.token !== 'undefined' && options.token === true) {
    // Setup token strategy
    server.auth.strategy('token', 'jwt', {
      key: options.session_private_key,
      validateFunc: (request, token, callback) => {
        let
          db = request.server.plugins['hapi-mongodb'].db,
          ObjectID = request.server.plugins['hapi-mongodb'].ObjectID;

        db.collection(options.collection).findOne({_id: new ObjectID(token._id)}, {password: 0}, (error, user) => {
          if (error) {
            return callback(error, false, {});
          }

          if (user === null) {
            return callback(null, false, {});
          }

          return callback(null, true, user);
        });
      }
    });
  }

  server.route([
    {
      method: 'POST',
      path: '/api/users/login',
      config: {
        tags: ['api', 'users'],
        validate: {
          payload: {
            username: Joi.string().required(),
            password: Joi.string().required(),
            token: Joi.boolean().valid(false, true)
          }
        },
        auth: {
          mode: 'try',
          strategies: ['session', 'token']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-auth-jwt': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (!request.auth.isAuthenticated) {
            let
              db = request.server.plugins['hapi-mongodb'].db,
              payload = request.payload;

            db.collection(options.collection).findOne({username: payload.username.toLowerCase()}, (error, user) => {
              if (error) {
                return response({
                  error: 'Database error.'
                }).code(500);
              }

              if (user === null) {
                return response({
                  error: 'Username or Password is incorrect'
                }).code(401);
              }

              bcrypt.compare(payload.password, user.password, (error, res) => {
                if (error && !res) {
                  return response({
                    error: 'Username or Password is incorrect'
                  }).code(401);
                }

                delete user.password;

                if (typeof payload.token !== 'undefined' && payload.token) {
                  let token = jwt.sign({
                    _id: user._id
                  }, process.env.SESSION_PRIVATE_KEY, {
                    expiresIn: (typeof options.expire !== 'undefined') ? options.expire : 2147483647
                  });

                  return response({
                    token: token
                  }).code(200);
                } else {
                  let usersid = user.username.toLowerCase() + '' + user._id;

                  cache.set(usersid, {
                    account: user
                  }, 0, (error) => {
                    if (error) {
                      return response({
                        error: 'Session failed.'
                      }).code(500);
                    }

                    request.cookieAuth.set({
                      sid: usersid
                    });

                    return response({
                      loggedIn: true
                    }).code(200);
                  });
                }
              });
            });
          } else {
            return response({
              error: 'Already authenticated.'
            }).code(401);
          }
        }
      }
    },
    {
      method: 'GET',
      path: '/api/users/logout',
      config: {
        tags: ['api', 'session'],
        auth: {
          mode: 'try',
          strategies: ['session']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (request.auth.isAuthenticated) {
            cache.drop(request.auth.artifacts.sid, (error) => {
              if (error) {
                return response({
                  error: 'Session failed.'
                }).code(500);
              }

              request.cookieAuth.clear();

              return response({
                loggedOut: true
              }).code(200);
            });
          } else {
            return response({
              error: 'Not authenticated.'
            }).code(401);
          }
        }
      }
    },
    {
      method: 'POST',
      path: '/api/users',
      config: {
        tags: ['api', 'users'],
        validate: {
          headers: Joi.object({
            Authorization: Joi.string()
          }).unknown(),
          payload: create_payload
        },
        auth: {
          mode: 'try',
          strategies: ['session', 'token']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-auth-jwt': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (request.auth.isAuthenticated) {
            let
              db = request.server.plugins['hapi-mongodb'].db,
              users = db.collection(options.collection),
              payload = request.payload;

            users.findOne({
              username: payload.username.toLowerCase()
            }, {password: 0}, (error, user) => {
              if (error) {
                return response({
                  error: 'Database error.',
                  userCreated: false
                }).code(500);
              }

              if (user !== null) {
                return response({
                  error: 'Username already exists.',
                  userCreated: false
                }).code(409);
              }

              bcrypt.hash(payload.password, 10, (error, hash) => {
                if (error) {
                  return response({
                    error: 'Could not create user.',
                    userCreated: false
                  }).code(500);
                }

                payload.password = hash;

                users.insert(payload, (error) => {
                  if (error) {
                    return response({
                      error: 'Could not create user.',
                      userCreated: false
                    }).code(500);
                  }

                  return response({
                    userCreated: true
                  }).code(200);
                });
              });
            });
          } else {
            return response({
              error: 'Not authenticated'
            }).code(401);
          }
        }
      }
    },
    {
      method: 'GET',
      path: '/api/users/{username}',
      config: {
        tags: ['api', 'users'],
        validate: {
          headers: Joi.object({
            Authorization: Joi.string()
          }).unknown(),
          params: {
            username: Joi.string().required()
          }
        },
        auth: {
          mode: 'try',
          strategies: ['session', 'token']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-auth-jwt': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (request.auth.isAuthenticated) {
            let
              db = request.server.plugins['hapi-mongodb'].db,
              users = db.collection(options.collection);

            users.findOne({username: request.params.username.toLowerCase()}, {password: 0}, (error, user) => {
              if (error) {
                return response({
                  error: 'Database error.',
                  userCreated: false
                }).code(500);
              }

              if (user === null) {
                return response({
                  error: 'User does not exist.'
                }).code(404);
              }

              return response({user: user}).code(200);
            });
          } else {
            return response({
              error: 'Not authenticated'
            }).code(401);
          }
        }
      }
    },
    {
      method: 'PUT',
      path: '/api/users',
      config: {
        tags: ['api', 'users'],
        validate: {
          headers: Joi.object({
            Authorization: Joi.string()
          }).unknown(),
          payload: update_payload
        },
        auth: {
          mode: 'try',
          strategies: ['session', 'token']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-auth-jwt': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (request.auth.isAuthenticated) {
            let
              db = request.server.plugins['hapi-mongodb'].db,
              ObjectID = request.server.plugins['hapi-mongodb'].ObjectID,
              users = db.collection(options.collection),
              payload = request.payload,
              userId = (typeof payload.id !== 'undefined') ? payload.id : request.auth.credentials._id;

            delete payload.id;

            if (typeof payload.password !== 'undefined') {
              payload.password = bcrypt.hashSync(payload.password, 10);
            }

            users.findOne({
              _id: new ObjectID(userId)
            }, {password: 0}, (error, user) => {
              if (error) {
                return response({
                  error: 'Database error.',
                  userCreated: false
                }).code(500);
              }

              if (user === null) {
                return response({
                  error: 'User does not exist.'
                }).code(404);
              }

              payload = extend(user, payload);

              users.update({_id: new ObjectID(userId)}, {$set: payload}, (error) => {
                if (error) {
                  return response({
                    error: 'Database error.',
                    userCreated: false
                  }).code(500);
                }

                delete payload.password;

                return response({
                  user: payload
                }).code(200);
              });
            });
          } else {
            return response({
              error: 'Not authenticated'
            }).code(401);
          }
        }
      }
    },
    {
      method: 'DELETE',
      path: '/api/users',
      config: {
        tags: ['api', 'users'],
        validate: {
          headers: Joi.object({
            Authorization: Joi.string()
          }).unknown(),
          payload: Joi.object({
            id: Joi.string().required()
          })
        },
        auth: {
          mode: 'try',
          strategies: ['session', 'token']
        },
        plugins: {
          'hapi-auth-cookie': {
            redirectTo: false
          },
          'hapi-auth-jwt': {
            redirectTo: false
          },
          'hapi-swagger': {
            payloadType: 'form'
          }
        },
        handler: (request, response) => {
          if (request.auth.isAuthenticated) {
            let
              db = request.server.plugins['hapi-mongodb'].db,
              ObjectID = request.server.plugins['hapi-mongodb'].ObjectID,
              users = db.collection(options.collection);

            users.findOne({_id: new ObjectID(request.payload.id)}, (error, user) => {
              if (error) {
                return response({
                  error: 'Database error.',
                  userCreated: false
                }).code(500);
              }

              if (user === null) {
                return response({
                  error: 'User does not exist.'
                }).code(404);
              }

              users.remove({_id: new ObjectID(request.payload.id)}, (error) => {
                if (error) {
                  return response({
                    error: 'Database error.',
                    userCreated: false
                  }).code(500);
                }

                return response({
                  removed: true
                }).code(200);
              });
            });
          } else {
            return response({
              error: 'Not authenticated'
            }).code(401);
          }
        }
      }
    }
  ]);

  next();
};

exports.register.attributes = {
  'name': 'hapi-users-plugin',
  'version': '1.0.2',
  'description': 'Users plugin for Hapi.JS',
  'main': 'index.js',
  'author': 'neme <neme@whispered.se>',
  'license': 'MIT'
};
