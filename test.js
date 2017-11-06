'use strict';

const Hapi = require('hapi');
const hapiusersplugins = require('../');
const { hashPassword } = require('../utils');
const { expect } = require('code');
const { experiment, test, before } = exports.lab = require('lab').script();
const Mongoose = require('mongoose');
let server;

Mongoose.Promise = require('bluebird');
const db = Mongoose.connect(process.env.MONGO_URL + process.env.MONGO_DB, {
  useMongoClient: true
}, (error) => {
  if (error)
    throw error;
});

// Usermodel
const User = require('../usermodel');
const testUser = {
  username: 'testuser',
  password: 'testpassword',
  scope: 'admin'
};

experiment('hapi-users-plugin', () => {

  let testUserId;
  let testUserArtifact;
  let createUserId;
  let createUserArtifact;

  before(() => {

    // Clear all users in collection before testing
    User.remove({}).then();
    return new Promise((resolve) => {
      let user = new User();
      user.username = testUser.username;
  
      hashPassword(testUser.password, (error, hash) => {
        if (error) {
          throw error;
        }
  
        user.password = hash;
        user.scope = testUser.scope;

        user.save().then((newUser) => {
          testUserId = newUser._id;

          server = new Hapi.Server();
          server.connection();
    
          server.register(require('hapi-auth-cookie'), (error) => {
            const cache = server.cache({segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
            server.app.cache = cache;
            
            server.auth.strategy('session', 'cookie', {
              password: 'jspwnv7hgyujutfr5UH786tyhgbvftrg',
              cookie: 'cookiename',
              redirectTo: '/',
              ttl: 2147483647,
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
    
            server.register([{
              register: require('../'),
              options: {
                url: '/api/users',
                scopes: ['admin', 'user']
              }
            }], (error) => {
              if (!error) {
                server.initialize()
                resolve();
              }
            });
          });
        });
      });
    });
  });

  test('Fail login with wrong password', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users/login',
      payload: {
        username: testUser.username,
        password: 'wrongpassword'
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
      expect(response.result.message).to.equal('Incorrect username or password');
    });
  });

  test('Fail login with wrong username', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users/login',
      payload: {
        username: 'wrongusername',
        password: testUser.password
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
      expect(response.result.message).to.equal('Incorrect username or password');
    });
  });

  test('Login user', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users/login',
      payload: {
        username: testUser.username,
        password: testUser.password
      }
    }).then((response) => {

      testUserArtifact = response.request.auth.artifacts.sid;

      expect(response.statusCode).to.equal(200);
      expect(response.result.loggedin).to.be.true();
    });
  });

  test('Fail to create user with no password', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        username: 'death',
        password: ''
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
      expect(response.result.error).to.be.string();
    });
  });

  test('Fail to create user with no username', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        username: '',
        password: 'nangijala'
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
      expect(response.result.error).to.be.string();
    });
  });

  test('Fail to create user with same username as another user', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        username: 'testuser',
        password: 'nangijala'
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
      expect(response.result.error).to.be.string();
    });
  });

  test('Create user with default scope', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        username: 'death',
        password: 'nangijala'
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      createUserId = response.result.userId;
      expect(response.statusCode).to.equal(201);
      expect(response.result.userCreated).to.be.true();
    });
  });

  test('Login with created user', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users/login',
      payload: {
        username: 'death',
        password: 'nangijala'
      }
    }).then((response) => {

      createUserArtifact = response.request.auth.artifacts.sid;

      expect(response.statusCode).to.equal(200);
      expect(response.result.loggedin).to.be.true();
    });
  });

  test('Fail to create user with user with user scope', () => {
    return server.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        username: 'simba',
        password: 'lionking'
      },
      credentials: {
        username: 'death',
        password: 'nangijala',
      },
      artifacts: {
        sid: createUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(403);
      expect(response.result.error).to.be.string();
    });
  });

  test('Fail to edit another user as admin', () => {
    return server.inject({
      method: 'PUT',
      url: '/api/users/' + createUserId,
      payload: {
        username: ''
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
    });
  });

  test('Edit another user as admin', () => {
    return server.inject({
      method: 'PUT',
      url: '/api/users/' + createUserId,
      payload: {
        username: 'deathgod'
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(200);
    });
  });

  test('Fail to edit own user', () => {
    return server.inject({
      method: 'PUT',
      url: '/api/users/',
      payload: {
        username: ''
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(400);
    });
  });

  test('Edit own user', () => {
    return server.inject({
      method: 'PUT',
      url: '/api/users/',
      payload: {
        username: 'testuserultra'
      },
      credentials: testUser,
      artifacts: {
        sid: testUserArtifact
      }
    }).then((response) => {
      expect(response.statusCode).to.equal(200);
    });
  });
});

// Edit user
// Fail to edit user
// Get user
// Fail to get user
// Delete user
// Fail to delete user
// Logout
// Fail to logout (not logged in)