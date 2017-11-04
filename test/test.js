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
  password: 'testpassword'
};

experiment('hapi-users-plugin', () => {

  let userId;
  let testUserArtifact;

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
        user.save().then(() => {
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
                url: '/api/users'
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

  test('Fail to create user', () => {
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
      expect(response.statusCode).to.equal(201);
      expect(response.result.userCreated).to.be.true();
    });
  });
});

// Create user
// Fail to create user
// Edit user
// Fail to edit user
// Get user
// Fail to get user
// Delete user
// Fail to delete user
// Login
// Fail to login
// Logout
// Fail to logout (not logged in)