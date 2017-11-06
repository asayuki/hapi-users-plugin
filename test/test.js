'use strict';

const Hapi = require('hapi');
const { hashPassword } = require('../lib/utils');
const { expect } = require('code');
const { experiment, test, before } = exports.lab = require('lab').script();
const Mongoose = require('mongoose');
const User = require('../lib/usermodel');

Mongoose.Promise = require('bluebird');
const db = Mongoose.connect(process.env.MONGO_URL + process.env.MONGO_DB, {
    useMongoClient: true
}, (error) => {
    if (error)
        throw error;
});

experiment('hapi-users-plugin', () => {

    let server;
    let testUserId;
    let testUserJwt;
    const secret = 'SuperDuperSecretYouCantFigureOut';
    const testUser = {
        username: 'testuser',
        password: 'testpassword',
        admin: true
    };

    before(() => {
        // Clear users in testdb
        User.remove({}).then();

        return new Promise((resolve) => {
            let user = new User();
            user.username = testUser.username;
            user.admin = testUser.admin;

            hashPassword(testUser.password, (error, hash) => {
                if (error) {
                    throw error;
                }

                user.password = hash;

                user.save().then((newUser) => {
                    testUserId = newUser._id;

                    server = new Hapi.Server();
                    server.connection();

                    const cache = server.cache({segment: 'sessions', expiresIn: 3 * 24 * 60 * 60 * 1000 });
                    server.app.cache = cache;

                    server.register([
                        require('hapi-auth-jwt2'),
                        {
                            register: require('../'),
                            options: {
                                url: '/api/users'
                            }
                        }
                     ], (error) => {
                        server.auth.strategy('jwt', 'jwt', {
                            key: secret,
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
                            },
                            verifyOptions: { algorithms: ['HS256'] }
                        });

                        resolve();
                    });
                });
            });
        });
    });

    test('Fail to login - wrong password', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users/authenticate',
            payload: {
                username: testUser.username,
                password: 'wrongpassword'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.message).to.equal('Incorrect username or password');
        });
    });

    test('Fail to login - wrong username', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users/authenticate',
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
            url: '/api/users/authenticate',
            payload: {
                username: testUser.username,
                password: testUser.password
            }
        }).then((response) => {

            console.log(response.result);

            expect(response.statusCode).to.equal(200);
            expect(response.result.token).to.be.a.string();
        });
    });
    /*
    test('', () => {

    });

    test('', () => {

    });

    test('', () => {

    });

    test('', () => {

    });

    test('', () => {

    });*/
});