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

                    server.register([
                        require('hapi-auth-jwt2'),
                        {
                            register: require('../'),
                            options: {
                                url: '/api/users'
                            }
                        }
                     ], (error) => {
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
            expect(response.statusCode).to.equal(200);
            expect(response.headers.authorization).to.be.a.string();
            testUserJwt = response.headers.authorization;
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