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
    
    test('Fail to create user - no password', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                username: 'death',
                password: ''
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to create user - no username', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                username: '',
                password: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to create user - username is taken', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                username: 'testuser',
                password: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Create user - with default scope', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                username: 'death',
                password: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(201);
            expect(response.result.userCreated).to.be.true();
            expect(response.result.userId).to.be.a.string();

            testUserId = response.result.userId;
        });
    });

    test('Create user - with admin scope', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                username: 'nangijala',
                password: 'death',
                admin: true
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(201);
            expect(response.result.userCreated).to.be.true();
        });
    });
    
    test('Fail to edit another user as admin - No username', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: testUserId,
                username: ''
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to edit another user as admin - No password', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: testUserId,
                password: ''
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to edit another user as admin - Username allready taken', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: testUserId,
                username: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });
    
    test('Edit another user as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: testUserId,
                username: 'superdeath'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.userUpdated).to.be.true();
        });
    });

    /*test('', () => {

    });

    test('', () => {

    });*/
});