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
    if (error) {
        throw error;
    }
});

experiment('hapi-users-plugin', () => {
    let server;
    let testUserId;
    let testUserJwt;
    let testUserNewJwt;
    let createUserId;
    let createdUserJwt;
    let getUsersFromId;
    
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

            createUserId = response.result.userId;
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
    
    test('Fail to edit another user with no username -  as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: createUserId,
                username: ''
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to edit another user with no password - as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: createUserId,
                password: ''
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to edit username on user with usernames that is already taken - as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: createUserId,
                username: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });
    
    test('Edit another user - as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                id: createUserId,
                username: 'superdeath'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.userUpdated).to.be.true();
        });
    });

    test('Edit own user - as admin', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                password: 'newtestpassword'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.userUpdated).to.be.true();
            expect(response.result.newToken).to.be.true();

            testUserNewJwt = response.headers.authorization;
        });
    });

    test('Fail to edit own user - as admin with old token', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': testUserJwt
            },
            payload: {
                password: 'testpassword'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(401);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Login user - with default scope', () => {
        return server.inject({
            method: 'POST',
            url: '/api/users/authenticate',
            payload: {
                username: 'superdeath',
                password: 'nangijala'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.headers.authorization).to.be.a.string();
            createdUserJwt = response.headers.authorization;
        });
    });

    test('Fail to edit another user - as normal user', () => {
        return server.inject({
            method: 'PUT',
            url: '/api/users',
            headers: {
                'Authorization': createdUserJwt
            },
            payload: {
                id: testUserId,
                username: 'supertestuser'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(401);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to get user with wrong username', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users/death',
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Get user', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users/superdeath',
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.user.username).to.be.a.string();
            expect(response.result.user.password).to.be.undefined();
            expect(response.result.user.username).to.equal('superdeath');
        });
    });

    test('Fail to get users with from-param set to invalid id', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users?from=invalidid',
            headers: {
                'Authorization': createdUserJwt
            },
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Get users, exactly 3 of them', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users',
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.users).to.be.an.array();
            expect(response.result.users.length).to.equal(3);
            getUsersFromId = response.result.users[0]._id;
        });
    });

    test('Limit users to 1', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users?limit=1',
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.users).to.be.an.array();
            expect(response.result.users.length).to.equal(1);
        });
    });

    test('Get users from ID', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users?from=' + getUsersFromId,
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.users).to.be.an.array();
            expect(response.result.users.length).to.equal(2);
        });
    });

    test('Fail to remove own user - as admin', () => {
        return server.inject({
            method: 'DELETE',
            url: '/api/users',
            headers: {
                'Authorization': testUserNewJwt
            },
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to remove user - as normal user', () => {
        return server.inject({
            method: 'DELETE',
            url: '/api/users',
            headers: {
                'Authorization': createdUserJwt
            },
            payload: {
                id: testUserId
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(403);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Fail to remove user with invalid id - as admin', () => {
        return server.inject({
            method: 'DELETE',
            url: '/api/users',
            headers: {
                'Authorization': testUserNewJwt
            },
            payload: {
                id: 'randomid'
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(400);
            expect(response.result.error).to.be.a.string();
        });
    });

    test('Remove user - as admin', () => {
        return server.inject({
            method: 'DELETE',
            url: '/api/users',
            headers: {
                'Authorization': testUserNewJwt
            },
            payload: {
                id: createUserId
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.userRemoved).to.be.true();
        });
    });

    test('Get users, exactly 2 of them', () => {
        return server.inject({
            method: 'GET',
            url: '/api/users',
            headers: {
                'Authorization': createdUserJwt
            }
        }).then((response) => {
            expect(response.statusCode).to.equal(200);
            expect(response.result.users).to.be.an.array();
            expect(response.result.users.length).to.equal(2);
        });
    });

    /*
    test('', () => {

    });

    test('', () => {

    });
    */
});