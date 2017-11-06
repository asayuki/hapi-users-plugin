'use strict';

const { badRequest, badImplementation, unauthorized } = require('boom');
const Bcrypt = require('bcrypt');
const User = require('./usermodel');
const jwt = require('jsonwebtoken');

/**
 * Verify unique user
 * @param {Object} request.payload
 * @param {String} request.payload.username
 * @return {Object} response 
 */
const verifyUniqueUser = (request, response) => {
  const query = User.findOne({username: request.payload.username});
  query.exec().then((user) => {
    if (user) {
      return response(badRequest('Username taken.'));
    }

    return response(request.payload);
  }).catch((error) => {
    return response(badImplementation('Something went wrong.'));
  });
}

/**
 * Verify login credentials
 * @param {Object} request.payload
 * @param {String} request.payload.username
 * @return {Object} response 
 */
const verifyCredentials = (request, response) => {
  const password = request.payload.password
  const query = User.findOne({username: request.payload.username});

  query.exec().then((user) => {
    user.comparePassword(password, user.password, (error, isMatch) => {
      if (error) {
        return response(badImplementation('Something went wrong.'));
      }

      if (!isMatch) {
        return response(badRequest('Incorrect username or password'));
      }

      return response(user);
    });

  }).catch((error) => {
    return response(badRequest('Incorrect username or password'));
  });
};

/**
 * 
 * @param {String} password 
 * @param {Function} callback
 * @return {Function} callback
 */
const hashPassword = (password, callback) => {
  Bcrypt.genSalt(10, (error, salt) => {
    Bcrypt.hash(password, salt, (error, hash) => {
      return callback(error, hash);
    })
  });
};

/**
 * Create JWT 
 */
const createToken = (user) => {
  let scopes;
  if (user.admin) {
    scopes = 'admin';
  }

  return jwt.sign({
    id: user._id,
    username: user.username,
    scope: scopes
  }, process.env.TOKEN_SECRET, {
      algorithm: 'HS256'
  });
}

module.exports = {
  verifyCredentials,
  verifyUniqueUser,
  hashPassword,
  createToken
};