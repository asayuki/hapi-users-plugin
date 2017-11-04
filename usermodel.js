'use strict';

const Mongoose = require('mongoose');
const Schema = Mongoose.Schema;
const bcrypt = require('bcrypt');

const user = new Schema({
  username: {
    type: String,
    required: true,
    index: {
      unique: true
    }
  },
  password: {
    type: String,
    required: true
  }
});

user.methods.comparePassword = (password, hash, callback) => {
  bcrypt.compare(password, hash, (error, isMatch) => {
    if (error) {
      return callback(error, false);
    }

    return callback(null, isMatch);
  });
}

user.index({username: 'text'});

module.exports = Mongoose.model('User', user);