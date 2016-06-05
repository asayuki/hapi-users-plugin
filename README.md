# hapi-users-plugin (WIP)

[HAPI](http://hapijs.com/) plugin for users and login.

## Install

```bash
npm i hapi-users-plugin --save
```

## Requirements

* `hapi-mongodb` installed and configurated in you hapi-server.
* Enable caching with either [Catbox](https://github.com/hapijs/catbox) or any other cache-engine.
* For session based login: `hapi-auth-cookie`
* For token based login: `hapi-auth-jwt`

## Usage

```js
server.register([
  // Register mongodb
  // Register hapi-auth-cookie for session/cookies
  // Register hapi-auth-jwt for tokens
  {
    register: require('hapi-users-plugin'),
    options: {
      collection: 'users',
      cache_name: 'serverCache',
      session: true,
      token: true,
      expire: 60 * 60 * 24 * 365,
      session_private_key: 'KeyThatIsEqualOrLongerThan32CharactersIsNeededForThis',
    }
  }
]);
```

Full example further down.

### Options

- `collection` - Collection in MongoDB where users should be saved.
- `cache_name` -
- `session` - `true` or `false`, defaults to `false`. Enables login with sessions & cookies. Required package needed for this option: `hapi-auth-cookie`.
- `token` - `true` or `false`, defaults to `false`. Enables login with tokens. Required package needed for this option: `hapi-auth-jwt`.
- `expire` -  Milliseconds for session and token to expire. Defaults to `2147483647`.
- `session_private_key` - A private session/token key. Minimum 32 characters.
- `extra_fields` - Extra fields for user object. Use [Joi](https://github.com/hapijs/joi) with this for validation. Example below. If you use .required() on any field, this will field will also be required in payload when trying to update user as this extends default payload.

```js
extra_fields: {
  firstname: Joi.string().min(2).max(30),
  lastname: Joi.string().min(2).max(30)
}
```

### Endpoints

All endpoints require that the user i logged in, except login-endpoint.

* `POST /api/users`
    * Default payload:
        * `username` - Joi.string().alphanum().min(3).max(30).required()
        * `password` - Joi.string().required()
* `PUT /api/users`
    * Default payload:
        * `id` - Joi.string() - If omitted, uses ID from session.
        * `username` - Joi.string()
        * `password` - Joi.string()
* `GET /api/users/{usename}`
* `DELETE /api/users`
    * Payload:
        * `id` - Joi.string().required()
* `POST /api/users/login`
    * Payload:
        * `username` - Joi.string().required()
        * `password` - Joi.string().required()
* `GET /api/users/logout`

### Full example

```js
'use strict';

const
  hapi = require('hapi'),
  catbox = require('catbox-redis'),
  Joi = require('joi'),
  plugins = [],
  server = new hapi.Server({
    cache: [{
      name: 'serverCache',
      engine: catbox,
      host: '127.0.0.1',
      port: 6379,
      partition: 'redis-partition'
    }]
  });

server.connection({
  host: '127.0.0.1',
  port: 8000
});

plugins.push({
  register: require('hapi-mongodb'),
  options: {
    url: 'mongodb://127.0.0.1:27017/database',
    settings: {
      db: {
        'native_parser': false
      }
    }
  }
});

plugins.push({
  register: require('hapi-auth-cookie')
});

plugins.push({
  register: require('hapi-auth-jwt')
});

plugins.push({
  register: require('hapi-users-plugin'),
  options: {
    collection: 'users',
    session: true,
    token: true,
    expire: 60 * 60 * 24 * 365,
    session_private_key: 'KeyThatIsEqualOrLongerThan32CharactersIsNeededForThis',
    cache_name: 'serverCache',
    extra_fields: {
      firstname: Joi.string().min(2).max(30),
      lastname: Joi.string().min(2).max(30)
    }
  }
});

server.register(plugins, (err) => {
  if (err)
    throw err;

  server.start(() => {
    console.log('Server started at:', server.info.uri);
  });
});

module.exports = server;
```

### Other notes

This is mainly a lazy way for myself to add user and login functionality to my own hapi installations. Feel free to use and modify!
