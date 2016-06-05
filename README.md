# hapi-users-plugin (WIP)

[HAPI](http://hapijs.com/) plugin for users and login.

## Install

```
npm i hapi-users-plugin --save
```

## Requirements

For the plugin to work at all, you need to install and configurate `hapi-mongodb` in you hapi installation.

For sessions you need to install `hapi-auth-cookie` and set the correct option value.

For tokens you need to install `hapi-auth-jwt` and set the correct option value.

## Usage

```
plugins.push({
  register: require('hapi-users-plugin'),
  options: {
    session: true,
    token: true,
    expire: 60 * 60 * 24 * 365,
    session_private_key: 'KeyThatIsEqualOrLongerThan32CharactersIsNeededForThis',
  }
});
```

### Options

- `session` - `true` or `false`, defaults to `false`. Enables login with sessions & cookies. Required package needed for this option: `hapi-auth-cookie`.
- `token` - `true` or `false`, defaults to `false`. Enabled login with tokens. Required package needed for this option: `hapi-auth-jwt`.
- `expire` -  Seconds for session and token to expire. Defaults to `60 * 60 * 24 * 365`.
- `session_private_key` - A private session/token key. Minimum 32 characters.
- `extra_fields` - Extra fields for user object. Use [Joi](https://github.com/hapijs/joi) with this for validation. Example below. If you use .required() on any field, this will field will also be required in payload when trying to update user.

```
extra_fields: {
  firstname: Joi.string().min(2).max(30),
  lastname: Joi.string().min(2).max(30)
}
```

### Other notes

This is mainly a lazy way for myself to add user and login functionality to my own hapi installations. Feel free to use and modify!
