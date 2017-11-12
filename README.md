# hapi-users-plugin (WIP)

[HAPI](http://hapijs.com/) plugin for users and login.

## Install

```bash
npm i hapi-users-plugin --save
```

## Endpoints

All endpoints, except `/authenticate` requires that `Authorization` is set in headers with valid JWT

* `POST /api/users/authenticate`
    * Default payload:
        * `username` - Joi.string().required()
        * `password` - Joi.string().required()
    * Response if valid login:
        * Body:
            * `loggedin` - true
        * Headers:
            * `authorization` - Signed JWT to use
* `GET/POST /api/users/unauthenticate`
* `PUT /api/users`
    * Default payload:
        * `id` - Joi.objectId()
        * `username` - Joi.string()
        * `password` - Joi.string()
        * `admin` - Joi.boolean()
    * Response if editing own user:
        * Headers:
            * `authorization` - Updated and signed JWT to use.
* `DELETE /api/users`
    * Default payload:
        * `id` - Joi.objectId().required()
* `POST /api/users`
    * Default payload:
        * `username` - Joi.string().required()
        * `password` - Joi.string().required()
        * `admin` - Joi.boolean().default(false)
* `GET /api/users`
    * Optional parameters:
        * `from` - Joi.objectId() - From which userid the list shall begin (omitting fromId)
        * `limit` - Joi.number() - Total of users to get
    * Default response:
        * Array with all users, passwordhash omitted
* `GET /api/users/{username}`
    * Default response:
        * Object with user, passwordhash omitted