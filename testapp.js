const Hapi = require('hapi');
const { hashPassword } = require('./lib/utils');

server = new Hapi.Server();
server.connection({
    port: 8080
});

const Mongoose = require('mongoose');
Mongoose.Promise = require('bluebird');
const db = Mongoose.connect(process.env.MONGO_URL + process.env.MONGO_DB, {
    useMongoClient: true
}, (error) => {
    if (error)
        throw error;
});

server.register([
    require('hapi-auth-jwt2'),
    {
        register: require('./lib/'),
        options: {
            url: '/api/users'
        }
    }
 ], (error) => {
    server.start((error) => {
        if (error)
            throw error;

        console.log(`ARGH started at: ${server.info.uri}`);
    });
});