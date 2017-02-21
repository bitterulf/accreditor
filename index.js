'use strict';

const fs = require('fs');
const _ = require('lodash');
const Hapi = require('hapi');
const Boom = require('boom');
const jwt = require('jsonwebtoken');
const auth = require('basic-auth');
const NodeRSA = require('node-rsa');

const config = require('./config.json');

const server = new Hapi.Server({});

if (!fs.existsSync("keys.json")) {
	const key = new NodeRSA({b: 512});

	fs.writeFileSync("keys.json", JSON.stringify({
		private: key.exportKey('pkcs1-sha256-private-pem'),
		public: key.exportKey('pkcs1-sha256-public-pem')
	}));
}

const keys = require('./keys.json');

const privateKey = keys.private;
const publicKey = keys.public;

const port = process.argv[2] || 4000;

server.connection({
  port: port
});

server.route({
    method: 'POST',
    path: '/generate',
    handler: function (request, reply) {
		const user = auth(request);
		if (!config[user.name] || config[user.name].password != user.pass) {
			return reply(Boom.unauthorized());
		}
		else if (!request.payload) {
			return reply(Boom.badRequest('nothing to accredit'));
		}
		const payload = _.defaults(config[user.name].payload, request.payload);

		reply(jwt.sign(payload, privateKey, {algorithm: 'RS256', expiresIn: config[user.name].expiresIn}));
    }
});

server.route({
    method: 'GET',
    path: '/publicKey',
    handler: function (request, reply) {
		reply(publicKey);
    }
});

server.start((err) => {
    if (err) {
        throw err;
    }

    console.log('server start on port ' + port);
});
