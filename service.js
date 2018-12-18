const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const validator = require('express-validator');
const _ = require('lodash');

const url = 'mongodb://localhost:27017/';

const TTL = 180;

const log = winston.createLogger({
    level: 'silly',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console()
    ]
});

let app = express();
let _db = undefined;
let get_server_secret = function() {
    if(get_server_secret.server_secret) {
        if(Date.now() - get_server_secret.secret_updated > 600000) {
            get_server_secret.server_secret = require('crypto').randomBytes(512).toString('base64');
            get_server_secret.secret_updated = Date.now();
            return get_server_secret.server_secret;
        }
        return get_server_secret.server_secret;
    }
}
get_server_secret.server_secret = require('crypto').randomBytes(512).toString('base64');
get_server_secret.secret_updated = Date.now();

app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(validator());

MongoClient.connect(url, function(err, db) {

    if (err) {
        log.error("Mongo DB connection has been failed.");
        throw err;
    }

    log.info("Mongo DB connection has been provided.");
    _db = db.db("cortex-auth");

    app.post('/authenticate', function(req, res) {
        log.debug("Authenticate method is being called");
        req.checkBody('secret', 'Secret is required!').notEmpty();
        req.checkBody('secret', 'Secret should be a JWT!').isJWT();
        let errors = req.validationErrors();
        if (errors) {
            res.status(403).send(_.map(errors, err => { return err.msg; }));
            return;
        }
        log.debug("Params are validated");
        let secret = req.body.secret;

        // get the decoded payload and header
        let decoded = jwt.decode(secret, {complete: true});

        // get account id and algorithm to verify authentication token
        let account_id = decoded.payload.account_id;
        let alg = decoded.header.alg;

        // bring public key of account to verify authentication token, findBy account id and algorithm
        _db.collection("accounts").findOne({"_id" :ObjectId(account_id), "alg1":alg}, function (err, result) {
            if(err != null) {
                log.error("DB returned error.");
                res.status(503).send(err);
                return;
            }

            if(result == null) {
                res.status(404).send("There is no such account!");
                return;
            }

            let pkey = result.account_public_key;

            jwt.verify(secret, pkey, function(err) {
                if(err != null) {
                    res.status(403).send("Invalid token!");
                    return;
                }
                let now = Date.now();
                let token = jwt.sign({ account_id: result._id, role: 'workforce', iat: Math.floor(now / 1000) + TTL}, get_server_secret(), { algorithm: 'HS512'});
                res.json({
                    token: token,
                    role: 'workforce',
                    ttl: TTL,
                    created:now
                });
            });
        });
    });

    app.post('/authorize', function(req, res) {
        log.debug("Authorization method is being called");
        if (req.body == null || req.body.access_token == null) {
            res.status(403).send("Invalid Request");
            return;
        }
        let access_token = req.body.access_token;

        jwt.verify(access_token, get_server_secret(), function(err) {
            if(err != null) {
                res.status(401).send(err);
                return;
            }
            res.status(200).send();
        });
    });

    app.listen(9999, function() {
        log.info("OAuth started.");
    });
});

module.exports = {app, get_server_secret};