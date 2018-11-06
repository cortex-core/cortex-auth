const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

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

app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

app.post('/authenticate', function(req, res) {
    log.debug("Authenticate method is being called");
    if (req.body == null || req.body.secret == null) {
        res.status(403).send("Invalid Request");
        return;
    }
    let secret = req.body.secret;

    // get the decoded payload and header
    var decoded = jwt.decode(secret, {complete: true});

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
            res.status(403).send("Forbidden");
            return;
        }

        let pkey = result.account_public_key;
        jwt.verify(secret, pkey, function(err, decoded) {
            if(err != null) {
                res.status(403).send("Forbidden");
                return;
            }
            let now = Date.now();
            let token = jwt.sign({ account_id: result._id, role: 'workforce', iat: Math.floor(now / 1000) + TTL}, result.server_secret, { algorithm: result.alg2});
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

    // get the decoded payload and header
    let decoded = jwt.decode(access_token, {complete: true});

    let account_id = decoded.payload.account_id;
    let alg = decoded.header.alg;

    // verify token
    _db.collection("accounts").findOne({"_id" :ObjectId(account_id), "alg2":alg}, function (err, result) {
        if(err != null) {
            log.error("DB returned error.");
            res.status(503).send(err);
            return;
        }

        if(result == null) {
            res.status(403).send("Forbidden");
            return;
        }

        let server_secret = result.server_secret;  // get public key
        jwt.verify(access_token, server_secret, function(err, decoded) {
            if(err != null) {
                res.status(401).send(err);
                return;
            }
            res.status(200).send();
        });
    });
});

MongoClient.connect(url, function(err, db) {
    log.info("Mongo DB connection has been provided.");
    _db = db.db("cortex-auth");
    app.listen(8080, function() {
        log.info("oauth started.");
    });
});

module.exports = app;