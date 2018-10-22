const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const winston = require('winston');
const jwt = require('jsonwebtoken');

const TTL = 180;

const logger = winston.createLogger({
    level: 'silly',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console()
    ]
});

let app = express();

app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

app.post('/authenticate', function(req, res) {
    logger.debug("Authenticate method is being called");
    let secret = req.body.secret;

    // get the decoded payload and header
    var decoded = jwt.decode(secret, {complete: true});
    console.log(decoded.header);
    console.log(decoded.payload);

    let account_id = decoded.payload.account_id;
    let created = decoded.payload.created || new Date().getTime();

    if(created > new Date().getTime() + TTL * 1000000) {
        res.send(401, 'Invalid token');
    }

    // verify token
    // TODO : Implement user's public key retrival from db
    var cert = '-----BEGIN PUBLIC KEY-----\n' +
        'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
        'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
        'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
        'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
        '-----END PUBLIC KEY-----';  // get public key
    jwt.verify(secret, cert, function(err, decoded) {
        if(err != null) {
            res.status(401).send(err);
            return;
        }
        // TODO : Our assigned secret_key for user
        // TODO : Put data into JWT payload
        // TODO : Sign
        res.json({
            token: 'test',
            role: 'undefined',
            expiry: new Date().toUTCString(),
            created: new Date().toUTCString(),
            updated: new Date().toUTCString()
        });
    });
});

app.listen(8080, function() {
  console.log("0auth service listening 8080")
});

module.exports = app;