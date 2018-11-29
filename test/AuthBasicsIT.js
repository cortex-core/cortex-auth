const chai = require('chai');
const chai_http = require('chai-http');
const chai_date_string = require('chai-date-string');

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const winston = require('winston');

const sinon = require('sinon');

const MongoClient = require("mongodb").MongoClient;
const MongoClientMock = require('mongo-mock').MongoClient;

const log = winston.createLogger({
    level: 'silly',
    format: winston.format.json(),
    transports: [
        new winston.transports.Console()
    ]
});

chai.should();
chai.use(chai_http);
chai.use(chai_date_string);

describe('Auth Baseline IT', function() {

    let mongo_stub;
    let service;
    let client_private;
    let server_secret;
    let account_id;
    let _db;

    before(function(){
        return new Promise(function (resolve, reject) {
            log.info("Initializing testing bed...");

            mongo_stub = sinon.stub(MongoClient, 'connect');

            MongoClientMock.connect('mongodb://localhost:27017/', function(db_err, db) {
                chai.should().equal(db_err, null);
                _db = db.db("cortex-auth");
                _db.collection("accounts").insert({alg1:'RS512', account_public_key:''}, function(err, res) {
                    chai.should().equal(err, null);
                    account_id = res.insertedIds[0];
                    mongo_stub.callsFake(function foo(url, cb) {
                        cb(null, db);
                    });

                    crypto.generateKeyPair('rsa', {
                        modulusLength: 4096,
                        publicKeyEncoding: {
                            type: 'spki',
                            format: 'pem'
                        },
                        privateKeyEncoding: {
                            type: 'pkcs1',
                            format: 'pem'
                        }
                    }, (err, publicKey, privateKey) => {
                        chai.should().equal(err, null);
                        let client_public = publicKey;
                        client_private = privateKey;

                        log.info("Public Key : " + client_public);
                        log.info("Private Key : " + client_private);

                        _db.collection("accounts").update({_id :account_id}, {$set:{account_public_key : client_public}}, function(err) {
                            chai.should().equal(err, null);
                            let service_module = require('./../service')
                            service = service_module.app;
                            server_secret = service_module.get_server_secret;
                            resolve();
                        });
                    });
                });
            });
        });
    });

    after(function(){
        log.info("Finalizing testing bed...");
        mongo_stub.restore();
    });

    it('should provide access token via /authenticate POST endpoint', function(done){
        let token = jwt.sign({ account_id: account_id, iat: Math.floor(Date.now() / 1000) + 180}, client_private, { algorithm: 'RS512'});
        let auth_request = { secret: token };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                chai.should().equal(err, null);
                res.should.have.status(200);
                res.should.be.json;
                res.body.should.have.property('token');
                token = res.body.token;
                res.body.should.have.property('role');
                res.body.should.have.property('ttl');
                res.body.should.have.property('created');
                done();
            });
    });
    it('should fail with missing secret at /authenticate POST endpoint', function(done){
        let auth_request = {};
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                chai.should().equal(err, null);
                res.should.have.status(403);
                done();
            });
    });
    it('should fail no account at /authenticate POST endpoint', function(done){
        let token = jwt.sign({ iat: Math.floor(Date.now() / 1000) + 180}, client_private, { algorithm: 'RS512'});
        let auth_request = { secret: token };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                chai.should().equal(err, null);
                res.should.have.status(404);
                done();
            });
    });
    it('should fail if verification fails at /authenticate POST endpoint', function(done){
        let token = jwt.sign({ account_id: account_id, iat: Math.floor(Date.now() / 1000) + 180}, client_private, { algorithm: 'RS512'});
        token += "s";
        let auth_request = { secret: token };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                chai.should().equal(err, null);
                res.should.have.status(403);
                done();
            });
    });
    it('should provide authorization response via /authorize POST endpoint', function(done){
        let token = jwt.sign({ account_id: account_id, iat: Math.floor(Date.now() / 1000) + 180}, server_secret(), { algorithm: 'HS512'});
        let validation_request = { access_token: token };
        chai.request(service)
            .post('/authorize')
            .send(validation_request)
            .end(function(err, res){
                chai.should().equal(err, null);
                res.should.have.status(200);
                done();
            });
    });
});

