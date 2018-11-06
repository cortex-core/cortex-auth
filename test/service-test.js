const chai = require('chai');
const chai_http = require('chai-http');
const chai_date_string = require('chai-date-string');
const service = require('./../service');

chai.should();
chai.use(chai_http);
chai.use(chai_date_string);

describe('0auth Baseline', function() {
    it('should provide JWT via /authenticate POST endpoint', function(done){
        let auth_request = { secret: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiNWJlMjE3ZGFhY2QxNTk1YWY3ZTlhODJjIn0.ELvtE9_pgJqS-UvTo9VugRlCF-a73YeSszkIul0f5CJ3lbDscxtC_0MQpEMxNAGV58dnzhOjyEVY5coEqQAtGS71xkmV8EU2Xv5ZyBme_uw9GwRLHW2p8f89C0YE7fzDPFRGa-_y1URwwJ5ecorcTfmCmkSBl136y0ZuWLCznLM' };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(200);
                res.should.be.json;
                res.body.should.be.a('object');
                res.body.should.have.property('token');
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
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(403);
                done();
            });
    });
    it('should fail no account at /authenticate POST endpoint', function(done){
        let auth_request = { secret: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiNWJlMjE3ZGFhY2QxNTk1YWY3ZTlhODJkIn0.F9-fXADZfknK7fLBcWWBHFwXLeppYFZGeFosGPCVpv0NicrrmQDD0qZ3QI-J_QuWQQi9GSsCfh7oN9NuHl75nIvMWfqlbz18wnSwe5weB_N5ROaWk566eAJtSRwBqVXw_-RjZbnSxuaOz4XyyW_7mMIIDnR3_iOT84oMqgWZMF8' };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(403);
                done();
            });
    });
    it('should fail if verification fails at /authenticate POST endpoint', function(done){
        let auth_request = { secret: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiNWJlMjE3ZGFhY2QxNTk1YWY3ZTlhODJjIn0.Ij3pc9VQMMVO1EMgr8C2rj-Tzk4sFU1pns7Vfd4HOkVpaDi85tL-4-S2aJgMSR_9rBpQoqzEHcNrkSjg2WkObTUUNkJUSY_mZREC4L-C8Kz-fGKHtRIGF5Do-I5uNtOtUEtqG9-HALnphrqILs_toF5sLn6b1B3ye6RaCJpW008' };
        chai.request(service)
            .post('/authenticate')
            .send(auth_request)
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(403);
                done();
            });
    });
    it('should provide authorization response via /authorize POST endpoint', function(done){
        let validation_request = { access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiNWJlMjE3ZGFhY2QxNTk1YWY3ZTlhODJjIiwicm9sZSI6Indvcmtmb3JjZSIsImlhdCI6MTU0MTU0NzA1N30.1bGFRbM0pepwPoH9Gvl5crt_OEZEmKG8ae9J4bbNibQ' };
        chai.request(service)
            .post('/authorize')
            .send(validation_request)
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(200);
                done();
            });
    });
});
