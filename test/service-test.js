const chai = require('chai');
const chai_http = require('chai-http');
const chai_date_string = require('chai-date-string');
const service = require('./../service');

chai.should();
chai.use(chai_http);
chai.use(chai_date_string);

describe('0auth Baseline', function() {
    it('should provide JWT via /authenticate POST endpoint', function(done){
        let auth_request = { account_id: '1234567890', secret: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiMTIzNDU2Nzg5MCIsImNyZWF0ZWQiOiIxNTQwMjQxODYyIn0.bV-2hSoqaYnWvvb0Wje8FywMFKFX9ltI8Mc_AbBHt7Xg4k6LgiNY9JRIf_4fahSQZa_mOLB5MGz6Q4mI-E8OlTcMS2Ol7pfcRaB0Z5OqYuoAJymDuF1lLC2GEz-Dx-0ob6qO1b0fSzof53Qdv5KnTtvfrorXqew1inoR6tz21EE' };
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
                res.body.should.have.property('expiry');
                res.body.should.have.property('created');
                res.body.should.have.property('updated');
                done();
            });
    });
    it('should provide JWKS via /jwks GET endpoint', function(done){
        chai.request(service)
            .get('/jwks')
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.statusCode.should.equal(200);
                done();
            });
    });
    it('should provide validation response via /validate POST endpoint', function(done){
        let validation_request = { access_token: 'auth service generated token in JWT format' };
        chai.request(service)
            .post('/validate')
            .send(validation_request)
            .end(function(err, res){
                if(err){
                    err.should.equal(null);
                }
                res.should.have.status(200);
                res.should.be.json;
                res.body.should.be.a('object');
                res.body.should.have.property('isValid');
                res.body.should.have.property('role');
                done();
            });
    });
});
