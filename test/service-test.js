const chai = require('chai');
const chai_http = require('chai-http');
const chai_date_string = require('chai-date-string');
const service = require('./../service');
chai.should();
chai.use(chai_http);
chai.use(chai_date_string);

describe('0auth Baseline', function() {
  it('should provide JWT via /authenticate POST endpoint', function(done){
      let auth_request = { secret: 'user_secret'};
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
              res.body.token.should.be.a.dateString();
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
});
