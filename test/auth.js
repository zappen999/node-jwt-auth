var chai = require('chai');
chai.use(require('sinon-chai'));
var expect = chai.expect;
var sinon = require('sinon');
require('sinon-mongoose');

var jwt = require('jsonwebtoken');
var TokenCache = require('../app/models/tokencache');

var User = require('../app/models/user');
var constants = require('../constants');

var bcrypt = require('bcrypt');

var userMock = sinon.mock(User);
var jwtMock = sinon.mock(jwt);


var auth = require('../app/middleware/auth');

describe('Authentication middleware', function () {

  afterEach(function () {
    jwtMock.restore();
    jwtMock = sinon.mock(jwt);

    userMock.restore();
    userMock = sinon.mock(User);
  });

  describe('findUserByEmail', function () {

    it('Should reject promise on mongoose error', function () {
      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(new Error('Mongoose error'));

      return auth.findUserByEmail('mail').catch(function (err) {
        expect(err).to.be.an('error');
      });
    });

    it('Should reject promise if no user if found', function () {
      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(null, null);

      return auth.findUserByEmail('mail').catch(function (err) {
        expect(err).to.be.an('error');
      });
    });

    it('Should resolve user object if user was found', function () {
      var fakeUser = {name: 'Fakeuser', email: 'fakemail@mail.com'};

      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(null, fakeUser);

      return auth.findUserByEmail('mail').then(function (user) {
        expect(user).to.deep.equal(fakeUser);
      });
    });
  });

  describe('findUserByXAccessId', function () {
    it('Should reject promise on mongoose error', function () {
      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(new Error('Mongoose error'));

      return auth.findUserByXAccessId('testid').catch(function (err) {
        expect(err).to.be.an('error');
      });
    });

    it('Should reject promise if no user if found', function () {
      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(null, null);

      return auth.findUserByXAccessId('testid').catch(function (err) {
        expect(err).to.be.an('error');
      });
    });

    it('Should resolve user object if user was found', function () {
      var fakeUser = {name: 'Fakeuser', email: 'fakemail@mail.com'};

      // Setup mock
      userMock.expects('findOne')
      .chain('exec')
      .yields(null, fakeUser);

      return auth.findUserByXAccessId('testid').then(function (user) {
        expect(user).to.deep.equal(fakeUser);
      });
    });
  });

  describe('compareHash', function () {
    it('Should reject promise on bcrypt error', function () {
      // Setup stub
      bcryptStub = sinon.stub(bcrypt, 'compare')
      .yields(new Error('bcrypt error'));

      return auth.compareHash('testid', 'hash').catch(function (err) {
        expect(err).to.be.an('error');
        bcryptStub.restore();
      });
    });

    it('Should resolve promise with hash if the hash did match', function () {
      // Setup stub
      bcryptStub = sinon.stub(bcrypt, 'compare')
      .yields(null, true);

      return auth.compareHash('teststring', 'testhash').then(function (hash) {
        expect(hash).to.equal('testhash');
        bcryptStub.restore();
      });
    });

    it('Should resolve promise with false if the hash didnt match', function () {
      // Setup stub
      bcryptStub = sinon.stub(bcrypt, 'compare')
      .yields(null, false);

      return auth.compareHash('teststring', 'testhash').then(function (result) {
        expect(result).to.equal(false);
      });
    });
  });

  describe('generateToken', function () {
    it('Should return a token string', function () {
      var fakeTokenString = 'eyhasdsuHDSIuh21987398';

      var jwtStub = sinon.stub(jwt, 'sign').returns(fakeTokenString);

      var res = auth.generateToken('fakeid', 'fakemail', 'fakename', 'fakerole');
      expect(res).to.equal(fakeTokenString);
      jwtStub.restore();
    });

    it('Should generate unique tokens with same data provided', function () {
      var token1 = auth.generateToken('id', 'email', 'name', 'role');
      var token2 = auth.generateToken('id', 'email', 'name', 'role');
      expect(token1).to.not.equal(token2);
    });
  });

  describe('generateHash', function () {
    it('Should reject promise on bcrypt salt error', function () {
      // Setup stub
      var bcryptStub = sinon.stub(bcrypt, 'genSalt')
      .yields(new Error('salt error'));

      return auth.generateHash('stringtohash').catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('salt error');
        bcryptStub.restore();
      });
    });

    it('Should reject promise on bcrypt hash error', function () {
      // Setup stub
      var bcryptSaltStub = sinon.stub(bcrypt, 'genSalt')
      .yields(null, 'salt');
      var bcryptHashStub = sinon.stub(bcrypt, 'hash')
      .yields(new Error('hash error'));

      return auth.generateHash('stringtohash').catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('hash error');
        bcryptSaltStub.restore();
        bcryptHashStub.restore();
      });
    });

    it('Should resolve promise with hash on success', function () {
      // Setup stub
      var bcryptSaltStub = sinon.stub(bcrypt, 'genSalt')
      .yields(null, 'salt');
      var bcryptHashStub = sinon.stub(bcrypt, 'hash')
      .yields(null, 'generatedhash');

      return auth.generateHash('stringtohash').then(function (hash) {
        expect(hash).to.equal('generatedhash');
        bcryptSaltStub.restore();
        bcryptHashStub.restore();
      });
    });

  });

  describe('saveUser', function () {
    it('Should reject promise on mongoose error', function () {
      var fakeUser = {
        save: function (cb) {
          cb(new Error('Mongoose error'));
        }
      };

      return auth.saveUser(fakeUser).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('Mongoose error');
      });
    });

    it('Should resolve promise if save succeeded', function () {
      var fakeUser = {
        save: function (cb) {
          cb(null, null);
        }
      };

      return auth.saveUser(fakeUser).then(function (res) {
        expect(res).to.be.undefined;
      });
    });
  });

  describe('removeAccessCodes', function () {
    it('Should clear accesscodes', function () {
      var mockUserObj = {
        accesscodes: ['code1', 'code2'],
        markModified: function () {}
      };

      auth.removeAccessCodes(mockUserObj);
      expect(mockUserObj.accesscodes.length).to.equal(0);
    });

    it('Should call markModified', function (done) {
      var mockUserObj = {
        accesscodes: ['code1', 'code2'],
        markModified: function (value) {
          expect(value).to.equal('accesscodes');
          done();
        }
      };

      auth.removeAccessCodes(mockUserObj);
    });
  });

  describe('extractFallbackHeaders', function () {
    it('Should return null if one of them is null', function () {
      var mockReq = {headers: {'x-access-code': 'blaja'}};

      var result = auth.extractFallbackHeaders(mockReq);
      expect(result).to.equal(null);
    });

    it('Should return object if both exists', function () {
      var mockReq = {headers: {'x-access-id': 'korv','x-access-code': 'blaja'}};

      var result = auth.extractFallbackHeaders(mockReq);
      expect(result).to.deep.equal({ id: 'korv', code: 'blaja' });
    });
  });

  describe('findMatchingHash', function () {

    it('Should reject the promise if no matching hash was found', function () {
      var hashes = ['hash1', 'hash2', 'hash3'];

      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(false));

      return auth.findMatchingHash('comparevalue', hashes).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('No matching hash');

        compareHashStub.restore();
      });
    });


    it('Should resolve promise if one of the hashes matched', function () {
      var hashes = ['hash1', 'hash2', 'hash3'];

      var compareHashStub = sinon.stub(auth, 'compareHash');
      compareHashStub.onSecondCall().returns(Promise.resolve(true));
      compareHashStub.returns(Promise.resolve(false));

      return auth.findMatchingHash('comparevalue', hashes).then(function (res) {
        expect(res).to.equal(undefined);

        compareHashStub.restore();
      });
    });
  });

  describe('verifyJwt', function () {
    it('Should reject promise if the token not could be verified', function () {
      var jwtVerStub = sinon.stub(jwt, 'verify').yields(new Error('JWT err'));

      return auth.verifyJwt('faketoken', 'fakesecret').catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('JWT err');
        jwtVerStub.restore();
      });
    });

    it('Should resolve promise with decoded token if token got verified', function () {
      var tokenData = {email: 'Fakeemail@mail.com', id: 'id'};
      var jwtVerStub = sinon.stub(jwt, 'verify').yields(null, tokenData);

      return auth.verifyJwt('faketoken', 'fakesecret').then(function (decoded) {
        expect(decoded).to.deep.equal(tokenData);
        jwtVerStub.restore();
      });
    });
  });


  describe('validateToken', function () {
    it('Should reject the promise if the token wasnt found', function () {
      var existsStub = sinon.stub(auth, 'tokenExistsInTokenCache');
      existsStub.returns(false);

      return auth.validateToken('testtoken').catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('Token did not exist in TokenCache');
        existsStub.restore();
      });
    });

    it('Should return a promise if the token was found', function () {
      var existsStub = sinon.stub(auth, 'tokenExistsInTokenCache');
      existsStub.returns(true);
      var verifyStub = sinon.stub(auth, 'verifyJwt');
      verifyStub.returns(Promise.resolve());

      return auth.validateToken('testtoken').then(function (res) {
        expect(res).to.equal(undefined);
        existsStub.restore();
        verifyStub.restore();
      });
    });
  });

  describe('Authenticate middleware method', function () {
    it('Should read the token from the query', function () {
      var fakeReq = {query: {token: 'thisisthetoken'}, headers: {}};
      var spy = sinon.spy(auth, 'validateToken');

      auth.authenticate(fakeReq, null, function () {});
      expect(spy).calledWith('thisisthetoken');
      spy.restore();
    });

    it('Should read the token from the headers', function () {
      var fakeReq = {query: {}, headers: {'x-access-token': 'thisisthetoken'}};
      var spy = sinon.spy(auth, 'validateToken');

      auth.authenticate(fakeReq, null, function () {});
      expect(spy).calledWith('thisisthetoken');
      spy.restore();
    });

    it(
      'Should run next middlware on successful token validation',
      function (done) {
        var fakeReq = {query: {}, headers: {'x-access-token': 'thisisthetoken'}};
        var validateTokenStub = sinon.stub(auth, 'validateToken');
        validateTokenStub.returns(Promise.resolve({}));

        auth.authenticate(fakeReq, null, function (res) {
          expect(res).to.equal(undefined);
          validateTokenStub.restore();
          done();
        });
      }
    );

    it('Should attempt secondary login mechanism if token not present', function (done) {
      var fakeReq = { query: {}, headers: {} };
      var fallbackSpy = sinon.spy(auth, 'fallbackAuthMiddlewareExtend');
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(403);
          done();
          return this;
        }
      };

      auth.authenticate(fakeReq, fakeRes, function () {});
      expect(fallbackSpy).calledOnce;
      fallbackSpy.restore();
    });

    it('Should validate the token if its present', function (done) {
      var fakeReq = { query: {token: 'thisisthetoken'}, headers: {} };
      var validateTokenStub = sinon.stub(auth, 'validateToken');
      validateTokenStub.returns(Promise.resolve());

      auth.authenticate(fakeReq, null, function (res) {
        expect(res).to.equal(undefined);
        expect(validateTokenStub).calledOnce;
        validateTokenStub.restore();
        done();
      });
    });

    it(
      'Should set the decoded token to the request object on successful validation',
      function (done) {
        var fakeReq = { query: {token: 'thisisthetoken'}, headers: {} };
        var fakeUser = {name: 'Johan'};
        var validateTokenStub = sinon.stub(auth, 'validateToken')
        .returns(Promise.resolve(fakeUser));

        auth.authenticate(fakeReq, null, function () {
          expect(fakeReq.user).to.deep.equal(fakeUser);
          done();
          validateTokenStub.restore();
        });
      }
    );

    it(
      'Should set the token to the request object on successful validation',
      function (done) {
        var fakeReq = { query: {token: 'thisisthetoken'}, headers: {} };
        var fakeUser = {name: 'Johan'};
        var validateTokenStub = sinon.stub(auth, 'validateToken')
        .returns(Promise.resolve(fakeUser));

        auth.authenticate(fakeReq, null, function () {
          expect(fakeReq.token).to.equal(fakeReq.query.token);
          done();
          validateTokenStub.restore();
        });
      }
    );

    it(
      'Should attempt secondary login mechanism if the token was invalid',
      function (done) {
        var fakeReq = { query: {token: 'thisisthetoken'}, headers: {} };
        var validateStub = sinon.stub(auth, 'validateToken')
        .returns(Promise.reject(new Error('tokenerror')));
        var fallbackAuthStub = sinon.stub(auth, 'fallbackAuth')
        .returns(Promise.reject(new Error('somerror')));
        var fallbackSpy = sinon.spy(auth, 'fallbackAuthMiddlewareExtend');
        var fakeRes = {
          json: function (json) {},
          status: function (statusCode) {
            expect(statusCode).to.equal(403);
            expect(fallbackSpy).calledOnce;
            fallbackSpy.restore();
            validateStub.restore();
            fallbackAuthStub.restore();
            done();
            return this;
          }
        };

        auth.authenticate(fakeReq, fakeRes, function () {});
      }
    );

    it(
      'Should return 403 if no id or code existed on secondary login mechanism',
      function (done) {
        var fakeReq = {
          query: {token: 'thisisthetoken'},
          headers: {'x-access-id': 'id', 'x-access-code': 'code'}
        };
        var validateStub = sinon.stub(auth, 'validateToken')
        .returns(Promise.reject(new Error('tokenerror')));
        var fallbackAuthStub = sinon.stub(auth, 'fallbackAuth')
        .returns(Promise.reject(new Error('somerror')));
        var fallbackSpy = sinon.spy(auth, 'fallbackAuthMiddlewareExtend');
        var fakeRes = {
          json: function (json) {},
          status: function (statusCode) {
            fallbackSpy.restore();
            validateStub.restore();
            fallbackAuthStub.restore();
            expect(statusCode).to.equal(403);
            expect(fallbackSpy).calledOnce;
            done();
            return this;
          }
        };

        auth.authenticate(fakeReq, fakeRes, function () {});
      });
    }
  );


  describe('User role middlware', function () {
    it('Should return 403 if user role less than USER', function (done) {
      var authStub = sinon.stub(auth, 'authenticate').callsArg(2);
      var fakeReq = {user: {role: constants.ROLES.INACTIVE}};
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(403);
          authStub.restore();
          done();
          return this;
        }
      };

      auth.user(fakeReq, fakeRes, null);
    });
  });

  describe('Admin role middlware', function () {
    it('Should return 403 if user role less than ADMIN', function (done) {
      var authStub = sinon.stub(auth, 'authenticate').callsArg(2);
      var fakeReq = {user: {role: constants.ROLES.MODERATOR}};
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(403);
          authStub.restore();
          done();
          return this;
        }
      };

      auth.admin(fakeReq, fakeRes, null);
    });
  });

  describe('fallbackAuthMiddlewareExtend', function () {
    it('Should return 403 if fallback headers cannot be found', function (done) {
      var fakeReq = {query: {token: 'thisisthetoken'}, headers: {}};
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(403);
          done();
          return this;
        }
      };

      auth.fallbackAuthMiddlewareExtend(fakeReq, fakeRes, function () {});
    });

    it('Should return 403 if the fallback authentication promise failed', function () {
      var fakeReq = {
        query: {token: 'thisisthetoken'},
        headers: {'x-access-id': 'id', 'x-access-code': 'code'}
      };
      var fallbackAuthStub = sinon.stub(auth, 'fallbackAuth')
      .returns(Promise.reject(new Error('somerror')));
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          fallbackAuthStub.restore();
          expect(statusCode).to.equal(403);
          done();
          return this;
        }
      };

      auth.authenticate(fakeReq, fakeRes, function () {});
    });

    it('Should set user and token to request object on fallback auth success', function (done) {
      var fakeReq = {
        query: {token: 'thisisthetoken'},
        headers: {'x-access-id': 'id', 'x-access-code': 'code'}
      };
      var fakeAuthObj = {
        user: {
          accessid: 'accessid'
        },
        token: 'token',
        code: 'code',
      };

      var fallbackAuthStub = sinon.stub(auth, 'fallbackAuth')
      .returns(Promise.resolve(fakeAuthObj));

      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          return this;
        }
      };

      auth.fallbackAuthMiddlewareExtend(fakeReq, fakeRes, function () {
        expect(fakeReq.user).to.deep.equal(fakeAuthObj.user);
        expect(fakeReq.token).to.equal(fakeAuthObj.token);

        fallbackAuthStub.restore();
        done();
      });
    });

    it('Should set auth object to response object on fallback auth success', function (done) {
      var fakeReq = {
        query: {token: 'thisisthetoken'},
        headers: {'x-access-id': 'id', 'x-access-code': 'code'}
      };
      var fakeAuthObj = {
        user: {
          accessid: 'accessid'
        },
        token: 'token',
        code: 'code',
      };

      var fallbackAuthStub = sinon.stub(auth, 'fallbackAuth')
      .returns(Promise.resolve(fakeAuthObj));

      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          return this;
        }
      };

      auth.fallbackAuthMiddlewareExtend(fakeReq, fakeRes, function () {
        expect(fakeRes.auth.token).to.equal(fakeAuthObj.token);
        expect(fakeRes.auth.id).to.equal(fakeAuthObj.user.accessid);
        expect(fakeRes.auth.code).to.equal(fakeAuthObj.code);

        fallbackAuthStub.restore();
        done();
      });
    });

  });

  describe('fallbackAuth', function () {

    it('Should reject the promise if no user was found', function () {
      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.reject(new Error('some error')));

      return auth.fallbackAuth().catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('some error');
        findUserByXAccessIdStub.restore();
      });
    });

    it('Should reject the promise if no matching hash was found', function () {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {}
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.reject(new Error('no matches')));

      return auth.fallbackAuth().catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('no matches');
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
      });
    });

    it('Should remove accesscodes and save user if no matching hash was found', function () {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {}
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.reject(new Error('no matches')));
      var removeAccessSpy = sinon.spy(auth, 'removeAccessCodes');
      var saveUserSpy = sinon.spy(auth, 'saveUser');

      return auth.fallbackAuth().catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('no matches');
        expect(removeAccessSpy).calledOnce;
        expect(saveUserSpy).calledOnce;
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
        removeAccessSpy.restore();
        saveUserSpy.restore();
      });
    });

    it('Should remove all tokens in TokenCache if no matching hash was found', function () {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {}
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.reject(new Error('no matches')));
      var removeAllForIdSpy = sinon.spy(TokenCache, 'removeAllForId');

      return auth.fallbackAuth().catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('no matches');
        expect(removeAllForIdSpy).calledOnce;
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
        removeAllForIdSpy.restore();
      });
    });

    it('Should generate a new token if one of the hashes matched', function (done) {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {},
        save: function (cb) {
          cb(null, true);
        },
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.resolve(true));
      var gentokenSpy = sinon.spy(auth, 'generateToken');

      auth.fallbackAuth().then(function () {
        expect(gentokenSpy).calledOnce;
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
        gentokenSpy.restore();
        done();
      });
    });

    it('Should add the token string to the TokenCache if fallback succeeded', function (done) {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {},
        save: function (cb) {
          cb(null, true);
        },
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.resolve(true));
      var addtokenSpy = sinon.spy(TokenCache, 'add');

      auth.fallbackAuth().then(function () {
        expect(addtokenSpy).calledOnce;
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
        addtokenSpy.restore();
        done();
      });
    });

    it('Should replace the old accesscode if fallback succeeded', function (done) {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [
          'thisistheaccesshash'
        ],
        markModified: function (field) {
          expect(field).to.equal('accesscodes');
          expect(fakeUser.accesscodes[0]).to.not.equal('thisistheaccesshash');
          findUserByXAccessIdStub.restore();
          findMatchingHashStub.restore();
          done();
        },
        save: function (cb) {
          cb(null, true);
        },
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.resolve('thisistheaccesshash'));

      auth.fallbackAuth();
    });

    it('Should save the user after the accesscodes has been changed', function (done) {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {},
        save: function (cb) {
          cb(null, true);
        },
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.resolve(true));
      var saveUserSpy = sinon.spy(auth, 'saveUser');

      auth.fallbackAuth().then(function () {
        expect(saveUserSpy).calledOnce;
        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
        saveUserSpy.restore();
        done();
      });
    });

    it('Should resolve promise with auth object on successful fallback authentication', function () {
      var fakeUser = {
        email: 'email', id: 'id', name: 'name', role: 'role', accesscodes: [],
        markModified: function () {},
        save: function (cb) {
          cb(null, true);
        },
      };

      var findUserByXAccessIdStub = sinon.stub(auth, 'findUserByXAccessId')
      .returns(Promise.resolve(fakeUser));
      var findMatchingHashStub = sinon.stub(auth, 'findMatchingHash')
      .returns(Promise.resolve(true));

      return auth.fallbackAuth().then(function (auth) {
        expect(auth.user).to.deep.equal(fakeUser);
        expect(auth.token).to.not.be.empty;
        expect(auth.id).to.equal(fakeUser.accessid);
        expect(auth.code).to.not.be.empty;

        findUserByXAccessIdStub.restore();
        findMatchingHashStub.restore();
      });
    });
  });























});
