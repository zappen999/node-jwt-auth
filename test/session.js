var chai = require('chai');
chai.use(require('sinon-chai'));
var expect = chai.expect;
var sinon = require('sinon');

var jwt = require('jsonwebtoken');
var uuid = require('uuid');
var TokenCache = require('../app/models/tokencache');

var User = require('../app/models/user');
var constants = require('../constants');

var bcrypt = require('bcrypt');

var auth = require('../app/middleware/auth');
var sess = require('../app/controllers/session');

var userMock = sinon.mock(User);
var jwtMock = sinon.mock(jwt);


describe('Session handling', function () {

  afterEach(function () {
    jwtMock.restore();
    jwtMock = sinon.mock(jwt);

    userMock.restore();
    userMock = sinon.mock(User);
  });


  describe('Refresh token', function () {
    it('Should generate a new token and resolve with it', function () {
      var fakeUser = {name: 'name', email: 'email', role: 'role', id: 'id'};
      var oldToken = 'thisistheoldtoken';

      return sess.refresh(fakeUser, oldToken).then(function (newToken) {
        expect(newToken).to.not.equal(oldToken);
      });
    });

    it('Should remove the old token from the TokenCache', function () {
      var fakeUser = {name: 'name', email: 'email', role: 'role', id: 'id'};
      var oldToken = 'thisistheoldtoken';

      var tokenCacheRemoveSpy = sinon.spy(TokenCache, 'remove');

      return sess.refresh(fakeUser, oldToken).then(function (newToken) {
        expect(tokenCacheRemoveSpy).calledWith(oldToken);
        tokenCacheRemoveSpy.restore();
      });
    });

    it('Should add the new token to the TokenCache', function () {
      var fakeUser = {name: 'name', email: 'email', role: 'role', id: 'id'};
      var oldToken = 'thisistheoldtoken';

      var tokenCacheAddSpy = sinon.spy(TokenCache, 'add');

      return sess.refresh(fakeUser, oldToken).then(function (newToken) {
        expect(tokenCacheAddSpy).calledWith(newToken, fakeUser.id);
        tokenCacheAddSpy.restore();
      });
    });

    it('Should reject promise if generateToken rejected', function () {
      var fakeUser = {name: 'name', email: 'email', role: 'role', id: 'id'};
      var oldToken = 'thisistheoldtoken';

      var generateTokenStub = sinon.stub(auth, 'generateToken')
      .returns(Promise.reject(new Error('some error')));

      return sess.refresh(fakeUser, oldToken).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('some error');
        generateTokenStub.restore();
      });
    });
  });


  describe('Login', function () {
    it('Should reject promise if user not found', function () {
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.reject(new Error('some error')));

      return sess.login('testmail', 'testpass', false).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('some error');
        findUserStub.restore();
      });
    });

    it('Should reject promise if the found user is inactive', function () {
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve({role: constants.ROLES.INACTIVE}));

      return sess.login('testmail', 'testpass', false).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('User not activated');
        findUserStub.restore();
      });
    });

    it('Should reject promise if the hash doesnt match', function () {
      var fakeUser = {name: 'name', email: 'email', role: constants.ROLES.USER, id: 'id'};
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve(fakeUser));
      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(false));

      return sess.login('testmail', 'testpass', false).catch(function (err) {
        expect(err).to.be.an('error');
        expect(err.message).to.equal('Wrong username or password');
        findUserStub.restore();
        compareHashStub.restore();
      });
    });

    it('Should generate token if authentication succeeded', function () {
      var fakeUser = {name: 'name', email: 'email', role: constants.ROLES.USER, id: 'id'};
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve(fakeUser));
      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(true));
      var generateTokenSpy = sinon.spy(auth, 'generateToken');

      return sess.login('testmail', 'testpass', false).then(function () {
        expect(generateTokenSpy).calledOnce;
        findUserStub.restore();
        compareHashStub.restore();
        generateTokenSpy.restore();
      });
    });

    it('Should add token to the token cache if the authentication succeeded', function () {
      var fakeUser = {name: 'name', email: 'email', role: constants.ROLES.USER, id: 'id'};
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve(fakeUser));
      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(true));
      var tokenCacheAddSpy = sinon.spy(TokenCache, 'add');

      return sess.login('testmail', 'testpass', false).then(function () {
        expect(tokenCacheAddSpy).calledOnce;
        findUserStub.restore();
        compareHashStub.restore();
        tokenCacheAddSpy.restore();
      });
    });

    it('Should resolve the "auth" object if the authentication succeeded', function () {
      var fakeUser = {name: 'name', email: 'email', role: constants.ROLES.USER, id: 'id'};
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve(fakeUser));
      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(true));
      var generateTokenStub = sinon.stub(auth, 'generateToken')
      .returns('thenewtoken');

      return sess.login('testmail', 'testpass', false).then(function (authObj) {
        expect(authObj.user).to.deep.equal(fakeUser);
        expect(authObj.auth.token).to.equal('thenewtoken');
        findUserStub.restore();
        compareHashStub.restore();
        generateTokenStub.restore();
      });
    });

    it('Should generate new access code if remember flag is set', function () {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        id: 'id',
        accesscodes: [],
        markModified: function() {},
        save: function() {},
      };
      var findUserStub = sinon.stub(auth, 'findUserByEmail')
      .returns(Promise.resolve(fakeUser));
      var compareHashStub = sinon.stub(auth, 'compareHash')
      .returns(Promise.resolve(true));
      var generateNewAccesscodeMock = sinon.mock(sess);
      generateNewAccesscodeMock.expects('generateNewAccesscode').once()
      .returns(Promise.resolve({}));

      return sess.login('testmail', 'testpass', true).then(function() {
        generateNewAccesscodeMock.verify();
        findUserStub.restore();
        compareHashStub.restore();
        generateNewAccesscodeMock.restore();
      });
    });

  });

  describe('generateNewAccesscode', function () {

    it('Should add the hash to the users accesscodes', function () {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        accessid: 'accesid',
        id: 'id',
        accesscodes: [],
        markModified: function() {},
        save: function() {},
      };
      var authObj = {};

      var saveUserStub = sinon.stub(auth, 'saveUser')
      .returns(Promise.resolve());

      return sess.generateNewAccesscode(fakeUser, authObj).then(function () {
        expect(fakeUser.accesscodes.length).to.equal(1);
        saveUserStub.restore();
      });
    });

    it('Should mark the accesscodes field as modified', function (done) {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        accessid: 'accesid',
        id: 'id',
        accesscodes: [],
        markModified: function() {
          saveUserStub.restore();
          done();
        },
        save: function() {},
      };
      var authObj = {};

      var saveUserStub = sinon.stub(auth, 'saveUser')
      .returns(Promise.resolve());

      sess.generateNewAccesscode(fakeUser, authObj);
    });

    it('Should remove the last access code if reaching limit of 10', function () {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        accessid: 'accesid',
        id: 'id',
        accesscodes: [
          '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'
        ],
        markModified: function() {},
        save: function() {},
      };
      var authObj = {};

      var saveUserStub = sinon.stub(auth, 'saveUser')
      .returns(Promise.resolve());

      return sess.generateNewAccesscode(fakeUser, authObj).then(function () {
        expect(fakeUser.accesscodes.length).to.equal(10);
        expect(fakeUser.accesscodes[0]).to.equal('2');
        saveUserStub.restore();
      });
    });

    it('Should save the user', function () {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        accessid: 'accesid',
        id: 'id',
        accesscodes: [],
        markModified: function() {},
        save: function() {},
      };
      var authObj = {};

      var saveUserMock = sinon.mock(auth);
      saveUserMock.expects('saveUser').once().returns(Promise.resolve());

      return sess.generateNewAccesscode(fakeUser, authObj).then(function () {
        saveUserMock.verify();
        saveUserMock.restore();
      });
    });

    it('Should append the "auth" object with id and code', function () {
      var fakeUser = {
        name: 'name',
        email: 'email',
        role: constants.ROLES.USER,
        accessid: 'accesid',
        id: 'id',
        accesscodes: [],
        markModified: function() {},
        save: function() {},
      };
      var authObj = {};

      var saveUserStub = sinon.stub(auth, 'saveUser')
      .returns(Promise.resolve());
      var uuidV4Stub = sinon.stub(uuid, 'v4').returns('thecode');

      return sess.generateNewAccesscode(fakeUser, authObj).then(function () {
        expect(authObj.id).to.equal(fakeUser.accessid);
        expect(authObj.code).to.equal('thecode');
        saveUserStub.restore();
        uuidV4Stub.restore();
      });
    });
  });

  describe('handleLogin', function () {

    it('Should return 200 on resolved login promise', function (done) {
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(200);
          loginStub.restore();
          done();
          return this;
        }
      };
      var fakeReq = {
        body: {email: 'email', password: 'password', remember: false}
      };

      var loginStub = sinon.stub(sess, 'login').returns(Promise.resolve());

      sess.handleLogin(fakeReq, fakeRes);
    });

    it('Should return auth object in the JSON response', function (done) {
      var fakeRes = {
        json: function (json) {
          loginStub.restore();
          expect(json).to.deep.equal(fakeAuthObj);
          done();
        },
        status: function (statusCode) {
          return this;
        }
      };
      var fakeReq = {
        body: {email: 'email', password: 'password', remember: false}
      };
      var fakeAuthObj = {token: 'token', stuff: 'stuff'};

      var loginStub = sinon.stub(sess, 'login')
      .returns(Promise.resolve(fakeAuthObj));

      sess.handleLogin(fakeReq, fakeRes);
    });

    it('Should return 403 if the login promise gets rejected', function (done) {
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(403);
          done();
          loginStub.restore();
          return this;
        }
      };
      var fakeReq = {
        body: {email: 'email', password: 'password', remember: false,}
      };

      var loginStub = sinon.stub(sess, 'login').returns(Promise.reject());

      sess.handleLogin(fakeReq, fakeRes);
    });

    it('Should return a JSON message when login promise gets rejected', function (done) {
      var fakeRes = {
        json: function (json) {
          loginStub.restore();
          expect(json.message).to.equal('Authentication failed');
          done();
        },
        status: function (statusCode) {
          return this;
        }
      };
      var fakeReq = {
        body: {email: 'email', password: 'password', remember: false}
      };

      var loginStub = sinon.stub(sess, 'login')
      .returns(Promise.reject());

      sess.handleLogin(fakeReq, fakeRes);
    });

  });

  describe('handleRefresh', function () {

    it('Should call refresh with user and token from request object', function () {
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) { return this; }
      };
      var fakeReq = {
        user: {},
        token: 'atoken',
        headers: {},
      };

      var refreshMock = sinon.mock(sess);
      refreshMock.expects('refresh').withArgs(fakeReq.user, fakeReq.token)
      .returns(Promise.resolve());

      sess.handleRefresh(fakeReq, fakeRes);
      refreshMock.verify();
      refreshMock.restore();
    });

    it('Should return user object with user from request object if refresh promise resolves', function (done) {
      var fakeReq = {
        user: {name: 'whatever', id: 'id', role: 'role', email: 'email'},
        token: 'atoken',
        headers: {},
      };
      var fakeRes = {
        json: function (json) {
          expect(json.user).to.deep.equal(fakeReq.user);
          refreshMock.restore();
          done();
        },
        status: function (statusCode) { return this; }
      };

      var refreshMock = sinon.mock(sess);
      refreshMock.expects('refresh').returns(Promise.resolve("atoken"));

      sess.handleRefresh(fakeReq, fakeRes);
    });

    it('Should return a new token in the response', function () {
      var fakeReq = {
        user: {name: 'whatever', id: 'id', role: 'role', email: 'email'},
        token: 'oldtoken',
        headers: {'x-access-id': 'acid', 'x-access-code': 'acode'},
      };
      var fakeRes = {
        json: function (json) {
          expect(json.auth.token).to.not.equal('oldtoken');
          refreshMock.restore();
          done();
        },
        status: function (statusCode) { return this; }
      };

      var refreshMock = sinon.mock(sess);
      refreshMock.expects('refresh').returns(Promise.resolve("atoken"));

      sess.handleRefresh(fakeReq, fakeRes);
    });

    it('Should return auth object with id and code if they are present in the request object', function (done) {
      var fakeReq = {
        user: {name: 'whatever', id: 'id', role: 'role', email: 'email'},
        token: 'atoken',
        headers: {'x-access-id': 'acid', 'x-access-code': 'acode'},
      };
      var fakeRes = {
        json: function (json) {
          var compareObj = {
            token: fakeReq.token,
            id: fakeReq.headers['x-access-id'],
            code: fakeReq.headers['x-access-code']
          };

          expect(json.auth).to.deep.equal(compareObj);
          refreshMock.restore();
          done();
        },
        status: function (statusCode) { return this; }
      };

      var refreshMock = sinon.mock(sess);
      refreshMock.expects('refresh').returns(Promise.resolve("atoken"));

      sess.handleRefresh(fakeReq, fakeRes);
    });

    it('Should return 500 if refresh promise gets rejected', function (done) {
      var fakeReq = {
        user: {name: 'whatever', id: 'id', role: 'role', email: 'email'},
        token: 'atoken',
        headers: {'x-access-id': 'acid', 'x-access-code': 'acode'},
      };
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(500);
          refreshMock.restore();
          done();
          return this;
        }
      };

      var refreshMock = sinon.mock(sess);
      refreshMock.expects('refresh').returns(Promise.reject());

      sess.handleRefresh(fakeReq, fakeRes);
    });
  });

  describe('handleLogout', function () {
    it('Should remove token in request object from the TokenCache', function () {
      var fakeReq = {token: 'token'};
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          return this;
        }
      };

      var removeTokenSpy = sinon.spy(TokenCache, 'remove');

      sess.handleLogout(fakeReq, fakeRes);
      expect(removeTokenSpy).calledWith(fakeReq.token);
      removeTokenSpy.restore();
    });

    it('Should return 200', function (done) {
      var fakeReq = {token: 'token'};
      var fakeRes = {
        json: function (json) {},
        status: function (statusCode) {
          expect(statusCode).to.equal(200);
          done();
          return this;
        }
      };

      sess.handleLogout(fakeReq, fakeRes);
    });
  });







});
