var expect = require('chai').expect;
var mongoose = require('mongoose');
var sinon = require('sinon');
require('chai').use(require('sinon-chai'));
require('sinon-as-promised');
require('sinon-mongoose');
var TokenCache = require('../app/models/tokencache');
var auth = require('../app/middleware/auth');
var constants = require('../constants');

var User = require('../app/models/user');

var server = require('http').Server().listen(5000);

var sio = require('../solidsocket');
sio.setup(server);
sio.initiate();
var cio = require('socket.io-client');

// For client side
var fs = require('fs');


var socketURL = 'http://0.0.0.0:5000';
var options = {
  transports: ['websocket'],
  'force new connection': true
};

var mockUser = {};
var client1;

describe('Socket', function () {

  beforeEach(function () {
    mockUser = {
      email: 'admin@admin.com',
      password: 'secret',
      id: 'mockid',
      role: 4,
      _id: '56e2f6cd9a7032875b71fe3c'
    };

    client1 = cio.connect(socketURL, options);
  });


  describe('Authentication', function () {
    it('Should disconnect the socket if no authentication request was sent', function (done) {
      this.timeout(5000);

      var client1 = cio.connect(socketURL, options);

      client1.on('connect', function (data) {
      });

      client1.on('disconnect', function (data) {
        done();
      });
    });

    it('Should emit authenticated message on successful authentication', function (done) {
      var client1 = cio.connect(socketURL, options);
      var decoded = {email: 'testmail'};

      var validateTokenStub = sinon.stub(auth, 'validateToken')
      .returns(Promise.resolve(decoded));

      client1.on('connect', function (data) {
        client1.emit('authenticate', {token: 'blaj'});
      });

      client1.on('authenticated', function (data) {
        expect(data).to.deep.equal({message: 'Authenticated'});
        validateTokenStub.restore();
        done();
      });
    });

    it('Should register the authenticated events on successful authentication', function (done) {
      var client1 = cio.connect(socketURL, options);
      var decoded = {email: 'testmail'};
      var validateTokenStub = sinon.stub(auth, 'validateToken')
      .returns(Promise.resolve(decoded));
      var registerAuthenticatedEventsSpy = sinon.spy(sio, 'registerAuthenticatedEvents');

      client1.on('connect', function (data) {
        client1.emit('authenticate', {token: 'blaj'});
      });

      client1.on('authenticated', function (data) {
        expect(registerAuthenticatedEventsSpy).calledOnce;
        validateTokenStub.restore();
        done();
      });
    });

    it('Should disconnect the socket on unsuccessful authentication', function (done) {
      var client1 = cio.connect(socketURL, options);
      var validateTokenStub = sinon.stub(auth, 'validateToken')
      .returns(Promise.reject());

      client1.on('connect', function (data) {
        client1.emit('authenticate', {token: 'blaj'});
      });

      client1.on('disconnect', function () {
        validateTokenStub.restore();
        done();
      });
    });

  });
});
