var expect = require('chai').expect;
var TokenCache = require('../app/models/tokencache');
var shortid = require('shortid');

describe('Token cache', function () {

  before(function () {
    TokenCache.reset();
  });

  afterEach(function() {
    TokenCache.reset();
  });


  it('Should add a token to the cache list', function () {
    TokenCache.add('mytesttokenstring', 'johan2');
    TokenCache.add('mytesttoksadsadadsenstring', 'adssadasd');
    expect(TokenCache.getLength()).to.equal(2);
  });

  it('Should return the token object is token is present', function () {
    TokenCache.add('token1', 'johasdadn2');
    TokenCache.add('token2', 'johasdadn2');
    var tokenObj = TokenCache.get('token2');
    expect(tokenObj.token).to.equal('token2');
  });

  it('Should return null when getting a token that doesnt exist', function () {
    expect(TokenCache.get('tokenstringthatdoesntexists')).to.equal(null);
  });

  it('Should remove all tokens for a specific userid', function () {
    TokenCache.add('token1', 'johan1');
    TokenCache.add('token2', 'johan1');
    TokenCache.add('token3', 'johan2');
    TokenCache.add('token4', 'johan2');
    TokenCache.removeAllForId('johan1');

    expect(TokenCache.getLength()).to.equal(2);
    expect(TokenCache.get('token3')).not.null;
    expect(TokenCache.get('token4')).not.null;
  });

  it('Should get the revoke flag on a token', function () {
    TokenCache.add('testingtoken2', 'useruddud');
    TokenCache.revoke('testingtoken2');
    expect(TokenCache.isRevoked('testingtoken2')).be.true;
  });


  it('Should set the revoke flag on a token', function () {
    TokenCache.add('testingtoken1', 'useruddud');
    TokenCache.revoke('testingtoken1');
    expect(TokenCache.get('testingtoken1').revoked).be.true;
  });

  it('Removes a token to the cache object', function () {
    TokenCache.add('testingtoken5', 'useruddud');
    expect(TokenCache.getLength()).to.equal(1);
    TokenCache.remove('testingtoken5');
    expect(TokenCache.getLength()).to.equal(0);
  });

  it('Should not remove tokens created after the expiredate', function () {
    TokenCache.add('mytesttoken', 'johan2');

    // Set expire date one second in the past
    var expiredate = new Date();
    expiredate.setSeconds(expiredate.getSeconds() - 1);

    expect(TokenCache.clean(expiredate)).equal.true;

    // Check if the token is still in the cache
    expect(TokenCache.get('mytesttoken').token).to.equal('mytesttoken');
  });

  it('Should keep a maximum number of sessions of 50 for a user', function () {
    for (var i = 0; i < 99; i++) {
      TokenCache.add(shortid.generate(), 'johan1');
    }

    expect(TokenCache.getLength()).to.equal(50);
  });

  it('Should not remove another users session when max is reached', function () {
    var rand1 = shortid.generate();
    var rand2 = shortid.generate();

    TokenCache.add(rand1, 'johan2');
    TokenCache.add(rand2, 'johan2');

    for (var i = 0; i < 99; i++) {
      TokenCache.add(shortid.generate(), 'henke');
    }

    // johan2's sessions should be left untouched when henke is fucking ut
    expect(TokenCache.get(rand1).token).to.equal(rand1);
    expect(TokenCache.get(rand2).token).to.equal(rand2);
  });


  it('Should delete the oldest token first', function () {
    TokenCache.add('firsttoken', 'David');

    for (var i = 0; i < 49; i++) {
      TokenCache.add('middletoken', 'David');
    }

    TokenCache.add('Lasttoken', 'David');

    // Expect the first token to be gone
    expect(TokenCache.get('firsttoken')).to.equal(null);
  });
});
