var jwt = require('jsonwebtoken');
var uuid = require('uuid');
var constants = require('../../constants');
var bcrypt = require('bcrypt');
var shortid = require('shortid');

// Import models
var User = require('../models/user');
var TokenCache = require('../models/tokencache');

/**
* Authentication middleware
*/

var self = module.exports = {

  /**
  * Finds a user by xaccessid, returns promise (with user object)
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} xaccessid
  * @return {Promise}
  */
  findUserByXAccessId: function(xaccessid) {
    return new Promise(function(resolve, reject) {
      User.findOne({accessid: xaccessid}).exec(function(err, user) {
        if (err) {
          return reject(err);
        }

        if (!user) {
          return reject(new Error('Not found'));
        }

        resolve(user);
      });
    });
  },

  /**
  * Finds a user by email, returns promise (with user object)
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} email    The email to search for
  * @return {Promise}
  */
  findUserByEmail: function(email) {
    return new Promise(function(resolve, reject) {
      User.findOne({email: email}).exec(function(err, user) {
        if (err) {
          return reject(err);
        }

        if (!user) {
          return reject(new Error('Not found'));
        }

        resolve(user);
      });
    });
  },

  /**
  * Compares a provided string and hash to see if they match
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string}   string   The string to compare
  * @param  {string}   hash     The hash to compare with
  * @return {Promise}
  */
  compareHash: function(string, hash) {
    return new Promise(function(resolve, reject) {
      bcrypt.compare(string, hash, function(err, res) {
        if (err) {
          return reject(err);
        }

        if (res) {
          return resolve(hash);
        }

        // No match
        return resolve(false);
      });
    });
  },

  /**
  * Generate a new token from user object
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} secret    The secret to sign with
  * @param  {string} id
  * @param  {string} email
  * @param  {string} name
  * @param  {string} role
  * @return {string}           The generated, signed token string
  */
  generateToken: function(id, email, name, role) {
    // Add the token to the token cache
    var tokenData = {
      id: id,
      email: email,
      name: name,
      role: role,
      unique: shortid.generate() // To ensure no token string are unique
    };

    // 1440 = 24h
    return jwt.sign(tokenData, constants.SECRET, {
      expireInMinutes: 1440
    });
  },

  /**
  * Generates hash from a string
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} string The string to hash
  * @return {Promise}
  */
  generateHash: function(string) {
    return new Promise(function(resolve, reject) {
      // Generate salt
      bcrypt.genSalt(10, function(err, salt) {
        if (err) {
          return reject(err);
        }

        bcrypt.hash(string, salt, function(err, hash) {
          if (err) {
            return reject(err);
          }

          return resolve(hash);
        });
      });
    });
  },

  /**
  * Saves the provided user into mongo
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {User} user Mongoose model
  * @return {Promise}
  */
  saveUser: function(user) {
    return new Promise(function(resolve, reject) {
      user.save(function(err) {
        if (err) {
          return reject(err);
        }

        resolve();
      });
    });
  },

  /**
  * Removes the list of accesscodes for the user
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Object} user Mongoose user object
  */
  removeAccessCodes: function(user) {
    user.accesscodes = [];
    user.markModified('accesscodes');
  },

  /**
  * Extracts the x-access-id and x-access-code
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Request} req The Express request object
  * @return {Mixed}       Object on success, null on fail
  */
  extractFallbackHeaders: function (req) {
    // Check if headers exists: x-access-id, x-access-code
    var xaccessid = req.headers['x-access-id'] || null,
    xaccesscode = req.headers['x-access-code'] || null;

    if (!(xaccessid && xaccesscode)) {
      return null;
    }

    return { id: xaccessid, code: xaccesscode };
  },

  /**
  * Finds out if a string matches any of the hashes in an array
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} value  The value to compare to the hashes
  * @param  {array} hashes  The array of hashes to compare with
  * @return {Promise}
  */
  findMatchingHash: function (value, hashes) {
    return Promise.all(hashes.map(function(hash) {
      return self.compareHash(value, hash);
    })).then(function (matches) {
      matchingHash = matches.filter(Boolean)[0] || null;

      if (matchingHash) {
        return Promise.resolve();
      }

      return Promise.reject(new Error('No matching hash'));
    });
  },

  /**
  * Fallback authentication if the token authentication doesnt work.
  * @todo break this apart into promise
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  fallbackAuth: function(xaccessid, xaccesscode) {
    // @todo get rid of these badboys
    var user, matchingHash, randId, tokenString;

    return self.findUserByXAccessId(xaccessid)
    .then(function (u) { // Got the user
      user = u;

      return self.findMatchingHash(xaccesscode, user.accesscodes);
    })
    .then(function (mh) { // Found matching hash
      matchingHash = mh;

      // Generate new token
      return self.generateToken(user.id, user.email, user.name, user.role);
    })
    .then(function (ts) {
      tokenString = ts;

      // Add the token to the cache
      TokenCache.add(tokenString, user.id);

      // Generate new access code
      randId = uuid.v4();

      // Hash the new access code
      return self.generateHash(randId).then(function (newHash) {
        // Replace the old access code in the user object
        user.accesscodes[user.accesscodes.indexOf(matchingHash)] = newHash;
        user.markModified('accesscodes'); // For mongoose to recognize change
      });
    })
    .then(function () {
      return self.saveUser(user);
    })
    .then(function () {
      var auth = {
        user: user,
        token: tokenString,
        id: user.accessid,
        code: randId
      };

      return Promise.resolve(auth);
    })
    .catch(function (err) {
      // No user found or no matching hash
      // Potential hacking attempt??
      if (user) {
        self.removeAccessCodes(user);
        self.saveUser(user);
        TokenCache.removeAllForId(user.id);
      }

      // @todo maybe this is not a good idea...
      return Promise.reject(err);
    });
  },

  /**
  * Extends the authenticate middleware, providing a second chance for
  * reautentication with 'remember me' ID and code.
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  fallbackAuthMiddlewareExtend: function (req, res, next) {
    // Check if headers exists: x-access-id, x-access-code
    var extractFallbackHeaders = self.extractFallbackHeaders(req);

    if (extractFallbackHeaders === null) {
      return res.status(403).json({message: 'Authentication failed'});
    }

    self.fallbackAuth(extractFallbackHeaders.id, extractFallbackHeaders.code)
    .then(function (auth) {
      // This authenticates the user on the server side
      req.user = auth.user;
      req.token = auth.token;

      // Setup the response to the client
      res.auth = {
        token: req.token,
        id: auth.user.accessid,
        code: auth.code
      };

      next(); // Next middleware
    })
    .catch(function (err) {
      return res.status(403).json({message: 'Authentication failed'});
    });
  },

  /**
  * This method should be used in the beginning of each 'user roles' middleware
  * This method will stop the request if token is invalid
  * Works as a regular middleware
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  authenticate: function(req, res, next) {
    var token = req.query.token || req.headers['x-access-token'];

    if (!token) {
      // Attempt secondary login mechanism
      return self.fallbackAuthMiddlewareExtend(req, res, next);
    }

    self.validateToken(token).then(function (decoded) {
      // This authenticates the user
      req.user = decoded;
      req.token = token;

      next(); // Next middleware
    })
    .catch(function (err) {
      // Token is invalid
      // Attempt secondary login mechanism
      self.fallbackAuthMiddlewareExtend(req, res, next);
    });
  },

  /**
  * Verifies a token with the secret. Returns a promise (decoded token)
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  verifyJwt: function(token, secret) {
    return new Promise(function(resolve, reject) {
      jwt.verify(token, secret, function(err, decoded) {
        if (err) {
          return reject(err);
        }

        resolve(decoded);
      });
    });
  },

  /**
  * Checks if token exists in the token cache
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  tokenExistsInTokenCache: function(token) {
    return (TokenCache.get(token) !== null);
  },

  /**
  * Checks if the JWT can be decoded with the secret and exists in the
  * TokenCache.
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {string} token The token string to validate
  * @return {Promise}  Promise with the decoded token
  */
  validateToken: function(token) {
    if (!self.tokenExistsInTokenCache(token)) {
      return Promise.reject(new Error('Token did not exist in TokenCache'));
    }

    return self.verifyJwt(token, constants.SECRET);
  },

  /**
  * Add authentication level middleware here
  */

  /**
  * Makes sure the requester is a logged in, activated user
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  user: function(req, res, next) {
    // Run base authentication
    self.authenticate(req, res, function() {
      if (req.user.role < constants.ROLES.USER) {
        return res.status(403).json({message: 'Authentication level too low'});
      }

      return next();
    });
  },

  /**
  * Makes sure the requester is a logged in admin
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  admin: function(req, res, next) {
    // Run base authentication
    self.authenticate(req, res, function() {
      if (req.user.role < constants.ROLES.ADMIN) {
        return res.status(403).json({message: 'Authentication level too low'});
      }

      return next();
    });
  },
};
