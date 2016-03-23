var bcrypt    = require('bcrypt');
var async     = require('async');
var jwt       = require('jsonwebtoken');
var router    = require('express').Router();
var constants = require('../../constants');
var shortid   = require('shortid');
var uuid      = require('uuid');

// Import models
var User = require('../models/user');
var TokenCache = require('../models/tokencache');
var auth = require('../middleware/auth');


/**
 * Login flow:
 * Find user by email
 * Check if user is active
 * Check provided password against the user.password hash
 * Generate new token and store it into the TokenCache
 * Check if remember me true:
 *  Generate accesscode and push it to accesscodes arr (remove oldest if over 10)
 *  save user
 */

/**
 * Refresh flow:
 * Generate new token
 * Remove the old token from TokenCache
 * Add the new token to the TokenCache
 * Return object identical to login route
 */

var self = module.exports = {

  /**
   * Refresh a token
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {User}   user     The user object to refresh for
   * @param  {string} oldToken The old token
   * @return {Promise}
   */
  refresh: function (user, oldToken) {
    return Promise.resolve(
      auth.generateToken(user.id, user.email, user.name, user.role)
    ).then(function (token) {
      // Revoke the old token by removing it from the token cache
      TokenCache.remove(oldToken);

      // Add the new token to the TokenCache
      TokenCache.add(token, user.id);

      return token;
    });
  },


  /**
   * Login function
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {string} email
   * @param  {string} password
   * @param  {bool}   remember Create fallback keys for remember functionality
   * @return {Promise}
   */
  login: function (email, password, remember) {
    return auth.findUserByEmail(email).then(function (user) {
      if (user.role === constants.ROLES.INACTIVE) {
        return Promise.reject(new Error('User not activated'));
      }

      return user;
    }).then(function (user) {
      return auth.compareHash(password, user.password).then(function (match) {
        if (!match) {
          return Promise.reject(new Error('Wrong username or password'));
        }

        return Promise.resolve(
          auth.generateToken(user.id, user.email, user.name, user.role)
        ).then(function (token) {

          // Add the token to the TokenCache
          TokenCache.add(token, user.id);

          // Return the beginning of the 'auth' object
          return {
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              role: user.role
            },
            auth: {
              token: token
            }
          };
        });
      }).then(function (authObj) { // Generated token
        if (!remember) {
          return authObj;
        }

        return self.generateNewAccesscode(user, authObj.auth).then(function () {
          return authObj;
        });
      });
    });
  },


  /**
   * Generates fallback keys to the auth object
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {Object} user User object
   * @param  {Object} auth Auth object created by self.login
   * @return {Promise}
   */
  generateNewAccesscode: function (user, authObj) {
    // Generate random id
    var code = uuid.v4();


    return auth.generateHash(code).then(function (hash) {
      // Only store the hash of the accesscode
      user.accesscodes.push(hash);

      // Max sessions is 10
      if (user.accesscodes.length > 10) {
        user.accesscodes.shift(); // Remove the oldest
      }

      user.markModified('accesscodes');
      return auth.saveUser(user).then(function () {
        authObj.id = user.accessid;
        authObj.code = code;
      });
    });
  },


  /**
   * Handle login requests
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {Object} req   Express request object
   * @param  {Object} res   Express response object
   */
  handleLogin: function (req, res) {
    self.login(req.body.email, req.body.password, req.body.remember)
    .then(function (authObj) {
      return res.status(200).json(authObj);
    }).catch(function (err) {
      return res.status(403).json({message: 'Authentication failed'});
    });
  },


  /**
   * Handle refresh requests
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {Object} req   Express request object
   * @param  {Object} res   Express response object
   */
  handleRefresh: function (req, res) {
    fbh = auth.extractFallbackHeaders(req);

    self.refresh(req.user, req.token).then(function (token) {
      return res.status(200).json({
        user: {
          id: req.user.id,
          email: req.user.email,
          name: req.user.name,
          role: req.user.role
        },
        auth: {
          token: token,
          id: fbh ? fbh.id : null,
          code: fbh ? fbh.code : null,
        }
      });

    }).catch(function (err) {
      return res.status(500).json({message: 'Could not refresh token'});
    });
  },


  /**
   * Perform a logout by removing the token from the TokenCache
   * @author Johan Kanefur <johan.kanefur@solidio.se>
   * @param  {Object} req   Express request object
   * @param  {Object} res   Express response object
   */
  handleLogout: function (req, res) {
    TokenCache.remove(req.token);
    res.status(200).json({message: 'Logged out'});
  },
};


router.post('/', self.handleLogin);
router.post('/refresh', auth.user, self.handleRefresh);
router.delete('/', auth.user, self.handleLogout);

// Export express routes
module.exports.router = router;
