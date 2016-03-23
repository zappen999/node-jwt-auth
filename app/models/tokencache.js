var _ = require('lodash');

/**
* The purpose of this module is to store tokens in the memory after creation.
* With this, we can revoke created tokens, without IO operations, slowing down
* the request.
*
* CONS:
* All tokens dissapear when server is put offline
*
* FIXES:
* Add functionality to "dump" the token cache if the system needs to be
* moved or restarted.
*/

var cache = [];
var maxSessions = 50;


/*

Set max sessions on a particular user.
When max session is reached, delete the oldest session for that user

*/
var add = function (token, userid) {
  cache.push({
    token: token,
    userid: userid,
    created: new Date(),
    revoked: false
  });

  var sessions = 0;

  // Check if the user has reached the session limit
  for (var i = cache.length - 1; i >= 0 ; i--) {
    if (cache[i].userid === userid) {
      sessions++;

      if (sessions > maxSessions) {
        cache.splice(i, 1);
      }
    }
  }
};

/**
 * Removes all tokens for a specific ID
 * @author Johan Kanefur <johan.kanefur@solidio.se>
 */
var removeAllForId = function (id) {
  _.remove(cache, function (cacheEntry) {
    return cacheEntry.userid === id;
  });
};

var getIndex = function (token) {
  var index = _.findIndex(cache, {token: token});
  return (index === -1 ? null : index);
};

var get = function (token) {
  var index = getIndex(token);
  return (index === null ? null : cache[index]);
};

var revoke = function (token) {
  var index = getIndex(token);

  if (index === null) {
    return false;
  }

  cache[index].revoked = true;
  return true;
};

var isRevoked = function (token) {
  var index = getIndex(token);

  // Token not found in cache
  if (index === null) {
    return null;
  }

  return cache[index].revoked;
};

var remove = function (token) {
  cache.splice(getIndex(token), 1);
};

/**
* Clear the old tokens from the cache, all tokens created before
* 'expiredate' will be removed from the cache
*/
var clean = function (expiredate) {
  _.remove(cache, function (cacheEntry) {
    return (cacheEntry.created < expiredate);
  });
};

/**
 * Used to reset this module state
 */
var reset = function () {
  cache = [];
};

var getLength = function () {
  return cache.length;
};

var getAll = function () {
  return cache;
};

// Export the public methods
module.exports = {
  get: get,
  getAll: getAll,
  add: add,
  getLength: getLength,
  removeAllForId: removeAllForId,
  remove: remove,
  revoke: revoke,
  isRevoked: isRevoked,
  clean: clean,
  cache: cache, // For testing purposes
  reset: reset,
};
