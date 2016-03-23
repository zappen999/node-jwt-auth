var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var async = require('async');
var router = require('express').Router();
var path = require('path');
var constants = require('../../constants');
var uuid = require('uuid');
var sendgrid = require("sendgrid")(constants.SENDGRID_APIKEY);

// Import models
var User = require('../models/user');

// Import middleware
var AuthMiddleware = require('../middleware/auth');


/**
* Get all users
* @author Johan Kanefur <johan.kanefur@solidio.se>
*/
router.get('/', AuthMiddleware.admin, function(req, res) {
  var query = {
    role: {$lt: constants.ROLES.ADMIN}
  };
  var fields = '-_id id email name role createdAt updatedAt';
  var pagination = {
    skip: 0, // Default from beginning
    limit: req.query.limit ? parseInt(req.query.limit) : 15,
  };

  if (pagination.limit > 100) {
    return res.status(400).json({message: 'Max limit is 100'});
  }

  // Text search (search for name)
  if (req.query.q) {
    query.name = new RegExp(req.query.q, 'i');
  }

  if (req.query.startFrom) {
    req.checkQuery('startFrom', 'Invalid start').notEmpty().isInt();

    if (req.validationErrors()) {
      return res.status(400).json({
        message: 'startFrom must be an integer'
      });
    }

    pagination.skip = parseInt(req.query.startFrom);
  }

  User
  .find(query, fields, pagination)
  .sort({
    name: 'asc'
  })
  .exec(function(err, users) {
    if (err) {
      return res.status(500).json({
        message: 'Could get users' + err.message
      });
    }

    return res.status(200).json(users);
  });
});


/**
* Get specific user
* @author Johan Kanefur <johan.kanefur@solidio.se>
*/
router.get('/:id', AuthMiddleware.admin, function(req, res) {
  var query = {
    id: req.params.id,
  };
  var fields = '-_id id email name role createdAt updatedAt';

  User
  .findOne(query, fields)
  .exec(function(err, user) {
    if (err) {
      return res.status(500).json({message: 'Could get user'});
    }

    if (!user) {
      return res.status(404).json({message: 'Not found'});
    }

    return res.status(200).json(user);
  });
});



/**
* For activating account
* @author Johan Kanefur <johan.kanefur@solidio.se>
*/
router.post('/password/:invitecode/activate', function(req, res) {
  req.checkBody('password', 'Invalid password').notEmpty().len(8, 100);

  async.waterfall([
    function (callback) {
      if (req.validationErrors()) {
        return callback(new Error('Input validation failed'));
      }

      callback(null); // Onwards
    },
    function (callback) {
      // Get the user
      var fields = '_id id email name role createdAt updatedAt';

      User.findOne({invitecode: req.params.invitecode}, fields)
      .exec(function (err, user) {
        if (err) {
          return callback(err);
        }

        if (!user) {
          return callback(new Error('No user found'));
        }

        return callback(null, user);
      });
    },
    function(user, callback) {
      // Hash the password
      bcrypt.hash(req.body.password, 8, function(err, hash) {
        if (err) {
          return res.status(500).json({message: 'Could not hash password'});
        }

        // Append the hash to the user object
        user.password = hash;

        // Update the role to USER
        user.role = constants.ROLES.USER;

        // Update the invitecode so the current one gets invalid
        user.invitecode = uuid.v4();

        callback(null, user);
      });
    },
    function (user, callback) {
      // Save the user
      user.save(function (err) {
        if (err) {
          return res.status(500).json({message: 'Could not save user'});
        }

        callback(null, user);
      });
    },
  ], function (err, user) {
    if (err) {
      return res.status(422).json({message: err.message});
    }

    // Hide sensitive stuff
    var returnUser = user.toJSON();
    returnUser.password = undefined;
    returnUser._id = undefined;
    returnUser.invitecode = undefined;

    return res.status(200).json(returnUser);
  });
});


/**
* Update password route
* @todo Use template engine (mustache?)
* @author Johan Kanefur <johan.kanefur@solidio.se>
*/
router.post('/password', function (req, res) {
  // Use async to avoid callback hell
  async.waterfall([
    function(callback) {
      // Validate input
      req.checkBody('email', 'Invalid email').notEmpty().isEmail();

      if (req.validationErrors()) {
        return callback(new Error('Input validation failed'));
      }

      callback(null); // Onwards
    },
    function(callback) {
      // Get the user
      User.findOne({email: req.body.email}, function(err, user) {
        if (err) {
          return callback(err);
        }

        if (!user) {
          return callback(new Error('User doesnt exist'));
        }

        return callback(null, user);
      });
    },
    function (user, callback) {
      // Update the users invitecode and save the user
      user.invitecode = uuid.v4();

      user.save(function (err) {
        if (err) {
          return callback(err);
        }

        return callback(null, user);
      });
    },
    function(user, callback) {
      callback(null, user);

      // Send mail async
      var email = new sendgrid.Email();
      email.addTo(user.email);
      email.setFrom(constants.SYSTEM_EMAIL);
      email.setFromName(constants.SYSTEM_NAME);
      email.setSubject("Begäran av nytt lösenord");
      email.setHtml(
        '<h1>Begäran av nytt lösenord</h1>' +
        '<p>Följ länken för att välja ett nytt lösenord.</p>' +
        '<p><a href="http://localhost:3000/users/password/' +
        user.invitecode + '">http://localhost:3000/users/password/' +
        user.invitecode + '</a></p>'
      );

      sendgrid.send(email, function (err, json) {
        if (err) {
          throw err;
        }
      });
    }
  ],
  function(err, user) {
    if (err) {
      return res.status(400).json({message: 'Password change request failed'});
    }

    res.status(200).json({message: 'Password change request sent'});
  });
});



/**
* Invite new user
* @author Johan Kanefur <johan.kanefur@solidio.se>
* @todo add email templating (mustache?)
* @todo change from localhost:3000
*/
router.post('/invites', AuthMiddleware.admin, function(req, res) {
  // Use async to avoid callback hell
  async.waterfall([
    function(callback) {
      // Validate input
      req.checkBody('email', 'Invalid email').notEmpty().isEmail();
      req.checkBody('name', 'Invalid name').notEmpty();

      if (req.validationErrors()) {
        return callback(new Error('Input validation failed'));
      }

      callback(null); // Onwards
    },
    function(callback) {
      // Check if email is taken
      User.findOne({
        email: req.body.email
      }, function(err, exists) {
        if (exists) {
          return callback(new Error('Email already exists'));
        }

        return callback(null);
      });
    },
    function(callback) {
      // Insert the user into the database
      var user = new User({
        email: req.body.email,
        name: req.body.name,
        role: constants.ROLES.INACTIVE
      });

      // Save into the database
      user.save(function(err) {
        if (err) {
          return res.status(500).json({
            message: 'Could not save user'
          });
        }

        callback(null, user);
      });
    },
    function(user, callback) {
      callback(null, user);

      // Send mail async
      var email = new sendgrid.Email();
      email.addTo(user.email);
      email.setFrom(constants.SYSTEM_EMAIL);
      email.setFromName(constants.SYSTEM_NAME);
      email.setSubject("Activate account");
      email.setHtml(
        '<h1>Activate account</h1>' +
        '<p><a href="http://localhost:3000/users/activate/' +
        user.invitecode + '">http://localhost:3000/users/activate/' +
        user.invitecode + '</a></p>'
      );

      sendgrid.send(email, function (err, json) {
        if (err) {
          throw err;
        }

      });
    }
  ],
  function(err, user, category) {
    if (err) {
      return res.status(400).json({
        message: err.message
      });
    }

    res.status(201).json({
      email: user.email,
      name: user.name,
      id: user.id,
      role: user.role,
      invitecode: user.invitecode,
    });
  });
});


/**
* Update a user.
* Password updates gets handled by another route.
* @author Johan Kanefur <johan.kanefur@solidio.se>
*/
router.post('/:id', AuthMiddleware.admin, function(req, res) {
  async.waterfall([
    function (callback) {
      // Try to find the user
      var fields = '_id id email name role createdAt updatedAt';

      User.findOne({id: req.params.id}, fields)
      .exec(function (err, user) {
        if (err) {
          return callback(err);
        }

        if (!user) {
          return callback(new Error('User not found'));
        }

        return callback(null, user);
      });
    },
    function (user, callback) {
      // Update the stuff that is present
      if (req.body.role) {
        user.role = req.body.role;
      }

      // Update name
      if (req.body.name) {
        req.checkBody('name', 'Invalid name').notEmpty();
        user.name = req.body.name;
      }

      // Check email
      if (req.body.email) {
        req.checkBody('email', 'Invalid email').notEmpty().isEmail();
      }

      // Check if all the validation failed
      var errors = req.validationErrors();

      if (errors) {
        return callback(new Error('Validation errors'));
      }

      return callback(null, user);
    },
    function (user, callback) {
      if (!req.body.email) {
        // Dont update the mail
        return callback(null, user);
      }

      // Check if the user is allowed to change to the provided email
      User.findOne({email: req.body.email}, function (err, foundUser) {
        if (err) {
          return callback(err);
        }

        // If the user was found, fine
        if (foundUser) {
          // The email must belong to the user
          if (foundUser.id !== user.id) {
            return callback(new Error('User with this email already exists'));
          }
        }

        // Its free to use
        user.email = req.body.email;

        return callback(null, user);
      });
    },
    function (user, callback) {
      // Save into the database
      user.save(function(err) {
        if (err) {
          return callback(err);
        }

        // Hide sensitive stuff
        var returnUser = user.toJSON();
        returnUser.password = undefined;
        returnUser._id = undefined;

        return callback(null, returnUser);
      });
    }
  ], function (err, returnUser) {

    if (err) {
      return res.status(400).json({message: err.message});
    }

    return res.status(200).json(returnUser);
  });
});

module.exports = router;
