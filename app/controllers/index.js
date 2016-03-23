var router = require('express').Router();

// The purpose of this file is to bind together all controller routes

// Default entities / routes for authentication
router.use('/session', require('./session').router);
router.use('/users', require('./users'));

// @boilerplate: Add more entities here if you like. Ex:
//router.use('/stations', require('./stations'));

module.exports = router;
