var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var envs = require('envs');
var fs = require('fs');
var expressValidator = require('express-validator');

// Load environment vars from .env file
require('dotenv').load();

// @boilerplate: Set production environment here
app.set('environment', envs('NODE_ENV', 'production'));
app.set('port', envs('PORT', 9000));
app.set('mongo_string', envs('MONGO', 'mongodb://localhost:27017/node-jwt-auth'));

var DEV = app.get('environment') === 'development';

var server = require('http').Server(app);

console.log('Running ' + app.get('environment') + ', port ' + app.get('port'));
console.log('Connecting to MongoDB using ' + app.get('mongo_string'));

// Connect the MongoDB
mongoose.connect(app.get('mongo_string'));

// Handle socket connections & events
var solidSocket = require('./solidsocket');
var io = solidSocket.setup(server, '/api');
solidSocket.initiate();

// Send along the reference to the socket (if we need to use the socket in the
// express routes, probably not...)
app.set('socketio', io);

// Middleware for parsing the request
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(expressValidator());
app.use(bodyParser.json());

// Handle body parser errors
app.use(function(err, req, res, next) {
  if (err) {
    return res.status(401).json({
      message: 'Invalid input: ' + err.message
    });
  }
});

// Custom validation methods
app.use(expressValidator({
  customValidators: {
    valueBetween: function(param, min, max) {
      return (param >= min && param <= max);
    }
  }
}));

var accessControlAllowOriginString = DEV ? '*' : constants.FRONT_END_HOST;

app.all('*', function(req, res, next) {
  res.header('Access-Control-Allow-Origin', accessControlAllowOriginString);
  res.header('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'X-Requested-With, Content-Type, x-access-id, x-access-code, x-access-token'
  );
  next();
});

// Always log to file
app.use(morgan('common', {
  stream: fs.createWriteStream(__dirname + '/access.log', {
    flags: 'a'
  })
}));

// Log to console if development
if (app.get('environment') === 'development') {
  app.use(morgan('dev'));
}

// Register the routes (add routes to the index controller)
app.use('/api', require('./app/controllers'));

// Static file serving for media
app.use('/media', express.static(__dirname + '/media'));

// Start the server and listen for requests
server.listen(app.get('port'), function() {
  console.log('Serving at http://localhost:' + app.get('port'));
});
