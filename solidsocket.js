var socketio = require('socket.io');
var auth = require('./app/middleware/auth'); // For authentication
var ss = require('socket.io-stream'); // For handling file stream uploads

var constants = require('./constants');
var User = require('./app/models/user');

var self = module.exports = {
  io: null, // Save the socketio reference

  /**
  * Sets up Socket.IO on the provided server and sets a namespace
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Server} server    The HTTP server to use
  * @param  {string} namespace The namespace to use, ex: /api
  * @return {Socketio}         Socketio reference
  */
  setup: function(server, namespace) {
    // Initiate the socket with the provided server
    self.io = socketio(server);

    // Setup the namespace
    if (namespace) {
      self.io = self.io.of(namespace);
    }

    // Return the reference to the io
    return self.io;
  },


  /**
  * Listen for incoming socket connections and delegate them
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  */
  initiate: function() {
    // Handle new connections
    self.io.on('connection', self.handleNewClient);
  },


  /**
  * Handles new clients
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Socket} client The new client
  */
  handleNewClient: function (client) {
    // New client connected, not authenticated by default
    client.isAuthenticated = false;

    // Register events that doesnt require authentication
    self.registerPublicEvents(client);

    // The client has one second to authenticate himself before he gets
    // disconnected (the socket closes).
    self.handleAuthenticationKick(client, 1000);
  },


  /**
  * The client must authenticate himself
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Socket} client    The socket in question
  * @param  {int}    countdown Time before he gets disconnected (ms)
  */
  handleAuthenticationKick: function (client, countdown) {
    setTimeout(function () {
      if (!client.isAuthenticated) {
        console.log('Sockets: client disconnected');
        client.disconnect({message: 'No authentication request received'});
      }
    }, countdown);
  },


  /**
  * Register public events here (events that doesnt need authentication).
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Socket} client The client socket
  */
  registerPublicEvents: function (client) {
    // Listen for the authenticate request
    console.log('Sockets: new connection');

    client.on('authenticate', function (data) {
      // Use the authentiction middleware to authenticate the provided token
      auth.validateToken(data.token).then(function (decoded) {
        // The token was decoded (authentication success)
        client.isAuthenticated = true;
        // Save the user object to the socket for later reference
        client.user = decoded;
        console.log('Sockets: ', client.user.email, 'is now authenticated');

        // Since we now are authenticated, we can register the event handlers
        // that requires authenticated users.
        self.registerAuthenticatedEvents(client);

        // Send the success
        client.emit('authenticated', {message: 'Authenticated'});
      }, function (reason) {
        // The token was not in the token cache
        client.disconnect();
      });
    });
  },


  /**
  * Register private events here (event that require authentication)
  * @author Johan Kanefur <johan.kanefur@solidio.se>
  * @param  {Socket} client The client socket
  */
  registerAuthenticatedEvents: function (client) {

  },
};
