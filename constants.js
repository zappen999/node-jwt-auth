// @boilerplate: Add your static configuration here
var constants = {
  SECRET: 'O6MSV2k3i9zOTRytMwETZ2ddD10uZLKCiX3UsNbR',
  SYSTEM_EMAIL: 'noreply@node-jwt-auth.com',
  ROLES: {
    GUEST: 0,
    INACTIVE: 1,
    USER: 2,
    MODERATOR: 3,
    ADMIN: 4
  },
  SENDGRID_APIKEY: 'your_sendgrid_apikey'
};

module.exports = constants;
