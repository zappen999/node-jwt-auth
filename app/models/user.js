var mongoose = require('mongoose');
var shortid = require('shortid');
var uuid = require('uuid');
var Schema = mongoose.Schema;

module.exports = mongoose.model('User', new Schema({
  id: {
    type: String,
    unique: true,
    index: true,
    'default': shortid.generate
  },
  accessid: {
    type: String,
    unique: true,
    'default': uuid.v4
  },
  accesscodes: [ String ], // Multiple valid hashes
  password: String,
  invitecode: {
    type: String,
    unique: true,
    'default': uuid.v4
  },
  email: String,
  name: String,
  role: {type: Number, max: 10},
}, {
  timestamps: true
}));
