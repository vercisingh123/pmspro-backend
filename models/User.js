const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, required: true, unique: true },
  password: String,
  isVerified: { type: Boolean, default: false },
  googleId: { type: String },
githubId: { type: String },

});

module.exports = mongoose.model('User', userSchema);
