const crypto = require('crypto')
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Provide a name'],
    minLength: [3, 'Name should be at least 3 char'],
  },
  password: {
    type: String,
    required: [true, 'Provide a password'],
    select: false,
  },
  email: {
    type: String,
    required: [true, 'Provide an email'],
    validate: [validator.isEmail(v), 'Should be email format'],
    unique: true,
  },
  role: {
    type: String,
    default: 'user',
  },
  photo: {
    id: {
      type: String,
      required: true,
    },
    secure_url: {
      type: String,
      required: true,
    },
  },
  forgotPasswordTaken: String,
  forgotPasswordExpiry: Date,
  createdAt: {
    type: Date,
    default: Date.now(),
  },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.isPasswordValidated = async function (loginPassword) {
  return await bcrypt.compare(loginPassword, this.password);
};

userSchema.methods.generateForgotPasswordToken = async function() {
  const passwordToken = crypto.randomBytes(32).toString('hex');
  this.forgotPasswordTaken = crypto.createHash('sha256').update(crypto).digest('hex');
  this.forgotPasswordExpiry = Date.now() + 30 * 60 * 1000 // 30m
  this.save();
  return passwordToken;
}

user.methods.generateJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, 
    {expiresIn: process.env.JWT_EXPIRY);}
};

module.exports = mongoose.model('User', userSchema);
