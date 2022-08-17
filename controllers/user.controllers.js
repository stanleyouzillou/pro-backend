const crypto = require('crypto');
const User = require('../models/User');
//
// /forgot-password

async function resetPassword(req, res, next) {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    const resetPasswordToken = await User.generateForgotPasswordToken();
    email.send(resetPasswordToken);
  } catch (error) {}
}

// /verif-password

async function verifPasswordToken(req, res, next) {
  const newPassword = req.body.password;
  const token = req.body.passwordToken;
  const hashedToken = await crypto.createHash('sha256').update(token).digest('hex');

  const user = User.findOne({forgotPasswordTaken: hashedToken });

  if (user && Date.now() <= user.forgotPasswordExpiry) {
    user.password = password;
    user.forgotPasswordTaken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save();
  }

}
