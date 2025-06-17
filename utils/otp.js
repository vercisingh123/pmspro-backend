const nodemailer = require('nodemailer');

exports.generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

exports.sendOTP = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your PMS Pro OTP',
    text: `Your OTP is: ${otp}`
  });
};
