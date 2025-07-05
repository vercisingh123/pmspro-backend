const passport = require('passport');


const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User');
const OTP = require('../models/OTP');
const { generateOTP, sendOTP } = require('../utils/otp');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET 

// --- JWT Middleware ---
function authenticateJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.log("Error: ", err);
    return res.status(403).json({ error: 'Invalid token' });

  }
}

// --- SIGNUP: Step 1 - Send OTP ---
router.post('/send-otp-signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

  let user = await User.findOne({ email });
  if (user) return res.status(400).json({ error: 'Email already registered' });

  const hashedPassword = await bcrypt.hash(password, 10);
  user = await User.create({ name, email, password: hashedPassword, isVerified: false });
const user1 = await User.findOne({ email });
console.log("User1 is found.", user1);
  const otp = generateOTP();
  
 console.log("OTP for", email, "is:", otp);
  const hashedOtp = await bcrypt.hash(otp, 10);

  await OTP.create({ email, otp: hashedOtp });
  await sendOTP(email, otp);

  res.json({ message: 'OTP sent to email. Please verify your account.' });
});

// --- SIGNUP: Step 2 - Verify OTP ---
router.post('/verify-otp-signup', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });

  const otpRecord = await OTP.findOne({ email }).sort({ createdAt: -1 });
  if (!otpRecord) return res.status(400).json({ error: 'OTP not found or expired' });

  const isValid = await bcrypt.compare(otp, otpRecord.otp);
  if (!isValid) return res.status(400).json({ error: 'Invalid OTP' });

  user.isVerified = true;
  await user.save();
  await OTP.deleteMany({ email });

  res.json({ message: 'Account verified. Please log in.' });
});

// --- LOGIN: Step 1 - Attempt Login ---
router.post('/send-otp-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) return res.status(400).json({ error: 'Invalid password' });

  if (!user.isVerified) {
    // Send OTP for verification
    const otp = generateOTP();
     console.log("OTP for", email, "is:", otp);
    const hashedOtp = await bcrypt.hash(otp, 10);
    await OTP.create({ email, otp: hashedOtp });
    await sendOTP(email, otp);
    return res.status(401).json({ error: 'Account not verified. Please complete OTP verification.' });
  }

  // --- JWT Creation and Cookie Setting ---
  const payload = { email };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });

  // Save 
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict' });

  res.json({ message: 'Authenticated', user: { email } });
});

// --- LOGIN: Step 2 - Verify OTP and Log In ---
router.post('/verify-otp-login', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });

  const otpRecord = await OTP.findOne({ email }).sort({ createdAt: -1 });
  if (!otpRecord) return res.status(400).json({ error: 'OTP not found or expired' });

  const isValid = await bcrypt.compare(otp, otpRecord.otp);
  if (!isValid) return res.status(400).json({ error: 'Invalid OTP' });

  user.isVerified = true;
  await user.save();
  await OTP.deleteMany({ email });

  // --- JWT Creation and Cookie Setting ---
  const payload = { email };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict' });

  res.json({ message: 'Authenticated', user: { email } });
});

// --- PROTECTED ROUTE: Dashboard Data ---
router.get('/dashboard-data', authenticateJWT, (req, res) => {
  res.json({ email: req.user.email });
});

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));





// --- LOGOUT: Clear JWT Cookie ---
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

module.exports = router;
