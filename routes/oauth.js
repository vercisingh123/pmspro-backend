const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // Adjust path if needed

// --- Google OAuth Routes ---
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    console.log("inside google callback",req.user);
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '2h' });
    console.log("token", token);
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict' });
    res.redirect(process.env.FRONTEND_URL + '/dashboard');
  }
);

// --- GitHub OAuth Routes ---
router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get('/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict' });
    res.redirect(process.env.FRONTEND_URL + '/dashboard');
  }
);

module.exports = router;

