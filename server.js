require('dotenv').config();

const express = require('express');

const cookieParser = require('cookie-parser');


const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const path = require('path');

const app = express();

// --- CORS: Allow credentials for session-based auth ---
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://65.0.107.174:3000', // Your frontend
  credentials: true
}));

// app.use(express.json());
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(cookieParser());
const authRoutes = require('./routes/auth');




// --- Session setup for Passport (required for login sessions) ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'MySuperSecretKey1234567890!@$%^&*', // Use .env in prod
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true only with HTTPS
}));

require('./config/passportSetup');






// --- Passport.js session setup ---
app.use(passport.initialize());
app.use(passport.session());

// // --- Passport: serialize/deserialize user for session support ---
// passport.serializeUser((user, done) => done(null, user));
// passport.deserializeUser((user, done) => done(null, user));

app.use('/api/auth', authRoutes);

// --- Routes ---
const oauthRoutes = require('./routes/oauth');
app.use('/api/auth', oauthRoutes);
// Add your other auth routes here (OTP, signup, login, etc.)

// --- MongoDB Connection (using your .env variable and correct DB name) ---
  const PORT = process.env.PORT || 5000;
  mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected')
    console.log("Mongo_UURI",process.env.MONGO_URI);
    app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  process.exit(1); // Exit the process if DB connection fails
});

//   // Serve static files from the React app
// app.use(express.static(path.join(__dirname, '../frontend/build')));

// // Catchall: send React's index.html for any route not starting with /api
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, '../frontend/build', 'index.html'));
// });

// --- Start Server ---

// --- Root route ---

app.get('/', (req,res)=>{
  res.send('Backend is running!');
});

// --- Status route---

app.get('/status', (req,res)=>{
res.json({status: 'OK', message:"Backend is healthy!"});
});

