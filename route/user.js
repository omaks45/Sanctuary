const express = require('express')
const router = express.Router()
const passport = require('passport')
const {signup} = require('../controller/user')
const {check} = require('express-validator')


router.post('/signup',  [
    check("name", "Name atleast should be 3 characters").isLength({min: 3}),
    check("email", "Email should be valid").isEmail(),
    check("password", "Password at least should be 6 characters").isLength({min: 6}),
  ] ,signup)

// Initialize Passport and restore authentication state from session
router.use(passport.initialize());
router.use(passport.session());

// Google OAuth authentication route
router.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['https://www.googleapis.com/auth/plus.login', 'https://www.googleapis.com/auth/userinfo.email'],
  })
);

// Google OAuth callback route
router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Successful authentication, redirect to the home page or handle as needed
    res.redirect('/');
  }
);

// Logout route
router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});


module.exports = router;
