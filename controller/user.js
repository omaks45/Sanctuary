const User = require('../models/user');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt')

const signup = async (req, res) => {
  try {
    // Extract user input from the request body
    const { email, password, confirmPassword } = req.body;

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match.' });
    }

    // Create a new user instance using the User model
    const newUser = new User({
      email,
      password,
      confirmPassword, // This field is virtual and not stored in the database
    });

    // Save the user to the database
    const savedUser = await newUser.save();

    res.status(201).json({ success: true, user: savedUser });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
};


// Use the GoogleStrategy with Passport
passport.use(
  new GoogleStrategy(
    {
      clientID: '950620274499-nm8dj1a0rv790s04uaaqsu43j8m3ke55.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: 'http://localhost:3000/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if the user already exists in the database
        let user = await User.findOne({ email: profile.emails[0].value });

        // If the user doesn't exist, create a new user
        if (!user) {
          user = new User({
            email: profile.emails[0].value,
            // You may want to generate a random password for Google signups
            password: await bcrypt.hash(profile.id, 10),
          });

          await user.save();
        }

        return done(null, user);
      } catch (error) {
        console.error('Error during Google authentication:', error);
        return done(error, null);
      }
    }
  )
);

// Serialize user into the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});


module.exports = {  signup };