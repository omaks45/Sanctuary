const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6, // Adjust the minimum length as needed
  },
});

// Virtual field for confirm password (not stored in the database)
userSchema.virtual('confirmPassword', {
  type: String,
  required: true,
  validate: {
    validator: function (value) {
      // Check if confirm password matches password
      return value === this.password;
    },
    message: 'Passwords do not match.',
  },
});

// Hash the password before saving it to the database
userSchema.pre('save', async function (next) {
  const saltRounds = 10;
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, saltRounds);
  }
  next();
});

// Method to compare passwords during login
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
