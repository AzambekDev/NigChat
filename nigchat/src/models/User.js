const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    validate: {
      validator: function(value) {
        // Allow only alphanumeric characters and underscores
        return /^[a-zA-Z0-9_]+$/.test(value);
      },
      message: 'Username can only contain letters, numbers, and underscores'
    }
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: validator.isEmail,
      message: 'Please provide a valid email address'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't return password by default in queries
  },
  lastLogin: {
    type: Date,
    default: null
  },
  accountStatus: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending'],
    default: 'pending'
  },
  tokens: [{
    token: {
      type: String,
      required: true
    },
    expires: {
      type: Date,
      required: true
    }
  }],
  passwordResetToken: String,
  passwordResetExpires: Date,
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  accountLocked: {
    type: Boolean,
    default: false
  },
  accountLockedUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt
  toJSON: { 
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.tokens;
      delete ret.passwordResetToken;
      delete ret.passwordResetExpires;
      return ret;
    }
  }
});

// Pre-save hook to hash password before saving
UserSchema.pre('save', async function(next) {
  const user = this;
  
  // Only hash the password if it's modified or new
  if (!user.isModified('password')) return next();
  
  try {
    // Generate salt rounds from environment variable or use default
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    
    // Hash the password
    const hash = await bcrypt.hash(user.password, saltRounds);
    
    // Replace plaintext password with hashed password
    user.password = hash;
    next();
  } catch (error) {
    return next(error);
  }
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error(error);
  }
};

// Method to generate JWT token
UserSchema.methods.generateAuthToken = async function() {
  const user = this;
  
  // Get JWT configuration from environment variables
  const jwtSecret = process.env.JWT_SECRET;
  const jwtExpiration = process.env.JWT_EXPIRATION || '24h';
  
  // Create token with user id
  const token = jwt.sign(
    { _id: user._id.toString() }, 
    jwtSecret, 
    { expiresIn: jwtExpiration }
  );
  
  // Calculate expiration date
  const expiresIn = parseInt(jwtExpiration) || 86400; // Default to 24 hours in seconds
  const expiryDate = new Date(Date.now() + expiresIn * 1000);
  
  // Add token to user's tokens array
  user.tokens = user.tokens || [];
  user.tokens.push({ token, expires: expiryDate });
  
  // Save user with new token
  await user.save();
  
  return token;
};

// Method to remove expired tokens
UserSchema.methods.cleanupExpiredTokens = async function() {
  const user = this;
  const currentDate = new Date();
  
  // Filter out expired tokens
  const validTokens = user.tokens.filter(tokenObj => tokenObj.expires > currentDate);
  
  // If there are expired tokens, update and save
  if (validTokens.length !== user.tokens.length) {
    user.tokens = validTokens;
    await user.save();
  }
  
  return user;
};

// Method to record login
UserSchema.methods.recordLogin = async function() {
  const user = this;
  user.lastLogin = new Date();
  user.failedLoginAttempts = 0;
  await user.save();
};

// Method to record failed login
UserSchema.methods.recordFailedLogin = async function() {
  const user = this;
  user.failedLoginAttempts += 1;
  
  // Lock account after 5 failed attempts
  if (user.failedLoginAttempts >= 5) {
    user.accountLocked = true;
    // Lock for 30 minutes
    user.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
  }
  
  await user.save();
};

// Static method to find user by credentials
UserSchema.statics.findByCredentials = async function(email, password) {
  // Find user by email
  const user = await this.findOne({ email }).select('+password');
  
  if (!user) {
    throw new Error('Invalid login credentials');
  }
  
  // Check if account is locked
  if (user.accountLocked) {
    const now = new Date();
    if (user.accountLockedUntil && user.accountLockedUntil > now) {
      const minutesLeft = Math.ceil((user.accountLockedUntil - now) / (60 * 1000));
      throw new Error(`Account is locked. Try again in ${minutesLeft} minutes.`);
    } else {
      // Unlock account if lock period has passed
      user.accountLocked = false;
      user.failedLoginAttempts = 0;
      await user.save();
    }
  }
  
  // Check password
  const isMatch = await user.comparePassword(password);
  
  if (!isMatch) {
    await user.recordFailedLogin();
    throw new Error('Invalid login credentials');
  }
  
  return user;
};

const User = mongoose.model('User', UserSchema);

module.exports = User;

