const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const winston = require('winston');

// Access the logger configured in app.js
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'auth-controller' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Helper function to create and send token response
const createSendToken = (user, statusCode, res) => {
  // Generate JWT token
  const token = jwt.sign(
    { _id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRATION || '24h' }
  );

  // Calculate expiration time
  const expiresIn = parseInt(process.env.JWT_EXPIRATION) || 86400; // Default to 24 hours in seconds
  const expiryDate = new Date(Date.now() + expiresIn * 1000);

  // Add token to user's tokens array
  user.tokens = user.tokens || [];
  user.tokens.push({ token, expires: expiryDate });
  user.save({ validateBeforeSave: false });

  // Set cookie options
  const cookieOptions = {
    expires: expiryDate,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' // Helps prevent CSRF attacks
  };

  // Send token via cookie and JSON response
  res.cookie('token', token, cookieOptions);
  
  // Don't send password in response
  const userObj = user.toJSON();

  res.status(statusCode).json({
    success: true,
    token,
    expiresIn: expiresIn,
    user: userObj
  });
};

/**
 * @desc   Register new user
 * @route  POST /api/auth/register
 * @access Public
 */
exports.register = async (req, res) => {
  try {
    // Validate and sanitize input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { username, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with that email or username already exists'
      });
    }

    // Create new user with default role and active status
    const user = await User.create({
      username,
      email,
      password,
      accountStatus: 'active', // Set to active by default, consider using email verification
      role: 'user'
    });

    // Log the successful registration
    logger.info(`New user registered: ${user.email}`);

    // Create token and send response
    createSendToken(user, 201, res);
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error registering user',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Login user
 * @route  POST /api/auth/login
 * @access Public
 */
exports.login = async (req, res) => {
  try {
    // Validate and sanitize input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }

    // Find user by credentials - this uses our custom static method in the User model
    // which handles account locking and tracking failed login attempts
    try {
      const user = await User.findByCredentials(email, password);
      
      // Record successful login
      await user.recordLogin();

      // Create token and send response
      createSendToken(user, 200, res);
      
      logger.info(`User logged in: ${user.email}`);
    } catch (error) {
      // findByCredentials already records failed login attempts
      logger.warn(`Failed login attempt for email: ${email} - ${error.message}`);
      
      return res.status(401).json({
        success: false,
        message: error.message
      });
    }
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error logging in',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Logout user from current device
 * @route  POST /api/auth/logout
 * @access Private
 */
exports.logout = async (req, res) => {
  try {
    // Get the current token from request
    const currentToken = req.token;
    
    // Filter out the current token
    req.user.tokens = req.user.tokens.filter(
      tokenObj => tokenObj.token !== currentToken
    );
    
    await req.user.save();

    logger.info(`User logged out: ${req.user.email}`);

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    logger.error(`Logout error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error logging out',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Logout user from all devices
 * @route  POST /api/auth/logoutAll
 * @access Private
 */
exports.logoutAll = async (req, res) => {
  try {
    // Clear all tokens
    req.user.tokens = [];
    await req.user.save();

    logger.info(`User logged out from all devices: ${req.user.email}`);

    res.status(200).json({
      success: true,
      message: 'Logged out from all devices successfully'
    });
  } catch (error) {
    logger.error(`Logout all error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error logging out from all devices',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Get current user profile
 * @route  GET /api/auth/me
 * @access Private
 */
exports.getCurrentUser = async (req, res) => {
  try {
    // User is already attached to req by auth middleware
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (error) {
    logger.error(`Get current user error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching user profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Forgot password - send reset token
 * @route  POST /api/auth/forgotPassword
 * @access Public
 */
exports.forgotPassword = async (req, res) => {
  try {
    // Validate and sanitize input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Hash token and set to passwordResetToken field
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // Set token expiry to 10 minutes from now
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000;

    await user.save({ validateBeforeSave: false });

    // In a real application, send email with reset token/link
    // For this example, we'll just log it
    logger.info(`Password reset token for ${email}: ${resetToken}`);

    // In a production environment, you would use:
    // await sendPasswordResetEmail(user, resetToken);

    res.status(200).json({
      success: true,
      message: 'Password reset token sent successfully',
      // Only return token in development for testing
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
  } catch (error) {
    logger.error(`Forgot password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error sending password reset token',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Reset password
 * @route  POST /api/auth/resetPassword/:token
 * @access Public
 */
exports.resetPassword = async (req, res) => {
  try {
    // Validate and sanitize input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { password } = req.body;
    const { token } = req.params;

    // Hash the token to compare with stored token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user by reset token and check if token is expired
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Token is invalid or has expired'
      });
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    
    // Invalidate all current tokens (force re-login after password reset)
    user.tokens = [];

    await user.save();

    logger.info(`Password reset successful for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Password reset successful'
    });
  } catch (error) {
    logger.error(`Reset password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error resetting password',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Refresh token
 * @route  POST /api/auth/refreshToken
 * @access Private
 */
exports.refreshToken = async (req, res) => {
  try {
    // Get current user from middleware
    const user = req.user;
    
    // Remove current token
    const currentToken = req.token;
    user.tokens = user.tokens.filter(
      tokenObj => tokenObj.token !== currentToken
    );
    
    // Create and send new token
    createSendToken(user, 200, res);
    
    logger.info(`Token refreshed for user: ${user.email}`);
  } catch (error) {
    logger.error(`Refresh token error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error refreshing token',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc   Update user password
 * @route  PUT /api/auth/updatePassword
 * @access Private
 */
exports.updatePassword = async (req, res) => {
  try {
    // Validate and sanitize input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');

    // Check if current password is correct
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    
    // Invalidate all other tokens
    user.tokens = user.tokens.filter(
      tokenObj => tokenObj.token === req.token
    );

    await user.save();

    logger.info(`Password updated for user: ${user.email}`);

    // Log user in with new token
    createSendToken(user, 200, res);
  } catch (error) {
    logger.error(`Update password error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error updating password',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

