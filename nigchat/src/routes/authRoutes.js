const express = require('express');
const { check } = require('express-validator');
const authController = require('../controllers/authController');
const { auth, authLimiter, authSecurityHeaders } = require('../middleware/auth');

const router = express.Router();

// Apply security headers to all auth routes
router.use(authSecurityHeaders);

// Registration endpoint with validation
router.post('/register', 
  [
    // Username validation
    check('username')
      .trim()
      .notEmpty().withMessage('Username is required')
      .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters')
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores')
      .escape(),
    
    // Email validation
    check('email')
      .trim()
      .notEmpty().withMessage('Email is required')
      .isEmail().withMessage('Please provide a valid email address')
      .normalizeEmail(),
    
    // Password validation
    check('password')
      .trim()
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/\d/).withMessage('Password must contain at least one number')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character')
  ],
  authController.register
);

// Login endpoint with rate limiting and validation
router.post('/login', 
  authLimiter, // Apply rate limiting to prevent brute force attacks
  [
    check('email')
      .trim()
      .notEmpty().withMessage('Email is required')
      .isEmail().withMessage('Please provide a valid email address')
      .normalizeEmail(),
    
    check('password')
      .trim()
      .notEmpty().withMessage('Password is required')
  ],
  authController.login
);

// Logout (current device) - requires authentication
router.post('/logout', auth, authController.logout);

// Logout from all devices - requires authentication
router.post('/logoutAll', auth, authController.logoutAll);

// Get current user profile - requires authentication
router.get('/me', auth, authController.getCurrentUser);

// Forgot password endpoint with validation
router.post('/forgotPassword',
  [
    check('email')
      .trim()
      .notEmpty().withMessage('Email is required')
      .isEmail().withMessage('Please provide a valid email address')
      .normalizeEmail()
  ],
  authController.forgotPassword
);

// Reset password endpoint with validation
router.post('/resetPassword/:token',
  [
    check('password')
      .trim()
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/\d/).withMessage('Password must contain at least one number')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character'),
    
    check('confirmPassword')
      .trim()
      .notEmpty().withMessage('Please confirm your password')
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error('Passwords do not match');
        }
        return true;
      })
  ],
  authController.resetPassword
);

// Refresh token - requires authentication
router.post('/refreshToken', auth, authController.refreshToken);

// Update password - requires authentication
router.put('/updatePassword', 
  auth,
  [
    check('currentPassword')
      .notEmpty().withMessage('Current password is required'),
    
    check('newPassword')
      .trim()
      .notEmpty().withMessage('New password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/\d/).withMessage('Password must contain at least one number')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
      .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character')
      .custom((value, { req }) => {
        if (value === req.body.currentPassword) {
          throw new Error('New password cannot be the same as current password');
        }
        return true;
      }),
    
    check('confirmPassword')
      .trim()
      .notEmpty().withMessage('Please confirm your new password')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Passwords do not match');
        }
        return true;
      })
  ],
  authController.updatePassword
);

module.exports = router;

