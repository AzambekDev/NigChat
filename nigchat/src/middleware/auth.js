const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { promisify } = require('util');
const User = require('../models/User');

/**
 * Rate limiter specifically for authentication endpoints to prevent brute force attacks
 * More restrictive than the general API rate limiter
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  skipSuccessfulRequests: true, // Don't count successful attempts against the rate limit
});

/**
 * Main authentication middleware
 * Verifies JWT token and attaches user to request object
 */
const auth = async (req, res, next) => {
  try {
    // Get token from authorization header
    let token;
    if (
      req.headers.authorization && 
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
      // Also check cookies for token if not in header
      token = req.cookies.token;
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Not authorized to access this route' 
      });
    }

    // Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // Find user by ID and check if user still exists
    const user = await User.findById(decoded._id);
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'The user belonging to this token no longer exists' 
      });
    }

    // Check if token is in user's valid tokens array
    const isValidToken = user.tokens.some(
      (tokenObj) => tokenObj.token === token && tokenObj.expires > new Date()
    );

    if (!isValidToken) {
      return res.status(401).json({ 
        success: false, 
        message: 'Token is invalid or has expired' 
      });
    }

    // Check account status
    if (user.accountStatus !== 'active') {
      return res.status(403).json({ 
        success: false, 
        message: `Your account is ${user.accountStatus}. Please contact support.` 
      });
    }

    // Clean up expired tokens
    await user.cleanupExpiredTokens();

    // Attach user to request object
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token. Please log in again' 
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Your token has expired. Please log in again' 
      });
    }
    
    console.error('Authentication error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during authentication' 
    });
  }
};

/**
 * Role-based access control middleware
 * @param {string[]} roles - Array of allowed roles
 * @returns {Function} Middleware function
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    // Role check (assuming user has a 'role' field)
    // If not implemented yet, you can add a role field to the User model
    if (!req.user.role || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `User role ${req.user.role || 'undefined'} is not authorized to access this route`
      });
    }
    next();
  };
};

/**
 * Middleware to apply security headers specifically for authentication routes
 */
const authSecurityHeaders = (req, res, next) => {
  // Set various security headers
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('X-Frame-Options', 'DENY');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  next();
};

module.exports = {
  auth,
  authorize,
  authLimiter,
  authSecurityHeaders
};

