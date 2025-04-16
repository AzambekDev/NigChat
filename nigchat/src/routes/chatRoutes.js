const express = require('express');
const { check } = require('express-validator');
const rateLimit = require('express-rate-limit');
const chatController = require('../controllers/chatController');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Apply authentication middleware to all chat routes
router.use(auth);

// Message rate limiter to prevent spam
const messageLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: 30, // limit each IP to 30 messages per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many messages sent, please try again after a minute',
  skipSuccessfulRequests: false
});

// Room Management Routes

/**
 * @route   GET /api/chat/rooms
 * @desc    Get all available chat rooms
 * @access  Private
 */
router.get('/rooms', chatController.getRooms);

/**
 * @route   POST /api/chat/rooms
 * @desc    Create a new chat room
 * @access  Private
 */
router.post('/rooms', [
  check('roomName')
    .trim()
    .notEmpty().withMessage('Room name is required')
    .isLength({ min: 3, max: 30 }).withMessage('Room name must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9-_]+$/).withMessage('Room name can only contain letters, numbers, hyphens, and underscores')
    .escape(),
  
  check('description')
    .trim()
    .optional()
    .isLength({ max: 200 }).withMessage('Description cannot exceed 200 characters')
    .escape(),
  
  check('isPrivate')
    .optional()
    .isBoolean().withMessage('isPrivate must be a boolean value')
], chatController.createRoom);

/**
 * @route   POST /api/chat/rooms/:roomId/join
 * @desc    Join a chat room
 * @access  Private
 */
router.post('/rooms/:roomId/join', [
  check('roomId')
    .trim()
    .notEmpty().withMessage('Room ID is required')
    .matches(/^[a-zA-Z0-9-_]+$/).withMessage('Room ID can only contain letters, numbers, hyphens, and underscores')
    .escape()
], chatController.joinRoom);

/**
 * @route   POST /api/chat/rooms/:roomId/leave
 * @desc    Leave a chat room
 * @access  Private
 */
router.post('/rooms/:roomId/leave', [
  check('roomId')
    .trim()
    .notEmpty().withMessage('Room ID is required')
    .matches(/^[a-zA-Z0-9-_]+$/).withMessage('Room ID can only contain letters, numbers, hyphens, and underscores')
    .escape()
], chatController.leaveRoom);

// Messaging Routes

/**
 * @route   GET /api/chat/rooms/:roomId/messages
 * @desc    Get messages for a room
 * @access  Private
 */
router.get('/rooms/:roomId/messages', [
  check('roomId')
    .trim()
    .notEmpty().withMessage('Room ID is required')
    .matches(/^[a-zA-Z0-9-_]+$/).withMessage('Room ID can only contain letters, numbers, hyphens, and underscores')
    .escape(),
  
  check('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  
  check('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], chatController.getMessages);

/**
 * @route   POST /api/chat/rooms/:roomId/messages
 * @desc    Send a message to a room
 * @access  Private
 */
router.post('/rooms/:roomId/messages', [
  messageLimiter, // Apply rate limiting to message sending
  
  check('roomId')
    .trim()
    .notEmpty().withMessage('Room ID is required')
    .matches(/^[a-zA-Z0-9-_]+$/).withMessage('Room ID can only contain letters, numbers, hyphens, and underscores')
    .escape(),
  
  check('content')
    .trim()
    .notEmpty().withMessage('Message content is required')
    .isLength({ max: 2000 }).withMessage('Message cannot exceed 2000 characters'),
  
  check('messageType')
    .optional()
    .isIn(['text', 'system', 'image', 'file', 'notification']).withMessage('Invalid message type')
], chatController.sendMessage);

/**
 * @route   PUT /api/chat/messages/:messageId
 * @desc    Edit a message
 * @access  Private
 */
router.put('/messages/:messageId', [
  check('messageId')
    .trim()
    .notEmpty().withMessage('Message ID is required')
    .isMongoId().withMessage('Invalid message ID format'),
  
  check('content')
    .trim()
    .notEmpty().withMessage('Message content is required')
    .isLength({ max: 2000 }).withMessage('Message cannot exceed 2000 characters')
], chatController.editMessage);

/**
 * @route   DELETE /api/chat/messages/:messageId
 * @desc    Delete a message (soft delete)
 * @access  Private
 */
router.delete('/messages/:messageId', [
  check('messageId')
    .trim()
    .notEmpty().withMessage('Message ID is required')
    .isMongoId().withMessage('Invalid message ID format')
], (req, res) => {
  // This route handler is not yet implemented in the controller
  // You will need to implement the corresponding controller method
  res.status(501).json({
    success: false,
    message: 'Message deletion not implemented yet'
  });
});

module.exports = router;

