const { validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');
const Message = require('../models/Message');
const User = require('../models/User');

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'chat-controller' },
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

// Maintain active room data in memory
// In a production environment, consider using Redis for distributed deployments
const activeRooms = new Map();

/**
 * @desc    Create a new chat room
 * @route   POST /api/chat/rooms
 * @access  Private
 */
exports.createRoom = async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false, 
        errors: errors.array()
      });
    }

    const { roomName, description, isPrivate } = req.body;
    const creator = req.user._id;

    // Check if the room already exists (by name)
    if (activeRooms.has(roomName)) {
      return res.status(400).json({
        success: false,
        message: 'A room with this name already exists'
      });
    }

    // Create room data structure
    const roomData = {
      id: roomName,
      name: roomName,
      description: sanitizeHtml(description, {
        allowedTags: [],
        allowedAttributes: {}
      }),
      creator,
      isPrivate: isPrivate || false,
      members: [creator],
      createdAt: new Date(),
      admins: [creator]
    };

    // Store room in active rooms
    activeRooms.set(roomName, roomData);

    logger.info(`Room created: ${roomName} by user: ${req.user.username}`);

    res.status(201).json({
      success: true,
      room: roomData
    });
  } catch (error) {
    logger.error(`Create room error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error creating chat room',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Get all available chat rooms
 * @route   GET /api/chat/rooms
 * @access  Private
 */
exports.getRooms = async (req, res) => {
  try {
    // Filter private rooms if user is not a member
    const userId = req.user._id;
    const availableRooms = Array.from(activeRooms.values()).filter(room => {
      // Include room if it's public or if user is a member
      return !room.isPrivate || room.members.some(member => member.toString() === userId.toString());
    });

    res.status(200).json({
      success: true,
      count: availableRooms.length,
      rooms: availableRooms
    });
  } catch (error) {
    logger.error(`Get rooms error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error fetching chat rooms',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Join a chat room
 * @route   POST /api/chat/rooms/:roomId/join
 * @access  Private
 */
exports.joinRoom = async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user._id;

    // Check if room exists
    if (!activeRooms.has(roomId)) {
      return res.status(404).json({
        success: false,
        message: 'Chat room not found'
      });
    }

    const room = activeRooms.get(roomId);

    // Check if user is already a member
    if (room.members.some(member => member.toString() === userId.toString())) {
      return res.status(400).json({
        success: false,
        message: 'You are already a member of this room'
      });
    }

    // Check if room is private
    if (room.isPrivate) {
      // In a real application, handle invitation system
      return res.status(403).json({
        success: false,
        message: 'This is a private room. You need an invitation to join.'
      });
    }

    // Add user to room members
    room.members.push(userId);
    activeRooms.set(roomId, room);

    // Emit socket event to notify room of new member
    // This would be handled by the Socket.IO implementation
    // io.to(roomId).emit('user:joined', { userId, username: req.user.username });

    logger.info(`User ${req.user.username} joined room: ${roomId}`);

    res.status(200).json({
      success: true,
      message: `Successfully joined room: ${room.name}`,
      room
    });
  } catch (error) {
    logger.error(`Join room error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error joining chat room',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Leave a chat room
 * @route   POST /api/chat/rooms/:roomId/leave
 * @access  Private
 */
exports.leaveRoom = async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user._id;

    // Check if room exists
    if (!activeRooms.has(roomId)) {
      return res.status(404).json({
        success: false,
        message: 'Chat room not found'
      });
    }

    const room = activeRooms.get(roomId);

    // Check if user is a member
    if (!room.members.some(member => member.toString() === userId.toString())) {
      return res.status(400).json({
        success: false,
        message: 'You are not a member of this room'
      });
    }

    // Remove user from room members
    room.members = room.members.filter(member => member.toString() !== userId.toString());
    
    // If user is an admin, remove from admins list
    if (room.admins.some(admin => admin.toString() === userId.toString())) {
      room.admins = room.admins.filter(admin => admin.toString() !== userId.toString());
    }

    // If room has no members left, consider removing it
    if (room.members.length === 0) {
      activeRooms.delete(roomId);
      logger.info(`Room ${roomId} deleted as last member left`);
    } else {
      activeRooms.set(roomId, room);
    }

    // Emit socket event to notify room that user left
    // This would be handled by the Socket.IO implementation
    // io.to(roomId).emit('user:left', { userId, username: req.user.username });

    logger.info(`User ${req.user.username} left room: ${roomId}`);

    res.status(200).json({
      success: true,
      message: `Successfully left room: ${room.name}`
    });
  } catch (error) {
    logger.error(`Leave room error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error leaving chat room',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Send a message to a room
 * @route   POST /api/chat/rooms/:roomId/messages
 * @access  Private
 */
exports.sendMessage = async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false, 
        errors: errors.array()
      });
    }

    const { roomId } = req.params;
    const { content, messageType = 'text' } = req.body;
    const userId = req.user._id;

    // Check if room exists
    if (!activeRooms.has(roomId)) {
      return res.status(404).json({
        success: false,
        message: 'Chat room not found'
      });
    }

    const room = activeRooms.get(roomId);

    // Check if user is a member of the room
    if (!room.members.some(member => member.toString() === userId.toString())) {
      return res.status(403).json({
        success: false,
        message: 'You must be a member of the room to send messages'
      });
    }

    // Sanitize content - this is also done in the model, but we do it here for extra security
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: ['b', 'i', 'em', 'strong', 'a', 'code'],
      allowedAttributes: {
        'a': ['href', 'target']
      }
    });

    // Create message in database
    const message = await Message.create({
      sender: userId,
      roomId,
      content: sanitizedContent,
      messageType,
      timestamp: new Date()
    });

    // Populate sender information for response
    await message.populate('sender', 'username');

    // Emit socket event to broadcast message to room
    // This would be handled by the Socket.IO implementation
    // io.to(roomId).emit('message:new', message);

    logger.info(`Message sent to room ${roomId} by user ${req.user.username}`);

    res.status(201).json({
      success: true,
      message
    });
  } catch (error) {
    logger.error(`Send message error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error sending message',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Get messages for a room
 * @route   GET /api/chat/rooms/:roomId/messages
 * @access  Private
 */
exports.getMessages = async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user._id;
    
    // Pagination parameters
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 50;
    const startIndex = (page - 1) * limit;

    // Check if room exists
    if (!activeRooms.has(roomId)) {
      return res.status(404).json({
        success: false,
        message: 'Chat room not found'
      });
    }

    const room = activeRooms.get(roomId);

    // Check if user is a member of the room
    if (!room.members.some(member => member.toString() === userId.toString())) {
      return res.status(403).json({
        success: false,
        message: 'You must be a member of the room to view messages'
      });
    }

    // Get total messages count for pagination
    const totalMessages = await Message.countDocuments({ 
      roomId, 
      isDeleted: false 
    });

    // Get messages with pagination, sorted by timestamp (newest first)
    const messages = await Message.find({ 
      roomId, 
      isDeleted: false 
    })
      .sort({ timestamp: -1 })
      .skip(startIndex)
      .limit(limit)
      .populate('sender', 'username')
      .populate('readBy.userId', 'username');

    // Mark messages as read by this user
    await Promise.all(messages.map(message => message.markAsReadBy(userId)));

    // Pagination result
    const pagination = {
      currentPage: page,
      totalPages: Math.ceil(totalMessages / limit),
      totalMessages,
      limit
    };

    res.status(200).json({
      success: true,
      count: messages.length,
      pagination,
      messages: messages.reverse() // Reverse to get oldest first for client display
    });
  } catch (error) {
    logger.error(`Get messages error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error retrieving messages',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * @desc    Edit a message
 * @route   PUT /api/chat/messages/:messageId
 * @access  Private
 */
exports.editMessage = async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false, 
        errors: errors.array()
      });
    }

    const { messageId } = req.params;
    const { content } = req.body;
    const userId = req.user._id;

    // Find message
    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }

    // Check if user is the message sender
    if (message.sender.toString() !== userId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You can only edit your own messages'
      });
    }

    // Check if message is deleted
    if (message.isDeleted) {
      return res.status(400).json({
        success: false,
        message: 'Cannot edit a deleted message'
      });
    }

    // Sanitize content
    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: ['b', 'i', 'em', 'strong', 'a', 'code'],
      allowedAttributes: {
        'a': ['href', 'target']
      }
    });

    // Update message
    const updatedMessage = await message.editMessage(sanitizedContent);
    await updatedMessage.populate('sender', 'username');

    // Emit socket event to broadcast edited message
    // This would be handled by the Socket.IO implementation
    // io.to(message.roomId).emit('message:update', updatedMessage);

    logger.info(`Message ${messageId} edited by user ${req.user.username}`);

    res.status(200).json({
      success: true,
      message: updatedMessage
    });
  } catch (error) {
    logger.error(`Edit message error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Error editing message',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }

