const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
const { check, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Message = require('./models/Message');
require('dotenv').config();

// Initialize Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'nigchat' },
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

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Initialize Socket.IO with CORS settings
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Set up CORS configuration
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Set up Helmet for security headers
app.use(helmet());

// Configure content security policy
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'", `${process.env.CLIENT_URL || "http://localhost:3000"}`],
  }
}));

// Basic express middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(cookieParser());

// Implement rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to all requests
app.use('/api/', apiLimiter);

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/nigchat', {
      // Mongoose 6+ doesn't need these options anymore, but keeping for reference
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
    });
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', error.message);
    // Exit process with failure
    process.exit(1);
  }
};

// Socket.IO authentication middleware
const socketAuth = async (socket, next) => {
  try {
    // Get token from socket handshake auth
    const token = socket.handshake.auth.token;
    
    if (!token) {
      return next(new Error('Authentication error: Token missing'));
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user by ID
    const user = await User.findById(decoded._id);
    if (!user) {
      return next(new Error('Authentication error: User not found'));
    }
    
    // Check account status
    if (user.accountStatus !== 'active') {
      return next(new Error(`Authentication error: Account is ${user.accountStatus}`));
    }
    
    // Check if token is valid in user's tokens array
    const isValidToken = user.tokens.some(
      (tokenObj) => tokenObj.token === token && tokenObj.expires > new Date()
    );
    
    if (!isValidToken) {
      return next(new Error('Authentication error: Invalid or expired token'));
    }
    
    // Attach user to socket
    socket.user = user;
    socket.userId = user._id;
    socket.username = user.username;
    
    // Continue with connection
    next();
  } catch (error) {
    logger.error(`Socket authentication error: ${error.message}`);
    return next(new Error('Authentication error'));
  }
};

// Apply Socket.IO middleware
io.use(socketAuth);

// Socket.IO connection handling
io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.id} (${socket.username})`);

  // Store active rooms for this user
  socket.rooms = new Set();

  // Handle joining a chat room
  socket.on('join', async (roomId) => {
    try {
      // Validate room ID
      if (!roomId || typeof roomId !== 'string' || !/^[a-zA-Z0-9-_]+$/.test(roomId)) {
        socket.emit('error', { message: 'Invalid room ID format' });
        return;
      }

      // Join the room
      socket.join(roomId);
      socket.rooms.add(roomId);
      
      logger.info(`User ${socket.username} (${socket.id}) joined room: ${roomId}`);

      // Notify room about new user
      socket.to(roomId).emit('user:joined', {
        userId: socket.userId,
        username: socket.username,
        timestamp: new Date()
      });

      // Send confirmation to user
      socket.emit('room:joined', { roomId });
    } catch (error) {
      logger.error(`Error joining room: ${error.message}`);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Handle leaving a chat room
  socket.on('leave', (roomId) => {
    try {
      // Validate room ID
      if (!roomId || typeof roomId !== 'string') {
        socket.emit('error', { message: 'Invalid room ID format' });
        return;
      }

      // Leave the room
      socket.leave(roomId);
      socket.rooms.delete(roomId);
      
      logger.info(`User ${socket.username} (${socket.id}) left room: ${roomId}`);

      // Notify room that user left
      socket.to(roomId).emit('user:left', {
        userId: socket.userId,
        username: socket.username,
        timestamp: new Date()
      });

      // Send confirmation to user
      socket.emit('room:left', { roomId });
    } catch (error) {
      logger.error(`Error leaving room: ${error.message}`);
      socket.emit('error', { message: 'Failed to leave room' });
    }
  });

  // Handle chat messages
  socket.on('message:send', async (data) => {
    try {
      // Validate data
      if (!data || !data.roomId || !data.content) {
        socket.emit('error', { message: 'Invalid message format' });
        return;
      }

      const { roomId, content, messageType = 'text' } = data;

      // Check if user is in the room
      if (!socket.rooms.has(roomId)) {
        socket.emit('error', { message: 'You are not in this room' });
        return;
      }

      // Sanitize content
      const sanitizedContent = sanitizeHtml(content, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a', 'code'],
        allowedAttributes: {
          'a': ['href', 'target']
        }
      });

      // Create message in database
      const message = await Message.create({
        sender: socket.userId,
        roomId,
        content: sanitizedContent,
        messageType,
        timestamp: new Date()
      });

      await message.populate('sender', 'username');

      // Format message for broadcasting
      const formattedMessage = {
        id: message._id,
        sender: {
          id: message.sender._id,
          username: message.sender.username
        },
        roomId: message.roomId,
        content: message.content,
        messageType: message.messageType,
        timestamp: message.timestamp,
        isEdited: false
      };

      // Broadcast to everyone in the room including sender
      io.to(roomId).emit('message:new', formattedMessage);
      
      logger.info(`Message sent to room ${roomId} by ${socket.username}`);
    } catch (error) {
      logger.error(`Error sending message: ${error.message}`);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle message editing
  socket.on('message:edit', async (data) => {
    try {
      // Validate data
      if (!data || !data.messageId || !data.content) {
        socket.emit('error', { message: 'Invalid message edit format' });
        return;
      }

      const { messageId, content } = data;

      // Find message in database
      const message = await Message.findById(messageId);
      
      if (!message) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }

      // Check if user is the message sender
      if (message.sender.toString() !== socket.userId.toString()) {
        socket.emit('error', { message: 'You can only edit your own messages' });
        return;
      }

      // Check if message is deleted
      if (message.isDeleted) {
        socket.emit('error', { message: 'Cannot edit a deleted message' });
        return;
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

      // Format message for broadcasting
      const formattedMessage = {
        id: updatedMessage._id,
        sender: {
          id: updatedMessage.sender._id,
          username: updatedMessage.sender.username
        },
        roomId: updatedMessage.roomId,
        content: updatedMessage.content,
        timestamp: updatedMessage.timestamp,
        isEdited: updatedMessage.isEdited,
        editedAt: updatedMessage.editHistory[updatedMessage.editHistory.length - 1].editedAt
      };

      // Broadcast edited message to room
      io.to(updatedMessage.roomId).emit('message:update', formattedMessage);
      
      logger.info(`Message ${messageId} edited by ${socket.username}`);
    } catch (error) {
      logger.error(`Error editing message: ${error.message}`);
      socket.emit('error', { message: 'Failed to edit message' });
    }
  });

  // Handle typing indicator
  socket.on('typing:start', (roomId) => {
    if (socket.rooms.has(roomId)) {
      socket.to(roomId).emit('user:typing', {
        userId: socket.userId,
        username: socket.username,
        roomId
      });
    }
  });

  socket.on('typing:stop', (roomId) => {
    if (socket.rooms.has(roomId)) {
      socket.to(roomId).emit('user:stopped-typing', {
        userId: socket.userId,
        username: socket.username,
        roomId
      });
    }
  });

  // Handle disconnection
  socket.on('disconnect', (reason) => {
    // Notify all rooms this user was in
    socket.rooms.forEach(roomId => {
      socket.to(roomId).emit('user:left', {
        userId: socket.userId,
        username: socket.username,
        timestamp: new Date(),
        reason: 'disconnected'
      });
    });
    
    logger.info(`User ${socket.username} (${socket.id}) disconnected: ${reason}`);
  });

  // Handle errors
  socket.on('error', (error) => {
    logger.error(`Socket error for user ${socket.username} (${socket.id}): ${error.message}`);
  });
});

// Import routes
const authRoutes = require('./routes/authRoutes');
const chatRoutes = require('./routes/chatRoutes');

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);

// Define a simple root route
app.get('/', (req, res) => {
  res.send('NigChat API is running');
});

// 404 Handler
app.use((req, res, next) => {
  res.status(404).json({ message: 'Route not found' });
});

// Error Handler
app.use((err, req, res, next) => {
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
  res.status(err.status || 500).json({
    message: err.message || 'Internal Server Error',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// Create a simple index.html for testing Socket.IO connections
app.get('/socket-test', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/socket-test.html'));
});

// Server Initialization
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();
  server.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err.message);
  // Close server & exit process
  server.close(() => process.exit(1));
});

module.exports = { app, startServer };

