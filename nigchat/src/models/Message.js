const mongoose = require('mongoose');
const sanitizeHtml = require('sanitize-html');

const MessageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Sender is required']
  },
  roomId: {
    type: String,
    required: [true, 'Room ID is required'],
    trim: true,
    index: true, // Add index for faster querying
    validate: {
      validator: function(value) {
        // Allow only alphanumeric characters and hyphens
        return /^[a-zA-Z0-9-]+$/.test(value);
      },
      message: 'Room ID can only contain letters, numbers, and hyphens'
    }
  },
  content: {
    type: String,
    required: [true, 'Message content is required'],
    maxlength: [2000, 'Message cannot exceed 2000 characters'],
    set: function(content) {
      // Sanitize HTML to prevent XSS attacks
      return sanitizeHtml(content, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a', 'code'],
        allowedAttributes: {
          'a': ['href', 'target']
        },
        // Strip all other tags and attributes
        disallowedTagsMode: 'discard',
        // Allow only href and target attributes on <a> tags
        allowedAttributes: {
          'a': ['href', 'target']
        }
      });
    }
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true // Add index for faster querying
  },
  readBy: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    readAt: {
      type: Date,
      default: Date.now
    }
  }],
  messageType: {
    type: String,
    enum: ['text', 'system', 'image', 'file', 'notification'],
    default: 'text'
  },
  metadata: {
    // For additional data based on message type
    fileUrl: String,
    fileName: String,
    fileSize: Number,
    mimeType: String,
    imageWidth: Number,
    imageHeight: Number
  },
  isEdited: {
    type: Boolean,
    default: false
  },
  editHistory: [{
    content: String,
    editedAt: {
      type: Date,
      default: Date.now
    }
  }],
  isDeleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt
  toJSON: {
    transform: function(doc, ret) {
      // Don't expose metadata if message is deleted
      if (ret.isDeleted) {
        ret.content = 'This message has been deleted';
        delete ret.metadata;
      }
      return ret;
    }
  }
});

// Index for efficient querying
MessageSchema.index({ roomId: 1, timestamp: -1 });

// Virtual for read status
MessageSchema.virtual('isRead').get(function() {
  return this.readBy && this.readBy.length > 0;
});

// Method to mark message as read by a user
MessageSchema.methods.markAsReadBy = async function(userId) {
  const message = this;
  
  // Check if this user has already read the message
  const alreadyRead = message.readBy.some(entry => 
    entry.userId.toString() === userId.toString()
  );
  
  if (!alreadyRead) {
    message.readBy.push({
      userId: userId,
      readAt: new Date()
    });
    await message.save();
  }
  
  return message;
};

// Method to edit a message
MessageSchema.methods.editMessage = async function(newContent) {
  const message = this;
  
  // Store the current content in edit history
  if (!message.isEdited) {
    message.editHistory = [];
  }
  
  message.editHistory.push({
    content: message.content,
    editedAt: new Date()
  });
  
  // Update content and mark as edited
  message.content = newContent;
  message.isEdited = true;
  
  await message.save();
  return message;
};

// Method to "delete" a message (soft delete)
MessageSchema.methods.softDelete = async function() {
  const message = this;
  message.isDeleted = true;
  await message.save();
  return message;
};

// Static method to find recent messages for a room
MessageSchema.statics.findRecentByRoom = async function(roomId, limit = 50) {
  return this.find({ 
    roomId: roomId,
    isDeleted: false 
  })
  .sort({ timestamp: -1 })
  .limit(limit)
  .populate('sender', 'username')
  .populate('readBy.userId', 'username')
  .exec();
};

const Message = mongoose.model('Message', MessageSchema);

module.exports = Message;

