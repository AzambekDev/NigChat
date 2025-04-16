# NigChat - Secure Chat Application

A secure real-time chat application built with Node.js, Express, Socket.IO, and MongoDB with focus on security and performance.

## Features

- Real-time messaging with Socket.IO
- Secure user authentication with JWT
- Password hashing with bcrypt
- Message encryption
- Cross-Site Scripting (XSS) protection
- Cross-Site Request Forgery (CSRF) protection
- Input validation and sanitization
- Rate limiting to prevent brute force attacks
- Account lockout mechanism
- Secure HTTP headers with Helmet
- Comprehensive error handling and logging
- MongoDB for persistent storage

## Security Considerations

NigChat implements multiple layers of security:

- **Authentication**: JWT-based authentication with proper token expiration and refresh mechanisms
- **Password Security**: Passwords are hashed using bcrypt with appropriate salt rounds
- **Input Validation**: All user inputs are validated and sanitized to prevent injection attacks
- **XSS Protection**: Content sanitization using sanitize-html
- **CSRF Protection**: Implemented using secure cookies with SameSite attribute
- **Rate Limiting**: Prevents brute force attacks on authentication and messaging
- **Secure Headers**: HTTP security headers implemented with Helmet
- **Session Management**: Secure token storage and validation
- **Account Protection**: Account lockout after multiple failed login attempts
- **Secure Communication**: Client-server communication secured with HTTPS/TLS

## Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)
- MongoDB (v4 or higher)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/nigchat.git
cd nigchat
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file in the root directory (see Environment Variables section below)

4. Start the development server:

```bash
npm run dev
```

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```
# Server Configuration
PORT=5000
NODE_ENV=development

# MongoDB Connection
# For production, use a secure MongoDB Atlas connection string or similar
MONGODB_URI=mongodb://localhost:27017/nigchat

# JWT Configuration
# Must be a secure random string - in production replace with a strong random value
JWT_SECRET=yoursecretkey
JWT_EXPIRATION=86400 # 24 hours in seconds

# Client URLs
# For production, update with actual domain
CLIENT_URL=http://localhost:3000

# Session Configuration
# Must be a secure random string - in production replace with a strong random value
SESSION_SECRET=yoursessionsecret

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000 # 15 minutes in milliseconds
RATE_LIMIT_MAX_REQUESTS=100

# Security Configuration
# Time in milliseconds for CSRF token expiration
CSRF_TOKEN_EXPIRY=3600000 # 1 hour

# Logging Configuration
LOG_LEVEL=info

# Socket.IO Configuration
SOCKET_CORS_ORIGIN=http://localhost:3000

# Password Security
# Number of salt rounds for bcrypt (higher is more secure but slower)
BCRYPT_SALT_ROUNDS=12
```

## Usage

### Starting the Server

Development mode with hot reloading:
```bash
npm run dev
```

Production mode:
```bash
npm run serve
```

### API Endpoints

#### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/logout` - Logout current device
- `POST /api/auth/logoutAll` - Logout all devices
- `GET /api/auth/me` - Get current user profile
- `POST /api/auth/forgotPassword` - Request password reset
- `POST /api/auth/resetPassword/:token` - Reset password with token
- `POST /api/auth/refreshToken` - Refresh JWT token
- `PUT /api/auth/updatePassword` - Update password

#### Chat Rooms

- `GET /api/chat/rooms` - Get all available chat rooms
- `POST /api/chat/rooms` - Create a new chat room
- `POST /api/chat/rooms/:roomId/join` - Join a chat room
- `POST /api/chat/rooms/:roomId/leave` - Leave a chat room

#### Messages

- `GET /api/chat/rooms/:roomId/messages` - Get messages for a room
- `POST /api/chat/rooms/:roomId/messages` - Send a message to a room
- `PUT /api/chat/messages/:messageId` - Edit a message
- `DELETE /api/chat/messages/:messageId` - Delete a message (soft delete)

### Socket.IO Events

#### Client Emits
- `join` - Join a chat room
- `leave` - Leave a chat room
- `message:send` - Send a message
- `message:edit` - Edit a message
- `typing:start` - Indicate user started typing
- `typing:stop` - Indicate user stopped typing

#### Server Emits
- `user:joined` - User joined a room
- `user:left` - User left a room
- `message:new` - New message
- `message:update` - Message was updated
- `user:typing` - User is typing
- `user:stopped-typing` - User stopped typing
- `error` - Error message
- `room:joined` - Confirmation of joining a room
- `room:left` - Confirmation of leaving a room

## Testing

Run tests:
```bash
npm test
```

## Linting

Check code style:
```bash
npm run lint
```

Fix code style issues:
```bash
npm run lint:fix
```

## Security Audit

Run a security audit:
```bash
npm run audit
```

Fix security vulnerabilities:
```bash
npm run audit:fix
```

## License

[ISC](LICENSE)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

