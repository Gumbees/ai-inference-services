import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { CONFIG, ERROR_MESSAGES } from '../constants.js';

/**
 * Authentication Service
 * Handles user authentication, session management, and security
 */

class AuthService {
  constructor() {
    // In-memory storage (in production, use a database)
    this.users = new Map();
    this.sessions = new Map();
    this.saltRounds = CONFIG.SECURITY.saltRounds;
    this.jwtSecret = CONFIG.JWT_SECRET;
  }

  /**
   * Password hashing
   */
  async hashPassword(password) {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  /**
   * JWT token management
   */
  generateToken(userId, type = 'session', expiresIn = '24h') {
    return jwt.sign({ userId, type }, this.jwtSecret, { expiresIn });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      throw new Error(ERROR_MESSAGES.INVALID_TOKEN);
    }
  }

  /**
   * User registration
   */
  async register(username, password, email) {
    if (this.users.has(username)) {
      throw new Error(ERROR_MESSAGES.USERNAME_EXISTS);
    }

    const userId = uuidv4();
    const hashedPassword = await this.hashPassword(password);
    
    const user = {
      id: userId,
      username,
      password: hashedPassword,
      email,
      provider: 'local',
      createdAt: new Date().toISOString(),
    };

    this.users.set(username, user);
    this.users.set(userId, user); // Also store by ID for lookups
    
    console.log(`User registered: ${username} (${userId})`);
    return { userId, username, email };
  }

  /**
   * User login
   */
  async login(username, password) {
    const user = this.users.get(username);
    if (!user) {
      throw new Error(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    const isValid = await this.verifyPassword(password, user.password);
    if (!isValid) {
      throw new Error(ERROR_MESSAGES.INVALID_PASSWORD);
    }

    const token = this.generateToken(user.id);
    const sessionId = uuidv4();
    
    const session = {
      userId: user.id,
      username: user.username,
      token,
      createdAt: new Date().toISOString(),
      lastAccess: Date.now(),
      accessCount: 0,
    };

    this.sessions.set(sessionId, session);
    
    console.log(`User login: ${username} (${user.id})`);
    return { sessionId, token, userId: user.id, username: user.username };
  }

  /**
   * OAuth user creation/update
   */
  async findOrCreateOAuthUser(userInfo) {
    // Try to find existing user by provider ID
    const existingUser = Array.from(this.users.values()).find(
      user => user.provider === 'oauth' && user.providerId === userInfo.providerId
    );

    if (existingUser) {
      // Update user info
      existingUser.email = userInfo.email;
      existingUser.name = userInfo.name;
      existingUser.lastLogin = new Date().toISOString();
      console.log(`OAuth user updated: ${userInfo.username} (${userInfo.email})`);
      return existingUser;
    }

    // Create new OAuth user
    const userId = uuidv4();
    const user = {
      id: userId,
      username: userInfo.username,
      email: userInfo.email,
      name: userInfo.name,
      provider: 'oauth',
      providerId: userInfo.providerId,
      profile: userInfo.profile,
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
    };

    this.users.set(userInfo.username, user);
    this.users.set(userId, user);
    
    console.log(`OAuth user created: ${userInfo.username} (${userInfo.email})`);
    return user;
  }

  /**
   * Session management
   */
  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }

  getUserById(id) {
    return this.users.get(id);
  }

  getUserBySession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    // Verify session integrity
    try {
      const decoded = this.verifyToken(session.token);
      if (decoded.userId !== session.userId) {
        console.warn(`Session tampering detected: Token userId ${decoded.userId} != Session userId ${session.userId}`);
        this.logout(sessionId); // Invalidate compromised session
        return null;
      }
      return session;
    } catch (error) {
      console.warn('Session token validation failed during user lookup:', error.message);
      this.logout(sessionId); // Invalidate invalid session
      return null;
    }
  }

  validateSessionOwnership(sessionId, expectedUserId) {
    const session = this.getUserBySession(sessionId);
    if (!session) {
      throw new Error(ERROR_MESSAGES.INVALID_SESSION);
    }
    
    if (session.userId !== expectedUserId) {
      console.error(`Session ownership violation: Session ${sessionId} belongs to ${session.userId}, not ${expectedUserId}`);
      this.logout(sessionId); // Invalidate session
      throw new Error('Session ownership validation failed');
    }
    
    return session;
  }

  logout(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      console.log(`Session logout: User ${session.userId} (${session.username})`);
    }
    return this.sessions.delete(sessionId);
  }

  /**
   * Session validation with security checks
   */
  validateSession(sessionId, requestContext = {}) {
    const session = this.getSession(sessionId);
    if (!session) {
      throw new Error(ERROR_MESSAGES.INVALID_SESSION);
    }

    // Additional security: Verify session integrity
    if (!this.validateSessionIntegrity(session, requestContext)) {
      throw new Error(ERROR_MESSAGES.SESSION_VALIDATION_FAILED);
    }

    // Check for session hijacking attempts
    if (this.detectSessionAnomaly(session, requestContext)) {
      // Invalidate potentially compromised session
      this.logout(sessionId);
      throw new Error(ERROR_MESSAGES.SECURITY_VIOLATION);
    }

    return session;
  }

  validateSessionIntegrity(session, requestContext) {
    // Verify session hasn't been tampered with
    if (!session.userId || !session.username || !session.token) {
      return false;
    }

    // Verify JWT token integrity
    try {
      const decoded = this.verifyToken(session.token);
      if (decoded.userId !== session.userId) {
        console.warn(`Session integrity violation: Token userId ${decoded.userId} != Session userId ${session.userId}`);
        return false;
      }
    } catch (error) {
      console.warn('Session token validation failed:', error.message);
      return false;
    }

    return true;
  }

  detectSessionAnomaly(session, requestContext) {
    // Check for rapid session switching (potential MitM)
    const now = Date.now();
    const lastAccess = session.lastAccess || now;
    
    // Update last access time
    session.lastAccess = now;
    session.accessCount = (session.accessCount || 0) + 1;

    // Detect suspicious patterns
    if (session.accessCount > CONFIG.SECURITY.maxRequestsPerSession) {
      console.warn(`Suspicious activity: Session ${session.userId} has ${session.accessCount} requests`);
      return true;
    }

    // Additional checks could include:
    // - IP address validation (if available)
    // - Request pattern analysis
    // - Geographic location checks

    return false;
  }

  /**
   * Enhanced token verification for MCP access tokens
   */
  verifyMCPToken(token) {
    try {
      const decoded = this.verifyToken(token);
      if (decoded.type === 'mcp-access') {
        return decoded;
      }
      throw new Error('Invalid token type');
    } catch (error) {
      throw new Error(ERROR_MESSAGES.INVALID_TOKEN);
    }
  }

  /**
   * Generate MCP access token
   */
  generateMCPToken(userId, username, expiresIn = '30d') {
    return this.generateToken(userId, 'mcp-access', expiresIn);
  }

  /**
   * Get all users (admin function)
   */
  getAllUsers() {
    return Array.from(this.users.values()).map(user => ({
      id: user.id,
      username: user.username,
      email: user.email,
      provider: user.provider,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
    }));
  }

  /**
   * Get session statistics
   */
  getSessionStats() {
    const sessions = Array.from(this.sessions.values());
    return {
      totalSessions: sessions.length,
      activeSessions: sessions.filter(s => s.lastAccess > Date.now() - 3600000).length, // Last hour
      totalUsers: this.users.size,
      oauthUsers: Array.from(this.users.values()).filter(u => u.provider === 'oauth').length,
      localUsers: Array.from(this.users.values()).filter(u => u.provider === 'local').length,
    };
  }

  /**
   * Cleanup expired sessions
   */
  cleanupExpiredSessions() {
    const now = Date.now();
    const timeout = CONFIG.SECURITY.sessionTimeoutHours * 60 * 60 * 1000;
    let cleaned = 0;

    for (const [sessionId, session] of this.sessions.entries()) {
      if (now - session.lastAccess > timeout) {
        this.sessions.delete(sessionId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Cleaned up ${cleaned} expired sessions`);
    }

    return cleaned;
  }
}

export default AuthService;
