// api/src/services/authService.js

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Environment variables (should be set in .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret-key';
const JWT_EXPIRES_IN = '15m'; // Short-lived token
const REFRESH_TOKEN_EXPIRES_IN = '7d';

/**
 * Register a new user
 * @param {Object} userData - User data including email, password, name
 */
const register = async (userData) => {
  const { email, password, name } = userData;

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new Error('User with this email already exists');
  }

  // Hash password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  // Create verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');

  // Create new user
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      name,
      role: 'USER',
      isVerified: false,
      status: 'ACTIVE',
      verificationToken,
    },
  });

  // Send verification email (implementation not shown)
  // await sendVerificationEmail(user.email, verificationToken);

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
  };
};

/**
 * Login a user
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {string} ipAddress - IP address of the request
 * @param {string} userAgent - User agent of the request
 */
const login = async (email, password, ipAddress, userAgent) => {
  // Find user by email
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    throw new Error('Invalid credentials');
  }

  // Check if user is active
  if (user.status !== 'ACTIVE') {
    throw new Error('Account is not active');
  }

  // Compare password
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordValid) {
    // Log failed login attempt
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_FAILED',
        ipAddress,
        userAgent,
        details: JSON.stringify({ reason: 'Invalid password' }),
      },
    });
    throw new Error('Invalid credentials');
  }

  // Generate tokens
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // Save refresh token in database
  await prisma.session.create({
    data: {
      userId: user.id,
      token: refreshToken,
      ipAddress,
      userAgent,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });

  // Update user's last login time
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: new Date() },
  });

  // Log successful login
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      ipAddress,
      userAgent,
      details: JSON.stringify({}),
    },
  });

  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
  };
};

/**
 * Refresh access token using refresh token
 * @param {string} refreshToken - Refresh token
 * @param {string} ipAddress - IP address of the request
 * @param {string} userAgent - User agent of the request
 */
const refreshToken = async (refreshToken, ipAddress, userAgent) => {
  if (!refreshToken) {
    throw new Error('Refresh token is required');
  }

  // Verify refresh token from database
  const session = await prisma.session.findUnique({
    where: { token: refreshToken },
    include: { user: true },
  });

  if (!session) {
    throw new Error('Invalid refresh token');
  }

  // Check if refresh token is expired
  if (new Date() > session.expiresAt) {
    // Delete expired session
    await prisma.session.delete({
      where: { id: session.id },
    });
    throw new Error('Refresh token has expired');
  }

  // Generate new tokens
  const user = session.user;
  const accessToken = generateAccessToken(user);
  const newRefreshToken = generateRefreshToken(user);

  // Update refresh token in database
  await prisma.session.update({
    where: { id: session.id },
    data: {
      token: newRefreshToken,
      ipAddress,
      userAgent,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });

  return {
    accessToken,
    refreshToken: newRefreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
  };
};

/**
 * Logout a user by invalidating their refresh token
 * @param {string} refreshToken - Refresh token
 */
const logout = async (refreshToken) => {
  if (!refreshToken) {
    return true;
  }

  // Delete session with refresh token
  await prisma.session.deleteMany({
    where: { token: refreshToken },
  });

  return true;
};

/**
 * Generate access token for a user
 * @param {Object} user - User object
 */
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

/**
 * Generate refresh token for a user
 * @param {Object} user - User object
 */
const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      sub: user.id,
      type: 'refresh',
    },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );
};

/**
 * Verify JWT token
 * @param {string} token - JWT token
 */
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (error) {
    throw new Error('Invalid token');
  }
};

/**
 * Verify email using verification token
 * @param {string} token - Verification token
 */
const verifyEmail = async (token) => {
  const user = await prisma.user.findFirst({
    where: { verificationToken: token },
  });

  if (!user) {
    throw new Error('Invalid verification token');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      isVerified: true,
      verificationToken: null,
      verifiedAt: new Date(),
    },
  });

  return {
    id: user.id,
    email: user.email,
    name: user.name,
  };
};

/**
 * Initiate password reset
 * @param {string} email - User email
 */
const initiatePasswordReset = async (email) => {
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    // Return success even if user doesn't exist to prevent email enumeration
    return true;
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  // Save reset token to user
  await prisma.user.update({
    where: { id: user.id },
    data: {
      resetToken,
      resetTokenExpiry,
    },
  });

  // Send password reset email (implementation not shown)
  // await sendPasswordResetEmail(user.email, resetToken);

  return true;
};

/**
 * Complete password reset
 * @param {string} token - Reset token
 * @param {string} newPassword - New password
 */
const completePasswordReset = async (token, newPassword) => {
  const user = await prisma.user.findFirst({
    where: {
      resetToken: token,
      resetTokenExpiry: {
        gt: new Date(),
      },
    },
  });

  if (!user) {
    throw new Error('Invalid or expired reset token');
  }

  // Hash new password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(newPassword, saltRounds);

  // Update user password and clear reset token
  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash,
      resetToken: null,
      resetTokenExpiry: null,
    },
  });

  // Invalidate all existing sessions for this user
  await prisma.session.deleteMany({
    where: { userId: user.id },
  });

  return true;
};

/**
 * Change password
 * @param {string} userId - User ID
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password
 */
const changePassword = async (userId, currentPassword, newPassword) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new Error('User not found');
  }

  // Verify current password
  const isPasswordValid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!isPasswordValid) {
    throw new Error('Current password is incorrect');
  }

  // Hash new password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(newPassword, saltRounds);

  // Update user password
  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash },
  });

  // Invalidate all existing sessions except current one
  // This logic would be implemented in the controller

  return true;
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  verifyToken,
  verifyEmail,
  initiatePasswordReset,
  completePasswordReset,
  changePassword,
};
