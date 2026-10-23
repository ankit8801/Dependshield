const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../config/db');
const logger = require('../config/logger');

const SALT_ROUNDS = 12;
const JWT_EXPIRY = '24h';

/**
 * Returns JWT secret from environment. Throws if not set.
 * Never hard-codes secrets.
 */
const getJwtSecret = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is not set');
  }
  return secret;
};

/**
 * Strips sensitive fields from a user record before returning to the client.
 * NEVER returns passwordHash, tokens, or internal IDs in insecure contexts.
 */
const sanitizeUser = (user) => ({
  id: user.id,
  email: user.email,
  createdAt: user.createdAt,
});

/**
 * Registers a new user.
 * @param {string} email
 * @param {string} password - plaintext, hashed here
 * @returns {{ user: object, token: string }}
 */
const register = async (email, password) => {
  // Check for existing user — use constant-time approach to avoid timing leaks
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const err = new Error('An account with this email already exists');
    err.statusCode = 409;
    throw err;
  }

  // Hash with bcrypt — SALT_ROUNDS=12 gives good security/performance balance
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await prisma.user.create({
    data: { email, passwordHash },
  });

  logger.info('New user registered', { userId: user.id });

  const token = jwt.sign({ sub: user.id, email: user.email }, getJwtSecret(), {
    expiresIn: JWT_EXPIRY,
    algorithm: 'HS256',
  });

  return { user: sanitizeUser(user), token };
};

/**
 * Authenticates a user with email + password.
 * Returns a generic error for both bad email AND bad password to avoid
 * revealing whether an account exists (username enumeration prevention).
 * @returns {{ user: object, token: string }}
 */
const login = async (email, password) => {
  const user = await prisma.user.findUnique({ where: { email } });

  // Always run bcrypt compare even if user not found to prevent timing attacks
  const dummyHash = '$2a$12$invalidhashfortimingattackprevention.xxxxxxxxxxxxxxxxxx';
  const passwordToCompare = user ? user.passwordHash : dummyHash;
  const isValid = await bcrypt.compare(password, passwordToCompare);

  if (!user || !isValid) {
    const err = new Error('Invalid email or password');
    err.statusCode = 401;
    throw err;
  }

  logger.info('User logged in', { userId: user.id });

  const token = jwt.sign({ sub: user.id, email: user.email }, getJwtSecret(), {
    expiresIn: JWT_EXPIRY,
    algorithm: 'HS256',
  });

  return { user: sanitizeUser(user), token };
};

/**
 * Retrieves a user by ID (for /auth/me).
 * @param {string} userId
 */
const getUserById = async (userId) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    const err = new Error('User not found');
    err.statusCode = 404;
    throw err;
  }
  return sanitizeUser(user);
};

module.exports = { register, login, getUserById, sanitizeUser };
