const authService = require('../services/authService');
const logger = require('../config/logger');

/**
 * POST /api/v1/auth/register
 * Registers a new user account.
 * Returns: 201 with sanitized user + sets HttpOnly cookie.
 */
const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.register(email, password);

    // Set JWT as HttpOnly cookie — not accessible by JS, mitigates XSS theft
    res.cookie('ds_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in ms
      path: '/',
    });

    res.status(201).json({
      data: {
        user,
        // Also return token in body so the frontend can optionally read it
        // (useful for testing; client should rely on cookie for auth)
        token,
      },
      message: 'Registration successful',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/v1/auth/login
 * Authenticates a user and issues a JWT via HttpOnly cookie.
 * Returns: 200 with sanitized user.
 */
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.login(email, password);

    res.cookie('ds_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.status(200).json({
      data: { user, token },
      message: 'Login successful',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/v1/auth/logout
 * Clears the auth cookie. Stateless JWT — no server-side invalidation needed.
 */
const logout = async (req, res) => {
  res.clearCookie('ds_token', { path: '/' });
  res.status(200).json({ message: 'Logged out successfully' });
};

/**
 * GET /api/v1/auth/me
 * Returns the currently authenticated user.
 * Requires: authenticate middleware (sets req.user).
 */
const me = async (req, res, next) => {
  try {
    const user = await authService.getUserById(req.user.sub);
    res.status(200).json({ data: { user } });
  } catch (error) {
    next(error);
  }
};

module.exports = { register, login, logout, me };
