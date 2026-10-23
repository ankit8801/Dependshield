const express = require('express');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');
const validate = require('../middlewares/validate');
const { authenticate } = require('../middlewares/authenticate');
const { registerSchema, loginSchema } = require('../validators/authSchemas');

const router = express.Router();

/**
 * Rate limiter for auth endpoints.
 * Limits to 10 requests per 15 minutes per IP for register/login.
 * Provides practical brute-force mitigation without requiring Redis.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: { message: 'Too many requests. Please try again in 15 minutes.' },
  },
  skip: () => process.env.NODE_ENV === 'test', // Disable in test environment
});

// POST /api/v1/auth/register
router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  authController.register
);

// POST /api/v1/auth/login
router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  authController.login
);

// POST /api/v1/auth/logout
router.post('/logout', authController.logout);

// GET /api/v1/auth/me  — protected
router.get('/me', authenticate, authController.me);

module.exports = router;
