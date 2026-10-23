const jwt = require('jsonwebtoken');
const logger = require('../config/logger');

/**
 * authenticate middleware
 *
 * Reads JWT from:
 *   1. HttpOnly cookie `ds_token` (preferred — set by server)
 *   2. Authorization header `Bearer <token>` (fallback — for API clients/tests)
 *
 * On success: attaches decoded payload to req.user
 * On failure: returns 401 Unauthorized
 *
 * SECURITY: Never trusts user-supplied IDs in the request body/params
 * when the authenticated identity can be obtained from the verified token.
 */
const authenticate = (req, res, next) => {
  try {
    let token = null;

    // 1. Prefer HttpOnly cookie
    if (req.cookies && req.cookies.ds_token) {
      token = req.cookies.ds_token;
    }

    // 2. Fallback to Authorization header (Bearer scheme)
    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2 && parts[0] === 'Bearer') {
        token = parts[1];
      }
    }

    if (!token) {
      return res.status(401).json({
        error: { message: 'Authentication required. Please log in.' },
      });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      logger.error('JWT_SECRET not configured — cannot validate tokens');
      return res.status(500).json({
        error: { message: 'Server configuration error' },
      });
    }

    // Verify signature and expiry
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

    // Attach verified payload — downstream handlers must use req.user.sub for identity
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: { message: 'Session expired. Please log in again.' },
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: { message: 'Invalid authentication token.' },
      });
    }
    // Unexpected error — pass to global error handler
    next(error);
  }
};

module.exports = { authenticate };
