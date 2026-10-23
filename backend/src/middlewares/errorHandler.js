const logger = require('../config/logger');

const { ZodError } = require('zod');

const errorHandler = (err, req, res, next) => {
  logger.error(err.message, { stack: err.stack, path: req.path, method: req.method });

  if (err instanceof ZodError) {
    return res.status(400).json({
      error: {
        message: 'Validation Error',
        details: err.errors
      }
    });
  }

  // Handle multer file filter and boundary errors
  if (err.message && (err.message.startsWith('Only .zip archives are accepted') || err.message.includes('Multipart: Boundary not found'))) {
    return res.status(400).json({
      error: { message: err.message }
    });
  }

  // Handle Prisma invalid UUID/ID errors
  if (err.code === 'P2023' || (err.message && err.message.includes('Invalid `prisma'))) {
    // If it's a UUID parse error it usually manifests as a Prisma client validation error
    if (err.message.includes('malformed') || err.message.includes('uuid')) {
        return res.status(400).json({ error: { message: 'Invalid ID format' } });
    }
  }

  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' && statusCode === 500 
    ? 'Internal Server Error' 
    : err.message;

  res.status(statusCode).json({
    error: {
      message,
      ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    }
  });
};

const notFoundHandler = (req, res, next) => {
  res.status(404).json({ error: { message: 'Resource Not Found' } });
};

module.exports = {
  errorHandler,
  notFoundHandler
};
