const prisma = require('../config/db');
const logger = require('../config/logger');

const checkHealth = async (req, res, next) => {
  try {
    // Check DB connection by running a simple query
    await prisma.$queryRaw`SELECT 1`;
    
    res.status(200).json({
      status: 'ok',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Database connection failed during health check', { error: error.message });
    res.status(503).json({
      status: 'error',
      database: 'disconnected',
      message: 'Service Unavailable',
      timestamp: new Date().toISOString()
    });
  }
};

module.exports = {
  checkHealth
};
