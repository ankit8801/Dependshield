require('dotenv').config();
const app = require('./src/app');
const logger = require('./src/config/logger');

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

// Handle unhandled promise rejections safely
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  // Graceful shutdown could be implemented here
});

module.exports = server; // for testing purposes
