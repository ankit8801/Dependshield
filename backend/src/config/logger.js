const winston = require('winston');

// Mask sensitive information
const maskSecrets = winston.format((info) => {
  const sensitiveKeys = ['password', 'token', 'jwt', 'secret', 'authorization'];
  
  if (info.message && typeof info.message === 'object') {
    Object.keys(info.message).forEach(key => {
      if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
        info.message[key] = '***MASKED***';
      }
    });
  }
  return info;
});

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    maskSecrets(),
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
          return `${timestamp} [${level}]: ${typeof message === 'object' ? JSON.stringify(message) : message} ${metaStr}`;
        })
      )
    })
  ]
});

module.exports = logger;
