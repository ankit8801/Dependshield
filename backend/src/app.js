const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const logger = require('./config/logger');
const healthRoutes = require('./routes/health');
const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const { errorHandler, notFoundHandler } = require('./middlewares/errorHandler');

const app = express();

const configuredOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const allowedOrigins = [...new Set(configuredOrigins.flatMap(o => {
  if (o === 'http://localhost:80') return [o, 'http://localhost'];
  if (o === 'http://localhost') return [o, 'http://localhost:80'];
  return [o];
}))];

// Security Middlewares
app.use(helmet());
app.use(cors({
  origin: allowedOrigins,
  credentials: true, // Required for cookies to be sent cross-origin
}));

// Parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Required to read HttpOnly auth cookies

// HTTP Request Logging
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// API Routes
app.use('/api/v1', healthRoutes);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/projects', projectRoutes);
app.use('/api/v1/vulnerabilities', vulnerabilityRoutes);

// Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
