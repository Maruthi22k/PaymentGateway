const express = require('express');
const connectDB = require('./Util/db');
require('dotenv').config();

// Import routes
const paymentRoutes = require('./Routes/paymentRoutes');
const paymentupdateRoutes = require('./Routes/PaymentupdateRoutes');
const fUrl = require('./Routes/fUrl');

// Security middleware
const { helmetConfig, corsOptions, requestSizeLimiter, securityHeaders, requestLogger } = require('./middleware/security');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { rateLimiters } = require('./middleware/rateLimiter');
const { logger } = require('./Util/logger');

// Initialize the Express app
const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Security middleware (order matters!)
app.use(helmetConfig);
app.use(securityHeaders);
app.use(requestLogger);
app.use(requestSizeLimiter);

// CORS Middleware
app.use(require('cors')(corsOptions));

// Rate limiting
app.use(rateLimiters.general);

// Middleware to parse JSON and URL-encoded data with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Connect to the database
connectDB();

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Use the payment routes
app.use('/api/payments', paymentRoutes);
app.use('/api', paymentupdateRoutes);
app.use('/api', fUrl);

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(`Payment server is running on port ${PORT}`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version
  });
});
