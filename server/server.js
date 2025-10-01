const express = require('express');
const connectDB = require('./Util/db');
const merchantsRoutes = require('./Routes/MerchantRoute');
const saltkeyRoutes = require('./Routes/SaltkeyRoute');
const transactionRoutes = require('./Routes/transactionRoutes');
const logoRoutes = require('./Routes/logoRoutes');
const whitelistRoutes = require('./Routes/whitelistRoutes');
const settlemtRoutes = require('./Routes/settlementRouter');
const bankDetails = require('./Routes/Bank');
const staffRoutes = require('./Routes/staffRoutes');

// Security middleware
const { helmetConfig, corsOptions, requestSizeLimiter, securityHeaders, requestLogger } = require('./middleware/security');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { rateLimiters } = require('./middleware/rateLimiter');
const { logger } = require('./Util/logger');

// Initialize Express app
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

// Middleware to parse JSON with size limit
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Connect to MongoDB
connectDB();

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Define a simple route
app.get('/', (req, res) => {
  res.json({
    message: 'JCS Pay API is running...',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Use the routes
app.use('/api', merchantsRoutes);  // Merchant routes
app.use('/api/', saltkeyRoutes);      // Saltkey routes
app.use('/api', transactionRoutes);  // Transactions routes
app.use('/api', settlemtRoutes);  // Settlement routes
app.use('/api/logo', logoRoutes);           // Logo routes
app.use('/api/', whitelistRoutes); // Whitelisting route
app.use('/api', bankDetails);
app.use('/api/staff', staffRoutes);  // Staff routes

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
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`, {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version
  });
});
