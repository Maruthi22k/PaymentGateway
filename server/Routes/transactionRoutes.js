// routes/transactionRoutes.js
const express = require('express');
const router = express.Router();
const transactionController = require('../Controllers/transactionController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

// Route to fetch transactions by merchantId
router.get('/transactions/:merchantId',
  rateLimiters.general,
  sanitizeInput,
  validate('getTransactions', 'params'),
  authenticateToken,
  asyncHandler(transactionController.getTransactions)
);

module.exports = router;
