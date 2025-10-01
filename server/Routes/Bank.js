const express = require('express');
const router = express.Router();
const bankDetailsController = require('../Controllers/bankDetailsController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

// Route to get bank details for a user
router.get('/bankDetails/:userId',
  rateLimiters.general,
  sanitizeInput,
  validate('getBankDetails', 'params'),
  authenticateToken,
  asyncHandler(bankDetailsController.getBankDetails)
);

// Route to create or update bank details for a user
router.post('/bankDetails/:userId',
  rateLimiters.general,
  sanitizeInput,
  validate('bankDetails', 'body'),
  validate('getBankDetails', 'params'),
  authenticateToken,
  asyncHandler(bankDetailsController.createOrUpdateBankDetails)
);

module.exports = router;
