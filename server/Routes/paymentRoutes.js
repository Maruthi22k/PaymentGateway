const express = require('express');
const { submitPaymentData } = require('../Controllers/paymentController');
const { submitPaymentDatatest } = require('../Controllers/estController');
const { decryptData } = require('../Controllers/Test');
const { validate, sanitizeInput } = require('../middleware/validation');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Define the routes with security middleware
router.post('/submit-payment-data',
  rateLimiters.payment,
  sanitizeInput,
  validate('submitPaymentData'),
  asyncHandler(submitPaymentData)
);

router.post('/submit-payment-datatest',
  rateLimiters.payment,
  sanitizeInput,
  asyncHandler(submitPaymentDatatest)
);

router.post('/test',
  rateLimiters.general,
  sanitizeInput,
  asyncHandler(decryptData)
);

module.exports = router;
