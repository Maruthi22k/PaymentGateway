const express = require('express');
const router = express.Router();

// Import the upload middleware from the controller
const { upload, uploadProfile, getProfile } = require('../Controllers/logoController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

// Route to upload the profile image
router.post('/upload/:merchantId',
  rateLimiters.upload,
  sanitizeInput,
  validate('logoUpload', 'params'),
  authenticateToken,
  upload,
  asyncHandler(uploadProfile)
);

// Route to retrieve the profile image
router.get('/:merchantId',
  rateLimiters.general,
  sanitizeInput,
  validate('logoUpload', 'params'),
  authenticateToken,
  asyncHandler(getProfile)
);

module.exports = router;
