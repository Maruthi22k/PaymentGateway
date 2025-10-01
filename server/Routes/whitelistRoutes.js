const express = require('express');
const router = express.Router();
const whitelistController = require('../Controllers/whitelistController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken, requirePermission } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

router.get('/whitelist/:userId',
  rateLimiters.general,
  sanitizeInput,
  validate('getWhitelists', 'params'),
  authenticateToken,
  requirePermission('whitelist.read'),
  asyncHandler(whitelistController.getWhitelists)
);

router.post('/whitelist/:userId',
  rateLimiters.general,
  sanitizeInput,
  validate('getWhitelists', 'params'),
  validate('createWhitelist'),
  authenticateToken,
  requirePermission('whitelist.write'),
  asyncHandler(whitelistController.createWhitelist)
);

module.exports = router;
