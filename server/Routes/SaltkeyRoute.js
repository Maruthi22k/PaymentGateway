// Routes/SaltkeyRoute.js

const express = require('express');
const { generateApiKey, getApiKeys, updateApiKeyStatus } = require('../Controllers/saltkeycontroller');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken, requirePermission } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

router.post('/generate-api-key',
  rateLimiters.general,
  sanitizeInput,
  validate('generateApiKey'),
  authenticateToken,
  requirePermission('api_keys.write'),
  asyncHandler(generateApiKey)
);

router.get('/api-keys/:userId',
  rateLimiters.general,
  sanitizeInput,
  validate('getApiKeys', 'params'),
  authenticateToken,
  requirePermission('api_keys.read'),
  asyncHandler(getApiKeys)
);

router.put('/update-api-key-status',
  rateLimiters.general,
  sanitizeInput,
  validate('updateApiKeyStatus'),
  authenticateToken,
  requirePermission('api_keys.write'),
  asyncHandler(updateApiKeyStatus)
);

module.exports = router;
