const express = require('express');
const { registerUser, loginUser, getUserData, changeMode, updatePassword, sendOTP, verifyOTP } = require('../Controllers/merchantController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken, requireKYC } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Public routes with rate limiting and validation
router.post('/register',
  rateLimiters.auth,
  sanitizeInput,
  validate('registerUser'),
  asyncHandler(registerUser)
);

router.post('/login',
  rateLimiters.auth,
  sanitizeInput,
  validate('loginUser'),
  asyncHandler(loginUser)
);

router.post('/sendotp',
  rateLimiters.otp,
  sanitizeInput,
  validate('sendOTP'),
  asyncHandler(sendOTP)
);

router.post('/verifyotp',
  rateLimiters.otp,
  sanitizeInput,
  validate('verifyOTP'),
  asyncHandler(verifyOTP)
);

// Protected routes requiring authentication
router.post('/user',
  rateLimiters.general,
  sanitizeInput,
  validate('getUserData'),
  authenticateToken,
  asyncHandler(getUserData)
);

router.post('/updatePassword',
  rateLimiters.passwordReset,
  sanitizeInput,
  validate('updatePassword'),
  authenticateToken,
  asyncHandler(updatePassword)
);

router.post('/changemode',
  rateLimiters.general,
  sanitizeInput,
  validate('changeMode'),
  authenticateToken,
  requireKYC,
  asyncHandler(changeMode)
);

module.exports = router;
