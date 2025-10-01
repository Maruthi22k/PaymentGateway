const express = require('express');
const router = express.Router();
const {
  registerStaff,
  loginStaff,
  getStaffMembers,
  getStaffMember,
  updateStaffMember,
  deleteStaffMember,
  changePassword,
  getStaffPermissions
} = require('../Controllers/staffController');
const { validate, sanitizeInput } = require('../middleware/validation');
const { authenticateToken, authorize } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/rateLimiter');
const { asyncHandler } = require('../middleware/errorHandler');

// Public routes
router.post('/login',
  rateLimiters.auth,
  sanitizeInput,
  validate('staffLogin'),
  asyncHandler(loginStaff)
);

// Protected routes requiring authentication
router.use(authenticateToken);

// Staff management routes (admin only)
router.post('/register',
  rateLimiters.general,
  sanitizeInput,
  validate('staffRegister'),
  authorize(['admin', 'super_admin']),
  asyncHandler(registerStaff)
);

router.get('/',
  rateLimiters.general,
  sanitizeInput,
  authorize(['admin', 'super_admin', 'manager']),
  asyncHandler(getStaffMembers)
);

router.get('/permissions',
  rateLimiters.general,
  sanitizeInput,
  authorize(['admin', 'super_admin']),
  asyncHandler(getStaffPermissions)
);

router.get('/:staffId',
  rateLimiters.general,
  sanitizeInput,
  validate('getStaffMember', 'params'),
  authorize(['admin', 'super_admin', 'manager']),
  asyncHandler(getStaffMember)
);

router.put('/:staffId',
  rateLimiters.general,
  sanitizeInput,
  validate('updateStaffMember', 'body'),
  validate('getStaffMember', 'params'),
  authorize(['admin', 'super_admin']),
  asyncHandler(updateStaffMember)
);

router.delete('/:staffId',
  rateLimiters.general,
  sanitizeInput,
  validate('getStaffMember', 'params'),
  authorize(['admin', 'super_admin']),
  asyncHandler(deleteStaffMember)
);

router.put('/:staffId/change-password',
  rateLimiters.passwordReset,
  sanitizeInput,
  validate('changePassword', 'body'),
  validate('getStaffMember', 'params'),
  asyncHandler(changePassword)
);

module.exports = router;
