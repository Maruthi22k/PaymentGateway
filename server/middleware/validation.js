const Joi = require('joi');
const logger = require('../Util/logger');

/**
 * Input validation middleware using Joi
 * Provides comprehensive validation for all endpoints
 */

// Common validation patterns
const commonPatterns = {
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).max(128).pattern(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
  ).required().messages({
    'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
  }),
  mobile: Joi.string().pattern(/^[6-9]\d{9}$/).required().messages({
    'string.pattern.base': 'Mobile number must be a valid 10-digit Indian mobile number'
  }),
  mongoId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required(),
  amount: Joi.number().positive().precision(2).max(999999.99).required(),
  name: Joi.string().min(2).max(50).pattern(/^[a-zA-Z\s]+$/).required(),
  url: Joi.string().uri().max(500).optional()
};

// Validation schemas for different endpoints
const schemas = {
  // User registration
  registerUser: Joi.object({
    firstName: commonPatterns.name,
    lastName: commonPatterns.name,
    email: commonPatterns.email,
    password: commonPatterns.password,
    mobile: commonPatterns.mobile,
    isCollectingPayments: Joi.boolean().default(false),
    websiteUrl: commonPatterns.url.allow('')
  }),

  // User login
  loginUser: Joi.object({
    email: commonPatterns.email,
    password: Joi.string().required()
  }),

  // OTP operations
  sendOTP: Joi.object({
    mobile: commonPatterns.mobile
  }),

  verifyOTP: Joi.object({
    mobile: commonPatterns.mobile,
    otp: Joi.string().length(6).pattern(/^\d{6}$/).required()
  }),

  // User data operations
  getUserData: Joi.object({
    _id: commonPatterns.mongoId
  }),

  updatePassword: Joi.object({
    _id: commonPatterns.mongoId,
    currentPassword: Joi.string().required(),
    newPassword: commonPatterns.password
  }),

  changeMode: Joi.object({
    _id: commonPatterns.mongoId,
    mode: Joi.string().valid('TEST', 'LIVE').required()
  }),

  // Payment operations
  submitPaymentData: Joi.object({
    merchantId: commonPatterns.mongoId,
    productinfo: Joi.string().min(1).max(100).required(),
    amount: commonPatterns.amount,
    email: commonPatterns.email,
    firstname: commonPatterns.name,
    lastname: commonPatterns.name,
    phone: commonPatterns.mobile,
    salt: Joi.string().min(1).max(100).required()
  }),

  // Transaction operations
  getTransactions: Joi.object({
    merchantId: commonPatterns.mongoId
  }),

  // Salt key operations
  createSaltKey: Joi.object({
    merchantId: commonPatterns.mongoId,
    saltKey: Joi.string().min(16).max(100).required(),
    isActive: Joi.boolean().default(true)
  }),

  // Bank details
  bankDetails: Joi.object({
    accountNumber: Joi.string().pattern(/^\d{9,18}$/).required(),
    holderName: commonPatterns.name,
    bankName: Joi.string().min(2).max(100).required(),
    branchName: Joi.string().min(2).max(100).required(),
    ifsc: Joi.string().pattern(/^[A-Z]{4}0[A-Z0-9]{6}$/).required()
  }),

  // Get bank details
  getBankDetails: Joi.object({
    userId: commonPatterns.mongoId
  }),

  // Logo upload
  logoUpload: Joi.object({
    merchantId: commonPatterns.mongoId
  }),

  // Salt key operations
  generateApiKey: Joi.object({
    merchantId: commonPatterns.mongoId
  }),

  getApiKeys: Joi.object({
    userId: commonPatterns.mongoId
  }),

  updateApiKeyStatus: Joi.object({
    merchantId: commonPatterns.mongoId,
    isActive: Joi.boolean().required()
  }),

  // Payment update
  updatePaymentStatus: Joi.object({
    ID2: commonPatterns.mongoId,
    status: Joi.string().valid('success', 'failure', 'pending', 'cancelled').required()
  }),

  // Failure URL
  getFailureUrl: Joi.object({
    ID2: commonPatterns.mongoId
  }),

  // Whitelist operations
  getWhitelists: Joi.object({
    userId: commonPatterns.mongoId
  }),

  createWhitelist: Joi.object({
    type: Joi.string().valid('domain', 'ip', 'url').required(),
    link: Joi.string().uri().max(500).required()
  }),

  // Settlement transactions
  getSettlementTransactions: Joi.object({
    merchantId: commonPatterns.mongoId
  }),

  // Test/Decrypt operations
  decryptData: Joi.object({
    token1: Joi.string().required(),
    token2: Joi.string().required(),
    token3: Joi.string().required(),
    token4: Joi.string().required()
  }),

  // Encrypted payment data
  submitPaymentDataTest: Joi.object({
    merchantId: commonPatterns.mongoId,
    encryptedData: Joi.string().required(),
    hashedSaltKey: Joi.string().length(64).required(),
    iv: Joi.string().length(32).required()
  }),

  // Staff operations
  staffLogin: Joi.object({
    email: commonPatterns.email,
    password: Joi.string().required()
  }),

  staffRegister: Joi.object({
    firstName: commonPatterns.name,
    lastName: commonPatterns.name,
    email: commonPatterns.email,
    password: commonPatterns.password,
    role: Joi.string().valid('super_admin', 'admin', 'manager', 'support', 'viewer').required(),
    permissions: Joi.array().items(Joi.string()).optional()
  }),

  getStaffMember: Joi.object({
    staffId: commonPatterns.mongoId
  }),

  updateStaffMember: Joi.object({
    firstName: commonPatterns.name.optional(),
    lastName: commonPatterns.name.optional(),
    email: commonPatterns.email.optional(),
    role: Joi.string().valid('super_admin', 'admin', 'manager', 'support', 'viewer').optional(),
    permissions: Joi.array().items(Joi.string()).optional(),
    isActive: Joi.boolean().optional()
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: commonPatterns.password
  })
};

/**
 * Validation middleware factory
 * @param {string} schemaName - Name of the schema to use
 * @param {string} source - Source of data to validate ('body', 'params', 'query')
 */
const validate = (schemaName, source = 'body') => {
  return (req, res, next) => {
    const schema = schemas[schemaName];

    if (!schema) {
      logger.error('Validation schema not found', { schemaName });
      return res.status(500).json({
        error: 'Internal server error. Validation schema not found.'
      });
    }

    const dataToValidate = req[source];
    const { error, value } = schema.validate(dataToValidate, {
      abortEarly: false, // Return all validation errors
      stripUnknown: true, // Remove unknown fields
      convert: true // Convert types when possible
    });

    if (error) {
      const errorDetails = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      logger.warn('Validation failed', {
        schemaName,
        source,
        errors: errorDetails,
        ip: req.ip,
        path: req.path
      });

      return res.status(400).json({
        error: 'Validation failed',
        details: errorDetails
      });
    }

    // Replace the original data with validated and sanitized data
    req[source] = value;
    next();
  };
};

/**
 * Sanitize input to prevent XSS
 */
const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      return obj
        .replace(/[<>]/g, '') // Remove potential HTML tags
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .trim();
    }

    if (Array.isArray(obj)) {
      return obj.map(sanitize);
    }

    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitize(value);
      }
      return sanitized;
    }

    return obj;
  };

  req.body = sanitize(req.body);
  req.query = sanitize(req.query);
  req.params = sanitize(req.params);

  next();
};

module.exports = {
  validate,
  sanitizeInput,
  schemas
};
