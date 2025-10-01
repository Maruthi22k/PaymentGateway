const winston = require('winston');
const path = require('path');

// Sensitive fields that should be masked in logs
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'authorization',
  'cookie',
  'secret',
  'key',
  'apiKey',
  'apikey',
  'auth',
  'credential',
  'otp',
  'pin',
  'ssn',
  'creditCard',
  'cardNumber',
  'cvv',
  'salt'
];

// PII fields that should be masked
const PII_FIELDS = [
  'email',
  'mobile',
  'phone',
  'firstName',
  'lastName',
  'address',
  'ip',
  'userAgent'
];

/**
 * Mask sensitive data in objects
 */
const maskSensitiveData = (obj, fieldsToMask = [...SENSITIVE_FIELDS, ...PII_FIELDS]) => {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }

  const masked = Array.isArray(obj) ? [] : {};

  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();

    // Check if this field should be masked
    const shouldMask = fieldsToMask.some(field =>
      lowerKey.includes(field.toLowerCase())
    );

    if (shouldMask) {
      if (typeof value === 'string' && value.length > 0) {
        // Mask the value, showing only first and last 2 characters
        if (value.length <= 4) {
          masked[key] = '*'.repeat(value.length);
        } else {
          masked[key] = value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
        }
      } else {
        masked[key] = '[MASKED]';
      }
    } else if (typeof value === 'object' && value !== null) {
      // Recursively mask nested objects
      masked[key] = maskSensitiveData(value, fieldsToMask);
    } else {
      masked[key] = value;
    }
  }

  return masked;
};

// Custom format for winston
const customFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    // Mask sensitive data in metadata
    const maskedMeta = maskSensitiveData(meta);

    return JSON.stringify({
      timestamp,
      level,
      message,
      ...maskedMeta
    });
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: customFormat,
  defaultMeta: { service: 'jcs-pay-api' },
  transports: [
    // Write all logs to console
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),

    // Write all logs with level 'error' and below to error.log
    new winston.transports.File({
      filename: path.join('logs', 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),

    // Write all logs to combined.log
    new winston.transports.File({
      filename: path.join('logs', 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ],

  // Handle exceptions and rejections
  exceptionHandlers: [
    new winston.transports.File({ filename: path.join('logs', 'exceptions.log') })
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: path.join('logs', 'rejections.log') })
  ]
});

// Security-specific logging methods
const securityLogger = {
  // Log authentication attempts
  authAttempt: (data) => {
    logger.info('Authentication attempt', {
      type: 'auth_attempt',
      ...maskSensitiveData(data)
    });
  },

  // Log successful authentication
  authSuccess: (data) => {
    logger.info('Authentication successful', {
      type: 'auth_success',
      ...maskSensitiveData(data)
    });
  },

  // Log authentication failures
  authFailure: (data) => {
    logger.warn('Authentication failed', {
      type: 'auth_failure',
      ...maskSensitiveData(data)
    });
  },

  // Log authorization failures
  authzFailure: (data) => {
    logger.warn('Authorization failed', {
      type: 'authz_failure',
      ...maskSensitiveData(data)
    });
  },

  // Log suspicious activities
  suspiciousActivity: (data) => {
    logger.warn('Suspicious activity detected', {
      type: 'suspicious_activity',
      ...maskSensitiveData(data)
    });
  },

  // Log rate limiting
  rateLimit: (data) => {
    logger.warn('Rate limit exceeded', {
      type: 'rate_limit',
      ...maskSensitiveData(data)
    });
  },

  // Log input validation failures
  validationFailure: (data) => {
    logger.warn('Input validation failed', {
      type: 'validation_failure',
      ...maskSensitiveData(data)
    });
  },

  // Log security events
  securityEvent: (event, data) => {
    logger.warn('Security event', {
      type: 'security_event',
      event,
      ...maskSensitiveData(data)
    });
  }
};

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

module.exports = {
  logger,
  securityLogger,
  maskSensitiveData
};
