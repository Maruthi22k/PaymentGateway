const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('redis');
const logger = require('../Util/logger');

// Redis client for distributed rate limiting
let redisClient = null;

// Initialize Redis client if available
const initRedis = async() => {
  try {
    if (process.env.REDIS_URL) {
      redisClient = Redis.createClient({
        url: process.env.REDIS_URL
      });

      redisClient.on('error', (err) => {
        logger.error('Redis connection error', { error: err.message });
      });

      await redisClient.connect();
      logger.info('Redis connected for rate limiting');
    }
  } catch (error) {
    logger.warn('Redis not available, using memory store for rate limiting', {
      error: error.message
    });
  }
};

// Initialize Redis on startup
initRedis();

// Base rate limiter configuration
const createRateLimiter = (options = {}) => {
  const defaultOptions = {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.ceil((options.windowMs || 15 * 60 * 1000) / 1000)
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        userId: req.user?.id
      });

      res.status(429).json({
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil((options.windowMs || 15 * 60 * 1000) / 1000)
      });
    },
    skip: (req) => {
      // Skip rate limiting for health checks and internal requests
      return req.path === '/health' || req.ip === '127.0.0.1';
    }
  };

  // Use Redis store if available, otherwise use memory store
  if (redisClient) {
    defaultOptions.store = new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args)
    });
  }

  return rateLimit({ ...defaultOptions, ...options });
};

// Specific rate limiters for different endpoints
const rateLimiters = {
  // General API rate limiter
  general: createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // 100 requests per 15 minutes
  }),

  // Strict rate limiter for authentication endpoints
  auth: createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per 15 minutes
    message: {
      error: 'Too many authentication attempts, please try again later.',
      retryAfter: 900 // 15 minutes in seconds
    }
  }),

  // Rate limiter for OTP operations
  otp: createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 3, // 3 OTP requests per 5 minutes
    message: {
      error: 'Too many OTP requests, please try again later.',
      retryAfter: 300 // 5 minutes in seconds
    }
  }),

  // Rate limiter for payment operations
  payment: createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // 10 payment requests per minute
    message: {
      error: 'Too many payment requests, please try again later.',
      retryAfter: 60 // 1 minute in seconds
    }
  }),

  // Rate limiter for password reset operations
  passwordReset: createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 password reset attempts per hour
    message: {
      error: 'Too many password reset attempts, please try again later.',
      retryAfter: 3600 // 1 hour in seconds
    }
  }),

  // Rate limiter for webhook endpoints
  webhook: createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // 100 webhook requests per minute
    message: {
      error: 'Too many webhook requests, please try again later.',
      retryAfter: 60 // 1 minute in seconds
    }
  }),

  // Rate limiter for file uploads
  upload: createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // 20 uploads per hour
    message: {
      error: 'Too many file uploads, please try again later.',
      retryAfter: 3600 // 1 hour in seconds
    }
  })
};

// Dynamic rate limiter based on user role
const createUserBasedRateLimiter = (baseLimiter) => {
  return (req, res, next) => {
    // Adjust rate limits based on user role or subscription
    if (req.user) {
      // Premium users get higher limits
      if (req.user.role === 'premium') {
        req.rateLimit = {
          ...baseLimiter,
          max: baseLimiter.max * 2
        };
      }
      // Admin users get even higher limits
      else if (req.user.role === 'admin') {
        req.rateLimit = {
          ...baseLimiter,
          max: baseLimiter.max * 5
        };
      }
    }

    baseLimiter(req, res, next);
  };
};

// Rate limiter for brute force protection
const bruteForceProtection = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 failed attempts per 15 minutes
  skipSuccessfulRequests: true, // Don't count successful requests
  message: {
    error: 'Too many failed attempts, please try again later.',
    retryAfter: 900 // 15 minutes in seconds
  }
});

module.exports = {
  rateLimiters,
  createRateLimiter,
  createUserBasedRateLimiter,
  bruteForceProtection
};
