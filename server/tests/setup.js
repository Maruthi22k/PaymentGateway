// Test setup file
// const { logger } = require('../Util/logger');

// Mock logger for tests
jest.mock('../Util/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  },
  securityLogger: {
    authAttempt: jest.fn(),
    authSuccess: jest.fn(),
    authFailure: jest.fn(),
    authzFailure: jest.fn(),
    suspiciousActivity: jest.fn(),
    rateLimit: jest.fn(),
    validationFailure: jest.fn(),
    securityEvent: jest.fn()
  },
  maskSensitiveData: jest.fn((data) => data)
}));

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-testing-only';
process.env.JWT_EXPIRES_IN = '1h';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.BCRYPT_ROUNDS = '4'; // Lower for faster tests
process.env.MONGODB_URI = 'mongodb://localhost:27017/merchants-test';
process.env.REDIS_URL = 'redis://localhost:6379/1';
process.env.ALLOWED_ORIGINS = 'http://localhost:3000,http://localhost:5173';

// Global test timeout
jest.setTimeout(10000);

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global error handler for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Global error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});
