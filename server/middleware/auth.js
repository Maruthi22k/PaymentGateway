const jwt = require('jsonwebtoken');
const User = require('../Models/Merchants');
const Staff = require('../Models/Staff');
const logger = require('../Util/logger');

/**
 * Centralized JWT Authentication Middleware
 * Validates JWT tokens with comprehensive security checks
 */
const authenticateToken = async(req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      logger.warn('Authentication failed: No token provided', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path
      });
      return res.status(401).json({
        error: 'Access denied. No token provided.'
      });
    }

    // Verify JWT token with comprehensive validation
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // Specify allowed algorithms
      issuer: process.env.JWT_ISSUER || 'jcs-pay', // Validate issuer
      audience: process.env.JWT_AUDIENCE || 'jcs-pay-api', // Validate audience
      clockTolerance: 30 // Allow 30 seconds clock skew
    });

    // Check if user still exists and is active
    let user = null;
    let userType = 'merchant';

    if (decoded.type === 'staff') {
      user = await Staff.findById(decoded.staffId).select('-password -twoFactorSecret');
      userType = 'staff';
    } else {
      user = await User.findById(decoded.userId).select('-password');
    }

    if (!user) {
      logger.warn('Authentication failed: User not found', {
        userId: decoded.userId || decoded.staffId,
        userType,
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({
        error: 'Access denied. User not found.'
      });
    }

    // Check if token is in revocation list (implement with Redis in production)
    // For now, we'll implement a simple in-memory check
    if (await isTokenRevoked(token)) {
      logger.warn('Authentication failed: Token revoked', {
        userId: decoded.userId,
        ip: req.ip,
        path: req.path
      });
      return res.status(401).json({
        error: 'Access denied. Token has been revoked.'
      });
    }

    // Add user info to request object
    if (userType === 'staff') {
      req.user = {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        permissions: user.permissions,
        isActive: user.isActive,
        type: 'staff'
      };
    } else {
      req.user = {
        id: user._id,
        email: user.email,
        mobile: user.mobile,
        firstName: user.firstName,
        lastName: user.lastName,
        mode: user.mode,
        kyc: user.kyc,
        type: 'merchant'
      };
    }

    logger.info('Authentication successful', {
      userId: user._id,
      email: user.email,
      userType,
      ip: req.ip,
      path: req.path
    });

    next();
  } catch (error) {
    logger.error('Authentication error', {
      error: error.message,
      ip: req.ip,
      path: req.path,
      userAgent: req.get('User-Agent')
    });

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access denied. Token has expired.'
      });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Access denied. Invalid token.'
      });
    } else if (error.name === 'NotBeforeError') {
      return res.status(401).json({
        error: 'Access denied. Token not active yet.'
      });
    }

    return res.status(500).json({
      error: 'Internal server error during authentication.'
    });
  }
};

/**
 * Check if token is in revocation list
 * In production, implement with Redis for distributed systems
 */
const isTokenRevoked = async() => {
  // TODO: Implement Redis-based token revocation list
  // For now, return false (no tokens revoked)
  return false;
};

/**
 * Authorization middleware for role-based access control
 */
const authorize = (roles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Access denied. Authentication required.'
      });
    }

    // Check if user has required role
    if (roles.length > 0 && !roles.includes(req.user.role)) {
      logger.warn('Authorization failed: Insufficient role', {
        userId: req.user.id,
        userType: req.user.type,
        requiredRoles: roles,
        userRole: req.user.role,
        ip: req.ip,
        path: req.path
      });
      return res.status(403).json({
        error: 'Access denied. Insufficient permissions.'
      });
    }

    next();
  };
};

/**
 * Permission-based authorization middleware
 */
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Access denied. Authentication required.'
      });
    }

    // Check if user has required permission
    if (req.user.type === 'staff' && !req.user.hasPermission(permission)) {
      logger.warn('Authorization failed: Insufficient permission', {
        userId: req.user.id,
        userType: req.user.type,
        requiredPermission: permission,
        userPermissions: req.user.permissions,
        ip: req.ip,
        path: req.path
      });
      return res.status(403).json({
        error: 'Access denied. Insufficient permissions.'
      });
    }

    // Merchants don't have permission-based access
    if (req.user.type === 'merchant') {
      logger.warn('Authorization failed: Merchant accessing staff endpoint', {
        userId: req.user.id,
        userType: req.user.type,
        requiredPermission: permission,
        ip: req.ip,
        path: req.path
      });
      return res.status(403).json({
        error: 'Access denied. Staff access required.'
      });
    }

    next();
  };
};

/**
 * Middleware to ensure KYC verification
 */
const requireKYC = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Access denied. Authentication required.'
    });
  }

  if (req.user.kyc !== 1) {
    logger.warn('KYC verification required', {
      userId: req.user.id,
      kycStatus: req.user.kyc,
      ip: req.ip,
      path: req.path
    });
    return res.status(403).json({
      error: 'Access denied. KYC verification required.'
    });
  }

  next();
};

module.exports = {
  authenticateToken,
  authorize,
  requirePermission,
  requireKYC,
  isTokenRevoked
};
