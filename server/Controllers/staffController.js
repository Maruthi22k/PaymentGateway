const Staff = require('../Models/Staff');
const jwt = require('jsonwebtoken');
const { securityLogger } = require('../Util/logger');
const {
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  NotFoundError
} = require('../middleware/errorHandler');

// Staff registration (only by super_admin or admin)
exports.registerStaff = async(req, res, next) => {
  try {
    const { firstName, lastName, email, password, role, permissions } = req.body;

    // Check if staff already exists
    const existingStaff = await Staff.findOne({ email });
    if (existingStaff) {
      throw new ConflictError('Staff member already exists with this email address.');
    }

    // Validate role hierarchy
    if (!req.user.hasRole('admin')) {
      throw new AuthorizationError('Insufficient permissions to create staff members.');
    }

    // Validate role assignment
    if (role === 'super_admin' && req.user.role !== 'super_admin') {
      throw new AuthorizationError('Only super admin can create super admin accounts.');
    }

    // Get default permissions for role if not provided
    const defaultPermissions = permissions || Staff.getRolePermissions(role);

    // Create new staff member
    const staff = new Staff({
      firstName,
      lastName,
      email,
      password,
      role,
      permissions: defaultPermissions,
      createdBy: req.user.id
    });

    await staff.save();

    // Log staff creation
    securityLogger.securityEvent('staff_created', {
      staffId: staff._id,
      email: staff.email,
      role: staff.role,
      createdBy: req.user.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Return staff data without sensitive information
    const staffResponse = {
      _id: staff._id,
      firstName: staff.firstName,
      lastName: staff.lastName,
      email: staff.email,
      role: staff.role,
      permissions: staff.permissions,
      isActive: staff.isActive,
      createdAt: staff.createdAt
    };

    res.status(201).json({
      message: 'Staff member created successfully.',
      staff: staffResponse
    });
  } catch (error) {
    next(error);
  }
};

// Staff login
exports.loginStaff = async(req, res, next) => {
  try {
    const { email, password } = req.body;

    // Log login attempt
    securityLogger.authAttempt({
      email,
      type: 'staff_login',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Find staff member
    const staff = await Staff.findOne({ email });
    if (!staff) {
      securityLogger.authFailure({
        email,
        type: 'staff_login',
        reason: 'staff_not_found',
        ip: req.ip
      });
      throw new AuthenticationError('Invalid credentials.');
    }

    // Check if account is locked
    if (staff.isLocked) {
      securityLogger.authFailure({
        staffId: staff._id,
        email,
        type: 'staff_login',
        reason: 'account_locked',
        ip: req.ip
      });
      throw new AuthenticationError('Account is temporarily locked due to multiple failed login attempts.');
    }

    // Check if account is active
    if (!staff.isActive) {
      securityLogger.authFailure({
        staffId: staff._id,
        email,
        type: 'staff_login',
        reason: 'account_inactive',
        ip: req.ip
      });
      throw new AuthenticationError('Account is inactive. Please contact administrator.');
    }

    // Compare password
    const isMatch = await staff.comparePassword(password);
    if (!isMatch) {
      // Increment login attempts
      await staff.incLoginAttempts();

      securityLogger.authFailure({
        staffId: staff._id,
        email,
        type: 'staff_login',
        reason: 'invalid_password',
        ip: req.ip
      });
      throw new AuthenticationError('Invalid credentials.');
    }

    // Reset login attempts on successful login
    await staff.resetLoginAttempts();

    // Update last login
    await Staff.findByIdAndUpdate(staff._id, { lastLogin: new Date() });

    // Generate JWT token
    const token = jwt.sign(
      {
        staffId: staff._id,
        email: staff.email,
        role: staff.role,
        permissions: staff.permissions,
        type: 'staff'
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer: process.env.JWT_ISSUER || 'jcs-pay',
        audience: process.env.JWT_AUDIENCE || 'jcs-pay-api'
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      {
        staffId: staff._id,
        type: 'staff_refresh'
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
        issuer: process.env.JWT_ISSUER || 'jcs-pay',
        audience: process.env.JWT_AUDIENCE || 'jcs-pay-api'
      }
    );

    // Log successful login
    securityLogger.authSuccess({
      staffId: staff._id,
      email: staff.email,
      role: staff.role,
      type: 'staff_login',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Return staff data without sensitive information
    const staffResponse = {
      _id: staff._id,
      firstName: staff.firstName,
      lastName: staff.lastName,
      email: staff.email,
      role: staff.role,
      permissions: staff.permissions,
      isActive: staff.isActive,
      lastLogin: staff.lastLogin
    };

    res.status(200).json({
      message: 'Login successful',
      token,
      refreshToken,
      staff: staffResponse
    });
  } catch (error) {
    next(error);
  }
};

// Get all staff members (with pagination and filtering)
exports.getStaffMembers = async(req, res, next) => {
  try {
    const { page = 1, limit = 10, role, isActive, search } = req.query;
    const skip = (page - 1) * limit;

    // Build filter
    const filter = {};
    if (role) filter.role = role;
    if (isActive !== undefined) filter.isActive = isActive === 'true';
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    // Get staff members
    const staffMembers = await Staff.find(filter)
      .select('-password -twoFactorSecret')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('createdBy', 'firstName lastName email')
      .populate('updatedBy', 'firstName lastName email');

    // Get total count
    const total = await Staff.countDocuments(filter);

    // Log staff access
    securityLogger.securityEvent('staff_list_accessed', {
      requestedBy: req.user.id,
      filters: filter,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({
      staffMembers,
      pagination: {
        current: parseInt(page),
        pages: Math.ceil(total / limit),
        total
      }
    });
  } catch (error) {
    next(error);
  }
};

// Get staff member by ID
exports.getStaffMember = async(req, res, next) => {
  try {
    const { staffId } = req.params;

    const staff = await Staff.findById(staffId)
      .select('-password -twoFactorSecret')
      .populate('createdBy', 'firstName lastName email')
      .populate('updatedBy', 'firstName lastName email');

    if (!staff) {
      throw new NotFoundError('Staff member not found.');
    }

    // Log staff access
    securityLogger.securityEvent('staff_accessed', {
      staffId,
      requestedBy: req.user.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json(staff);
  } catch (error) {
    next(error);
  }
};

// Update staff member
exports.updateStaffMember = async(req, res, next) => {
  try {
    const { staffId } = req.params;
    const { firstName, lastName, email, role, permissions, isActive } = req.body;

    const staff = await Staff.findById(staffId);
    if (!staff) {
      throw new NotFoundError('Staff member not found.');
    }

    // Check permissions
    if (req.user.id !== staffId && !req.user.hasPermission('staff.write')) {
      throw new AuthorizationError('Insufficient permissions to update staff members.');
    }

    // Validate role hierarchy
    if (role && role !== staff.role) {
      if (!req.user.hasRole('admin')) {
        throw new AuthorizationError('Insufficient permissions to change staff roles.');
      }
      if (role === 'super_admin' && req.user.role !== 'super_admin') {
        throw new AuthorizationError('Only super admin can assign super admin role.');
      }
    }

    // Update fields
    if (firstName) staff.firstName = firstName;
    if (lastName) staff.lastName = lastName;
    if (email) staff.email = email;
    if (role) staff.role = role;
    if (permissions) staff.permissions = permissions;
    if (isActive !== undefined) staff.isActive = isActive;
    staff.updatedBy = req.user.id;

    await staff.save();

    // Log staff update
    securityLogger.securityEvent('staff_updated', {
      staffId,
      updatedBy: req.user.id,
      changes: req.body,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Return updated staff data
    const staffResponse = {
      _id: staff._id,
      firstName: staff.firstName,
      lastName: staff.lastName,
      email: staff.email,
      role: staff.role,
      permissions: staff.permissions,
      isActive: staff.isActive,
      updatedAt: staff.updatedAt
    };

    res.status(200).json({
      message: 'Staff member updated successfully.',
      staff: staffResponse
    });
  } catch (error) {
    next(error);
  }
};

// Delete staff member
exports.deleteStaffMember = async(req, res, next) => {
  try {
    const { staffId } = req.params;

    const staff = await Staff.findById(staffId);
    if (!staff) {
      throw new NotFoundError('Staff member not found.');
    }

    // Check permissions
    if (!req.user.hasPermission('staff.delete')) {
      throw new AuthorizationError('Insufficient permissions to delete staff members.');
    }

    // Prevent self-deletion
    if (req.user.id === staffId) {
      throw new ValidationError('Cannot delete your own account.');
    }

    // Prevent deletion of super admin by non-super admin
    if (staff.role === 'super_admin' && req.user.role !== 'super_admin') {
      throw new AuthorizationError('Only super admin can delete super admin accounts.');
    }

    await Staff.findByIdAndDelete(staffId);

    // Log staff deletion
    securityLogger.securityEvent('staff_deleted', {
      staffId,
      deletedBy: req.user.id,
      staffEmail: staff.email,
      staffRole: staff.role,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({
      message: 'Staff member deleted successfully.'
    });
  } catch (error) {
    next(error);
  }
};

// Change password
exports.changePassword = async(req, res, next) => {
  try {
    const { staffId } = req.params;
    const { currentPassword, newPassword } = req.body;

    const staff = await Staff.findById(staffId);
    if (!staff) {
      throw new NotFoundError('Staff member not found.');
    }

    // Check if user is changing their own password or has permission
    if (req.user.id !== staffId && !req.user.hasPermission('staff.write')) {
      throw new AuthorizationError('Insufficient permissions to change password.');
    }

    // Verify current password
    const isMatch = await staff.comparePassword(currentPassword);
    if (!isMatch) {
      securityLogger.authFailure({
        staffId,
        reason: 'incorrect_current_password',
        type: 'password_change',
        ip: req.ip
      });
      throw new AuthenticationError('Incorrect current password.');
    }

    // Update password
    staff.password = newPassword;
    staff.updatedBy = req.user.id;
    await staff.save();

    // Log password change
    securityLogger.securityEvent('staff_password_changed', {
      staffId,
      changedBy: req.user.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({
      message: 'Password changed successfully.'
    });
  } catch (error) {
    next(error);
  }
};

// Get staff permissions
exports.getStaffPermissions = async(req, res, next) => {
  try {
    const { role } = req.query;

    if (role) {
      const permissions = Staff.getRolePermissions(role);
      res.status(200).json({ role, permissions });
    } else {
      // Return all role permissions
      const roles = ['super_admin', 'admin', 'manager', 'support', 'viewer'];
      const rolePermissions = {};

      roles.forEach(roleName => {
        rolePermissions[roleName] = Staff.getRolePermissions(roleName);
      });

      res.status(200).json(rolePermissions);
    }
  } catch (error) {
    next(error);
  }
};
