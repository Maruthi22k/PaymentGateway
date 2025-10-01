const mongoose = require('mongoose');

const StaffSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  role: {
    type: String,
    required: true,
    enum: ['super_admin', 'admin', 'manager', 'support', 'viewer'],
    default: 'viewer'
  },
  permissions: [{
    type: String,
    enum: [
      'users.read', 'users.write', 'users.delete',
      'transactions.read', 'transactions.write', 'transactions.delete',
      'payments.read', 'payments.write', 'payments.delete',
      'merchants.read', 'merchants.write', 'merchants.delete',
      'reports.read', 'reports.write',
      'settings.read', 'settings.write',
      'staff.read', 'staff.write', 'staff.delete',
      'api_keys.read', 'api_keys.write', 'api_keys.delete',
      'bank_details.read', 'bank_details.write',
      'whitelist.read', 'whitelist.write', 'whitelist.delete',
      'settlements.read', 'settlements.write'
    ]
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    default: null
  },
  profile: {
    data: { type: Buffer },
    contentType: { type: String },
    originalName: { type: String },
    size: { type: Number },
    uploadedAt: { type: Date }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Staff',
    default: null
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Staff',
    default: null
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.twoFactorSecret;
      delete ret.profile;
      return ret;
    }
  }
});

// Index for performance
StaffSchema.index({ email: 1 }, { unique: true });
StaffSchema.index({ role: 1 });
StaffSchema.index({ isActive: 1 });
StaffSchema.index({ createdAt: -1 });

// Virtual for account lock status
StaffSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
StaffSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const bcrypt = require('bcryptjs');
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
StaffSchema.methods.comparePassword = async function(candidatePassword) {
  const bcrypt = require('bcryptjs');
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to increment login attempts
StaffSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }

  return this.updateOne(updates);
};

// Method to reset login attempts
StaffSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Method to check permission
StaffSchema.methods.hasPermission = function(permission) {
  if (this.role === 'super_admin') return true;
  return this.permissions.includes(permission);
};

// Method to check role hierarchy
StaffSchema.methods.hasRole = function(requiredRole) {
  const roleHierarchy = {
    'super_admin': 5,
    'admin': 4,
    'manager': 3,
    'support': 2,
    'viewer': 1
  };

  return roleHierarchy[this.role] >= roleHierarchy[requiredRole];
};

// Static method to get role permissions
StaffSchema.statics.getRolePermissions = function(role) {
  const rolePermissions = {
    'super_admin': [
      'users.read', 'users.write', 'users.delete',
      'transactions.read', 'transactions.write', 'transactions.delete',
      'payments.read', 'payments.write', 'payments.delete',
      'merchants.read', 'merchants.write', 'merchants.delete',
      'reports.read', 'reports.write',
      'settings.read', 'settings.write',
      'staff.read', 'staff.write', 'staff.delete',
      'api_keys.read', 'api_keys.write', 'api_keys.delete',
      'bank_details.read', 'bank_details.write',
      'whitelist.read', 'whitelist.write', 'whitelist.delete',
      'settlements.read', 'settlements.write'
    ],
    'admin': [
      'users.read', 'users.write',
      'transactions.read', 'transactions.write',
      'payments.read', 'payments.write',
      'merchants.read', 'merchants.write',
      'reports.read', 'reports.write',
      'staff.read', 'staff.write',
      'api_keys.read', 'api_keys.write',
      'bank_details.read', 'bank_details.write',
      'whitelist.read', 'whitelist.write',
      'settlements.read', 'settlements.write'
    ],
    'manager': [
      'users.read',
      'transactions.read', 'transactions.write',
      'payments.read', 'payments.write',
      'merchants.read', 'merchants.write',
      'reports.read',
      'api_keys.read', 'api_keys.write',
      'bank_details.read', 'bank_details.write',
      'whitelist.read', 'whitelist.write',
      'settlements.read', 'settlements.write'
    ],
    'support': [
      'users.read',
      'transactions.read',
      'payments.read',
      'merchants.read',
      'reports.read',
      'api_keys.read',
      'bank_details.read',
      'whitelist.read',
      'settlements.read'
    ],
    'viewer': [
      'transactions.read',
      'payments.read',
      'merchants.read',
      'reports.read',
      'settlements.read'
    ]
  };

  return rolePermissions[role] || [];
};

module.exports = mongoose.model('Staff', StaffSchema);
