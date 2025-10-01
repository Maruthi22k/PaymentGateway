const bcrypt = require('bcryptjs');
const User = require('../Models/Merchants');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { securityLogger } = require('../Util/logger');
const { ValidationError, AuthenticationError, ConflictError, NotFoundError, AuthorizationError } = require('../middleware/errorHandler');
const crypto = require('crypto');

// Helper function to send welcome message
const sendWelcomeMessage = async(firstName, mobile) => {
  try {
    const mobileNumber = `91${mobile}`;
    const tenantId = process.env.WHATSAPP_TENANT_ID || '386174';
    const url = `https://live-mt-server.wati.io/${tenantId}/api/v1/sendTemplateMessage?whatsappNumber=${mobileNumber}`;
    const authorizationToken = `Bearer ${process.env.WHATSAPP_AUTH_TOKEN}`;

    const data = {
      template_name: 'welcome_jpay',
      broadcast_name: 'welcome_jpay',
      parameters: [
        {
          name: 'name',
          value: firstName
        }
      ]
    };

    const response = await axios.post(url, data, {
      headers: {
        Authorization: authorizationToken,
        Accept: '*/*',
        'Content-Type': 'application/json-patch+json'
      }
    });

    return response.data;
  } catch (error) {
    throw new Error(`WhatsApp message failed: ${error.message}`);
  }
};

exports.registerUser = async(req, res, next) => {
  try {
    const { firstName, lastName, email, password, mobile, isCollectingPayments, websiteUrl } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ConflictError('Merchant already exists with this email address.');
    }

    // Check if mobile number already exists
    const existingMobile = await User.findOne({ mobile });
    if (existingMobile) {
      throw new ConflictError('Merchant already exists with this mobile number.');
    }

    // Hash the password with secure cost factor
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      mobile,
      isCollectingPayments,
      websiteUrl
    });

    // Save the user to the database
    await user.save();

    // Log successful registration
    securityLogger.authSuccess({
      userId: user._id,
      email: user.email,
      mobile: user.mobile,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send WhatsApp template message (moved to background task)
    try {
      await sendWelcomeMessage(user.firstName, user.mobile);
    } catch (err) {
      // Log error but don't fail registration
      securityLogger.securityEvent('whatsapp_send_failed', {
        userId: user._id,
        error: err.message
      });
    }

    // Return user data without sensitive information
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      mobile: user.mobile,
      isCollectingPayments: user.isCollectingPayments,
      websiteUrl: user.websiteUrl,
      mode: user.mode,
      kyc: user.kyc,
      createdAt: user.createdAt
    };

    res.status(201).json({
      message: 'Merchant registered successfully.',
      user: userResponse
    });
  } catch (error) {
    next(error);
  }
};


exports.loginUser = async(req, res, next) => {
  try {
    const { email, password } = req.body;

    // Log login attempt
    securityLogger.authAttempt({
      email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      securityLogger.authFailure({
        email,
        reason: 'user_not_found',
        ip: req.ip
      });
      throw new AuthenticationError('Invalid credentials.');
    }

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      securityLogger.authFailure({
        userId: user._id,
        email,
        reason: 'invalid_password',
        ip: req.ip
      });
      throw new AuthenticationError('Invalid credentials.');
    }

    // Generate JWT token with secure configuration
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        mobile: user.mobile,
        mode: user.mode
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer: process.env.JWT_ISSUER || 'jcs-pay',
        audience: process.env.JWT_AUDIENCE || 'jcs-pay-api',
        notBefore: 0
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      {
        userId: user._id,
        type: 'refresh'
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
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Return user data without sensitive information
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      mobile: user.mobile,
      mode: user.mode,
      kyc: user.kyc,
      isCollectingPayments: user.isCollectingPayments,
      websiteUrl: user.websiteUrl
    };

    res.status(200).json({
      message: 'Login successful',
      token,
      refreshToken,
      user: userResponse
    });
  } catch (error) {
    next(error);
  }
};

// In-memory OTP storage (use Redis in production)
const otpStorage = new Map();

// Helper function to generate secure OTP
const generateSecureOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Helper function to send SMS
const sendSMS = async(mobile, message) => {
  try {
    const apikey = process.env.SMS_API_KEY;
    const apisender = process.env.SMS_SENDER_ID || 'JPAYTX';
    const encodedMessage = encodeURIComponent(message);
    const formattedMobile = mobile.toString();
    const smsURL = `https://www.smsgatewayhub.com/api/mt/SendSMS?APIKey=${apikey}&senderid=${apisender}&channel=2&DCS=0&flashsms=0&number=${formattedMobile}&text=${encodedMessage}&route=1`;

    const smsResponse = await axios.get(smsURL);
    return smsResponse.data;
  } catch (error) {
    throw new Error(`SMS sending failed: ${error.message}`);
  }
};

exports.sendOTP = async(req, res, next) => {
  try {
    const { mobile } = req.body;

    // Log OTP request
    securityLogger.securityEvent('otp_request', {
      mobile,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Find user by mobile number
    const user = await User.findOne({ mobile });
    if (!user) {
      securityLogger.authFailure({
        mobile,
        reason: 'user_not_found',
        ip: req.ip
      });
      throw new AuthenticationError('User not found with this mobile number');
    }

    // Check if OTP was recently sent (rate limiting)
    const existingOTP = otpStorage.get(mobile);
    if (existingOTP && (Date.now() - existingOTP.timestamp) < 60000) { // 1 minute cooldown
      throw new ValidationError('Please wait before requesting another OTP');
    }

    // Generate a secure 6-digit OTP
    const otp = generateSecureOTP();

    // Save the OTP with expiration time (5 minutes)
    const expiry = Date.now() + 5 * 60 * 1000;
    otpStorage.set(mobile, {
      otp: otp,
      expiry: expiry,
      userId: user._id,
      timestamp: Date.now(),
      attempts: 0
    });

    // Prepare message
    const message = `Dear User, your OTP for JPay login is ${otp}. Do not share it with anyone. This OTP is valid for 5 minutes. - JCS GLOBAL`;

    // Send SMS
    const smsResponse = await sendSMS(mobile, message);

    if (smsResponse && smsResponse.ErrorCode === '000') {
      securityLogger.securityEvent('otp_sent', {
        userId: user._id,
        mobile,
        ip: req.ip
      });

      res.status(200).json({
        success: true,
        message: 'OTP sent successfully'
      });
    } else {
      throw new Error(`SMS Gateway error: ${JSON.stringify(smsResponse)}`);
    }

  } catch (error) {
    next(error);
  }
};


// Verify OTP and authenticate user
exports.verifyOTP = async(req, res, next) => {
  try {
    const { mobile, otp } = req.body;

    // Log OTP verification attempt
    securityLogger.securityEvent('otp_verification_attempt', {
      mobile,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Check if OTP exists and is valid
    const otpData = otpStorage.get(mobile);

    if (!otpData) {
      securityLogger.authFailure({
        mobile,
        reason: 'otp_not_found',
        ip: req.ip
      });
      throw new AuthenticationError('OTP expired or not found. Please request a new OTP.');
    }

    // Check if OTP has expired
    if (Date.now() > otpData.expiry) {
      otpStorage.delete(mobile);
      securityLogger.authFailure({
        mobile,
        reason: 'otp_expired',
        ip: req.ip
      });
      throw new AuthenticationError('OTP has expired. Please request a new one.');
    }

    // Check attempt limit (max 3 attempts)
    if (otpData.attempts >= 3) {
      otpStorage.delete(mobile);
      securityLogger.suspiciousActivity({
        mobile,
        reason: 'otp_max_attempts_exceeded',
        ip: req.ip
      });
      throw new AuthenticationError('Maximum OTP attempts exceeded. Please request a new OTP.');
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      // Increment attempt counter
      otpData.attempts += 1;
      otpStorage.set(mobile, otpData);

      securityLogger.authFailure({
        mobile,
        reason: 'invalid_otp',
        attempts: otpData.attempts,
        ip: req.ip
      });
      throw new AuthenticationError('Invalid OTP. Please try again.');
    }

    // OTP is valid, fetch the user
    const user = await User.findById(otpData.userId);
    if (!user) {
      throw new AuthenticationError('User not found');
    }

    // Generate JWT token with secure configuration
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        mobile: user.mobile,
        mode: user.mode
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
        userId: user._id,
        type: 'refresh'
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
        issuer: process.env.JWT_ISSUER || 'jcs-pay',
        audience: process.env.JWT_AUDIENCE || 'jcs-pay-api'
      }
    );

    // Delete the used OTP
    otpStorage.delete(mobile);

    // Log successful OTP verification
    securityLogger.authSuccess({
      userId: user._id,
      mobile: user.mobile,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Get user data to send back to the frontend
    const userData = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      mobile: user.mobile,
      profile: user.profile,
      mode: user.mode,
      kyc: user.kyc,
      isCollectingPayments: user.isCollectingPayments,
      websiteUrl: user.websiteUrl
    };

    res.status(200).json({
      message: 'OTP verification successful',
      token,
      refreshToken,
      user: userData
    });
  } catch (error) {
    next(error);
  }
};

exports.getUserData = async(req, res, next) => {
  try {
    const { _id } = req.body;

    // Fetch user data from the database
    const user = await User.findById(_id).select('firstName lastName profile mode kyc mobile email isCollectingPayments websiteUrl createdAt'); // Select only necessary fields

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Respond with the user data
    res.status(200).json(user);
  } catch (error) {
    next(error);
  }
};

exports.updatePassword = async(req, res, next) => {
  try {
    const { _id, currentPassword, newPassword } = req.body;

    // Find user by ID
    const user = await User.findById(_id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    // Check if the current password matches
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      securityLogger.authFailure({
        userId: _id,
        reason: 'incorrect_current_password',
        ip: req.ip
      });
      throw new AuthenticationError('Incorrect current password');
    }

    // Hash new password with secure cost factor
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    user.password = await bcrypt.hash(newPassword, saltRounds);

    // Save updated password
    await user.save();

    // Log password update
    securityLogger.securityEvent('password_updated', {
      userId: _id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    next(error);
  }
};


exports.changeMode = async(req, res, next) => {
  try {
    const { _id, mode } = req.body;

    // Fetch user data from the database
    const user = await User.findById(_id).select('firstName lastName profile mode kyc'); // Select only necessary fields

    if (!user) {
      throw new NotFoundError('User not found');
    }

    // If KYC is not verified (kyc !== 1), do not allow any mode change
    if (user.kyc !== 1) {
      securityLogger.authzFailure({
        userId: _id,
        reason: 'kyc_not_verified',
        requestedMode: mode,
        ip: req.ip
      });
      throw new AuthorizationError('You are not allowed to change the mode until your KYC is verified');
    }

    // Update mode if KYC is verified
    user.mode = mode;
    await user.save();

    // Log mode change
    securityLogger.securityEvent('mode_changed', {
      userId: _id,
      oldMode: user.mode,
      newMode: mode,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Respond with the updated user data
    res.status(200).json({ message: `Mode changed to ${mode}`, user });
  } catch (error) {
    next(error);
  }
};


