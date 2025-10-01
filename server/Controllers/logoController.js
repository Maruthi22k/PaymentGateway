const multer = require('multer');
const Merchant = require('../Models/Merchants');
const { securityLogger } = require('../Util/logger');
const { NotFoundError, ValidationError } = require('../middleware/errorHandler');

// Set up file storage in memory (buffer)
const storage = multer.memoryStorage();

// Set file size limit (e.g., 5 MB) and validate MIME type for image files
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB limit
    files: 1 // Only allow 1 file
  },
  fileFilter: (req, file, cb) => {
    // Allow only image files with strict validation
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

    // Check MIME type
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(new ValidationError('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'), false);
    }

    // Check file extension
    const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    if (!allowedExtensions.includes(fileExtension)) {
      return cb(new ValidationError('Invalid file extension. Only .jpg, .jpeg, .png, .gif, and .webp files are allowed.'), false);
    }

    // Check for suspicious file names
    if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
      return cb(new ValidationError('Invalid file name. File name contains suspicious characters.'), false);
    }

    cb(null, true);
  }
}).single('profile');

// Export the upload middleware as part of the module
module.exports = {
  upload, // Export upload middleware
  uploadProfile: async(req, res, next) => {
    try {
      const { merchantId } = req.params;

      // Log profile upload attempt
      securityLogger.securityEvent('profile_upload_attempt', {
        merchantId,
        requestedBy: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      if (!req.file) {
        throw new ValidationError('No file uploaded');
      }

      // Find merchant by _id
      const merchant = await Merchant.findById(merchantId);
      if (!merchant) {
        throw new NotFoundError('Merchant not found');
      }

      // Additional security checks
      if (req.file.size > 5 * 1024 * 1024) { // 5MB limit
        throw new ValidationError('File size exceeds 5MB limit');
      }

      // Update the merchant profile picture
      merchant.profile = {
        data: req.file.buffer, // Store image as binary data (Buffer)
        contentType: req.file.mimetype, // Store MIME type
        originalName: req.file.originalname,
        size: req.file.size,
        uploadedAt: new Date()
      };

      await merchant.save();

      securityLogger.securityEvent('profile_uploaded', {
        merchantId,
        requestedBy: req.user?.id,
        fileSize: req.file.size,
        contentType: req.file.mimetype,
        ip: req.ip
      });

      res.status(200).json({
        message: 'Profile updated successfully',
        fileInfo: {
          originalName: req.file.originalname,
          size: req.file.size,
          contentType: req.file.mimetype,
          uploadedAt: new Date()
        }
      });
    } catch (error) {
      next(error);
    }
  },

  getProfile: async(req, res, next) => {
    try {
      const { merchantId } = req.params;

      // Log profile access
      securityLogger.securityEvent('profile_access', {
        merchantId,
        requestedBy: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Find merchant by _id
      const merchant = await Merchant.findById(merchantId);

      if (!merchant || !merchant.profile) {
        throw new NotFoundError('No profile picture found');
      }

      // Set security headers for image serving
      res.set({
        'Content-Type': merchant.profile.contentType,
        'Cache-Control': 'private, max-age=3600', // Cache for 1 hour
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': 'default-src \'self\''
      });

      res.send(merchant.profile.data); // Send the image buffer as a response
    } catch (error) {
      next(error);
    }
  }

};
