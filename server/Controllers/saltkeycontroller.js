const Merchant = require('../Models/SaltKey');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { securityLogger } = require('../Util/logger');
// Generate API Key and Save to DB
exports.generateApiKey = async(req, res, next) => {
  try {
    const { merchantId } = req.body;

    // Log API key generation attempt
    securityLogger.securityEvent('api_key_generation', {
      merchantId,
      requestedBy: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Generate a secure random 64-character hex string for AES-256 encryption
    const saltKey = crypto.randomBytes(32).toString('hex');

    // Create or update merchant in the database
    const merchant = await Merchant.findOneAndUpdate(
      { merchantId },
      {
        merchantId,
        saltKey,
        isActive: true,
        createdAt: new Date(),
        createdBy: req.user?.id
      },
      { upsert: true, new: true }
    );

    // Log successful API key generation
    securityLogger.securityEvent('api_key_generated', {
      merchantId,
      requestedBy: req.user?.id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      data: {
        appId: merchant.merchantId,
        secretKey: merchant.saltKey,
        generatedAt: merchant.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

// Fetch API Keys for a User
exports.getApiKeys = async(req, res) => {
  try {
    const { userId } = req.params;

    // Validate input
    if (!userId) {
      return res.status(400).json({ success: false, message: 'userId is required' });
    }

    // Fetch active merchants associated with the user
    const merchants = await Merchant.find({ merchantId: userId }).sort({ createdAt: -1 });

    if (!merchants.length) {
      return res.status(404).json({ success: false, message: 'No API keys found for this user' });
    }

    // Prepare API key data
    const apiKeys = merchants.map(merchant => {
      const payload = {
        appId: merchant.merchantId,
        secretKey: merchant.saltKey,
        generatedAt: merchant.createdAt,
        isActive: merchant.isActive
      };

      // Sign the payload with the appId as the secret key, with 4-minute expiry
      const token = jwt.sign(payload, merchant.merchantId, { expiresIn: '4m' });

      return {
        token
      };
    });

    res.status(200).json({ success: true, data: apiKeys });
  } catch (error) {
    console.error('Error fetching API keys:', error.message);
    res.status(500).json({ success: false, message: 'Failed to fetch API keys' });
  }
};

// Update the status of an API key (active or inactive)
exports.updateApiKeyStatus = async(req, res) => {
  try {
    const { merchantId, isActive } = req.body;

    // Validate input
    if (!merchantId || typeof isActive !== 'boolean') {
      return res.status(400).json({ success: false, message: 'Invalid request data' });
    }

    // Find the merchant by merchantId and update the status
    const updatedMerchant = await Merchant.findOneAndUpdate(
      { merchantId },
      { isActive },
      { new: true } // Return the updated document
    );

    if (!updatedMerchant) {
      return res.status(404).json({ success: false, message: 'API key not found' });
    }

    // Return the updated merchant details
    res.status(200).json({
      success: true,
      data: {
        appId: updatedMerchant.merchantId,
        secretKey: updatedMerchant.saltKey,
        generatedAt: updatedMerchant.createdAt,
        isActive: updatedMerchant.isActive
      }
    });
  } catch (error) {
    console.error('Error updating API key status:', error.message);
    res.status(500).json({ success: false, message: 'Failed to update API key status' });
  }
};
