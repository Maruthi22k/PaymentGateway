const Whitelist = require('../Models/whitelistModel');
const { securityLogger } = require('../Util/logger');
const { NotFoundError } = require('../middleware/errorHandler');

exports.getWhitelists = async(req, res, next) => {
  try {
    const { userId } = req.params;

    // Log whitelist access
    securityLogger.securityEvent('whitelist_access', {
      userId,
      requestedBy: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const whitelists = await Whitelist.find({ merchantId: userId })
      .select('-__v')
      .sort({ createdAt: -1 });

    if (whitelists.length === 0) {
      throw new NotFoundError('No domains are whitelisted');
    }

    return res.status(200).json(whitelists);
  } catch (error) {
    next(error);
  }
};

exports.createWhitelist = async(req, res, next) => {
  try {
    const { userId } = req.params;
    const { type, link } = req.body;

    // Log whitelist creation attempt
    securityLogger.securityEvent('whitelist_creation', {
      userId,
      type,
      link,
      requestedBy: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const newWhitelist = new Whitelist({
      merchantId: userId,
      type,
      link,
      status: 'Pending', // Default status
      createdBy: req.user?.id
    });

    const savedWhitelist = await newWhitelist.save();

    // Log successful whitelist creation
    securityLogger.securityEvent('whitelist_created', {
      whitelistId: savedWhitelist._id,
      userId,
      type,
      requestedBy: req.user?.id,
      ip: req.ip
    });

    return res.status(201).json({
      message: 'Whitelist request submitted successfully',
      whitelist: {
        _id: savedWhitelist._id,
        merchantId: savedWhitelist.merchantId,
        type: savedWhitelist.type,
        link: savedWhitelist.link,
        status: savedWhitelist.status,
        createdAt: savedWhitelist.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};
