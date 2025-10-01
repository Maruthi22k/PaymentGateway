const { generateTransactionId } = require('../Util/helpers');
const Transaction = require('../Models/Transaction');
const SaltKey = require('../Models/Saltkey');
const { securityLogger } = require('../Util/logger');
const { AuthenticationError } = require('../middleware/errorHandler');

// Controller to handle payment data submission
const submitPaymentData = async(req, res, next) => {
  try {
    const data = req.body;

    // Log payment submission attempt
    securityLogger.securityEvent('payment_submission', {
      merchantId: data.merchantId,
      amount: data.amount,
      email: data.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Verify salt key authentication
    const saltkey = await SaltKey.findOne({
      merchantId: data.merchantId,
      saltKey: data.salt,
      isActive: true
    });

    if (!saltkey) {
      securityLogger.authFailure({
        merchantId: data.merchantId,
        reason: 'invalid_salt_key',
        ip: req.ip
      });
      throw new AuthenticationError('Authentication credentials are incorrect');
    }

    // Generate a unique transaction ID
    const txnid = generateTransactionId();

    // Get the current date and time in UTC, then adjust it to IST (UTC +5:30)
    const currentUtcDate = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000; // 5 hours 30 minutes in milliseconds
    const istDate = new Date(currentUtcDate.getTime() + istOffset);

    // Save the transaction to the database
    const transaction = new Transaction({
      txnid,
      merchantId: data.merchantId,
      productinfo: data.productinfo,
      amount: data.amount,
      email: data.email,
      firstname: data.firstname,
      lastname: data.lastname,
      phone: data.phone,
      salt: data.salt,
      status: 'process',
      transactionTime: istDate,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Save the transaction in the database
    await transaction.save();

    // Log successful payment submission
    securityLogger.securityEvent('payment_submitted', {
      transactionId: txnid,
      merchantId: data.merchantId,
      amount: data.amount,
      ip: req.ip
    });

    // Redirect with the transaction ID in the URL
    const redirectUrl = `${process.env.REDIRECT_URL}?txnid=${txnid}`;

    return res.status(200).json({
      status: 'success',
      message: 'Payment data processed successfully',
      transactionId: txnid,
      redirectUrl
    });
  } catch (error) {
    next(error);
  }
};

module.exports = { submitPaymentData };
