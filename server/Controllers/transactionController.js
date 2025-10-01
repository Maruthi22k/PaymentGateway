// controllers/transactionController.js
const Transaction = require('../Models/Transaction');
const { securityLogger } = require('../Util/logger');
const { NotFoundError } = require('../middleware/errorHandler');

exports.getTransactions = async(req, res, next) => {
  try {
    const { merchantId } = req.params;

    // Log transaction access
    securityLogger.securityEvent('transaction_access', {
      merchantId,
      userId: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const transactions = await Transaction.find({ merchantId })
      .select('-salt -ipAddress -userAgent') // Exclude sensitive fields
      .sort({ transactionTime: -1 })
      .exec();

    if (!transactions.length) {
      throw new NotFoundError('No transactions found for this merchant.');
    }

    return res.status(200).json(transactions);
  } catch (error) {
    next(error);
  }
};
