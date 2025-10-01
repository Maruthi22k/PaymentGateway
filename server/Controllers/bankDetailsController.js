const BankDetails = require('../Models/BankDetails');
const { securityLogger } = require('../Util/logger');
const { NotFoundError } = require('../middleware/errorHandler');

exports.getBankDetails = async(req, res, next) => {
  try {
    const { userId } = req.params;

    // Log bank details access
    securityLogger.securityEvent('bank_details_access', {
      userId,
      requestedBy: req.user?.id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const bankDetails = await BankDetails.findOne({ userId: userId })
      .select('-__v'); // Exclude version field

    if (!bankDetails) {
      throw new NotFoundError('No bank account details found');
    }

    // Log bank details access (account number masked for security)

    securityLogger.securityEvent('bank_details_retrieved', {
      userId,
      requestedBy: req.user?.id,
      hasAccountNumber: !!bankDetails.accountNumber,
      ip: req.ip
    });

    return res.status(200).json(bankDetails);
  } catch (error) {
    next(error);
  }
};

exports.createOrUpdateBankDetails = async(req, res, next) => {
  try {
    const { userId } = req.params;
    const { accountNumber, holderName, bankName, branchName, ifsc } = req.body;

    // Log bank details modification attempt
    securityLogger.securityEvent('bank_details_modification', {
      userId,
      requestedBy: req.user?.id,
      action: 'create_or_update',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Check if bank details exist for the given userId
    const bankDetails = await BankDetails.findOne({ userId });

    if (bankDetails) {
      // If bank details exist, update them
      bankDetails.accountNumber = accountNumber;
      bankDetails.holderName = holderName;
      bankDetails.bankName = bankName;
      bankDetails.branchName = branchName;
      bankDetails.ifscCode = ifsc;
      bankDetails.updatedAt = new Date();

      await bankDetails.save();

      securityLogger.securityEvent('bank_details_updated', {
        userId,
        requestedBy: req.user?.id,
        ip: req.ip
      });

      return res.status(200).json({
        message: 'Bank details updated successfully',
        bankDetails: {
          userId: bankDetails.userId,
          holderName: bankDetails.holderName,
          bankName: bankDetails.bankName,
          branchName: bankDetails.branchName,
          ifscCode: bankDetails.ifscCode,
          updatedAt: bankDetails.updatedAt
        }
      });
    } else {
      // If bank details do not exist, create new bank details
      const newBankDetails = new BankDetails({
        userId,
        accountNumber,
        holderName,
        bankName,
        branchName,
        ifscCode: ifsc
      });

      const savedBankDetails = await newBankDetails.save();

      securityLogger.securityEvent('bank_details_created', {
        userId,
        requestedBy: req.user?.id,
        ip: req.ip
      });

      return res.status(201).json({
        message: 'Bank details added successfully',
        bankDetails: {
          userId: savedBankDetails.userId,
          holderName: savedBankDetails.holderName,
          bankName: savedBankDetails.bankName,
          branchName: savedBankDetails.branchName,
          ifscCode: savedBankDetails.ifscCode,
          createdAt: savedBankDetails.createdAt
        }
      });
    }
  } catch (error) {
    next(error);
  }
};
