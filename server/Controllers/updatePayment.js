const mongoose = require('mongoose');
const Transaction = require('../Models/Transaction'); // Import your Transaction model

// Payment status update controller
const updatePaymentStatus = async(req, res) => {
  try {
    const { ID2, status } = req.body;

    // Validate input
    if (!ID2 || !status) {
      return res.status(400).json({ success: false, message: 'ID2 and status are required' });
    }

    // Validate if ID2 is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(ID2)) {
      return res.status(400).json({ success: false, message: 'Invalid transaction ID' });
    }

    // Find the transaction by ID2 (_id)
    const transaction = await Transaction.findById(ID2);

    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }

    // Log transaction for debugging
    console.log('Transaction found:', transaction);

    // Update the status
    transaction.status = status;
    await transaction.save(); // Save changes

    // Log the updated transaction
    console.log('Updated transaction:', transaction);

    // Determine redirect URL based on status
    const redirectUrl = status === 'failure' ? transaction.furl : transaction.surl;

    return res.status(200).json({
      success: true,
      message: `Payment status updated to ${status}`,
      url: redirectUrl,
      transactionData: transaction
    });

  } catch (error) {
    console.error('Error occurred:', error);

    return res.status(500).json({
      success: false,
      message: 'Failed to update payment status',
      error: error.message // More informative error response
    });
  }
};

module.exports = { updatePaymentStatus };
