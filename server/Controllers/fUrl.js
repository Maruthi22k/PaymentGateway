const mongoose = require('mongoose');
const Transaction = require('../Models/Transaction'); // Import your Transaction model

// Fetch and return furl controller
const getFailureUrl = async(req, res) => {
  try {
    const { ID2 } = req.body;

    // Validate input
    if (!ID2) {
      return res.status(400).json({ success: false, message: 'ID2 is required' });
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

    // Return only the furl
    return res.status(200).json({
      success: true,
      furl: transaction.furl
    });

  } catch (error) {
    console.error('Error occurred:', error);

    return res.status(500).json({
      success: false,
      message: 'Failed to fetch failure URL',
      error: error.message // More informative error response
    });
  }
};

module.exports = { getFailureUrl };
