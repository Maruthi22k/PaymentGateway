// controllers/transactionController.js
const Transaction = require('../Models/Transaction');

// Fetch successful transactions for a specific merchantId in descending order
exports.getsettlementTransactions = async(req, res) => {
  try {
    const { merchantId } = req.params;  // Extract merchantId from URL params
    const transactions = await Transaction.find({ merchantId, status: 'success' }).sort({ createdAt: -1 });

    if (!transactions.length) {
      return res.status(404).json({ message: 'No successful transactions found for this merchant.' });
    }

    return res.status(200).json(transactions);
  } catch (error) {
    console.error('Error fetching transactions:', error);
    return res.status(500).json({ message: 'Server error. Please try again later.' });
  }
};
