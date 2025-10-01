const mongoose = require('mongoose');

// BankDetails Schema
const bankDetailsSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  accountNumber: {
    type: String,
    required: true
  },
  holderName: {
    type: String,
    required: true
  },
  bankName: {
    type: String,
    required: true
  },
  branchName: {
    type: String,
    required: true
  },
  ifscCode: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Create the model for BankDetails
const BankDetails = mongoose.model('BankDetails', bankDetailsSchema);

module.exports = BankDetails;
