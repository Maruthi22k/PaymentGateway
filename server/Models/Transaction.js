const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  maintxnid: {
    type: String,
    required: true,
    unique: true
  },
  txnid: {
    type: String,
    required: true,
    unique: true
  },
  merchantId: {
    type: String,
    required: true
  },
  productinfo: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  firstname: {
    type: String,
    required: true
  },
  lastname: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true
  },
  status: {
    type: String,
    default: 'proceed'
  },
  transactionTime: {
    type: Date,
    default: Date.now // Set default to current time
  },
  otransactionTime: {
    type: Date
  },
  mode: {
    type: String,
    enum: ['TEST', 'LIVE'],
    required: true
  },
  settlestatus: {
    type: String,
    enum: ['pending', 'settled'],
    default: 'pending',
    required: true
  },
  surl: { type: String, required: true },
  furl: { type: String, required: true }
}, { timestamps: true }); // Add timestamps

transactionSchema.index({ txnid: 1, merchantId: 1 }, { unique: true });

module.exports = mongoose.model('Transaction', transactionSchema);
