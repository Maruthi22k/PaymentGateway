// models/whitelistModel.js
const mongoose = require('mongoose');

const WhitelistSchema = new mongoose.Schema({
  merchantId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  type: {
    type: String,
    enum: ['Website', 'App'],
    required: true
  },
  link: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['Pending', 'Approved','Rejected'],
    default: 'Pending'
  }
});

module.exports = mongoose.model('Whitelist', WhitelistSchema);
