const mongoose = require('mongoose');

const merchantSchema = new mongoose.Schema({
  merchantId: {
    type: String,
    required: true,
    unique: true
  },
  saltKey: {
    type: String,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
module.exports = mongoose.model('saltkeys', merchantSchema);
