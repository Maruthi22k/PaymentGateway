const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: { type: String, required: true },
  isCollectingPayments: { type: Boolean, default: false },
  websiteUrl: { type: String, default: '' },
  profile: {
    data: { type: Buffer }, // Buffer type for image data
    contentType: { type: String } // String type for MIME type (image/jpeg, etc.)
  },
  mode: { type: String, required: false, default: 'TEST' },
  kyc: { type: Number, required: false, default: 0 } // URL to the profile picture
}, { timestamps: true });

module.exports = mongoose.model('Merchant',UserSchema);
