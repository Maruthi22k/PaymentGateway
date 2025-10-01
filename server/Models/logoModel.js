const mongoose = require('mongoose');

const logoSchema = new mongoose.Schema({
  logo: { type: Buffer, required: true }, // Store image as binary data
  contentType: { type: String, required: true }, // Store the image type (e.g., "image/png")
  uploadedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Logo', logoSchema);
