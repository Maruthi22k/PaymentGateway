const express = require('express');
const router = express.Router();
const { updatePaymentStatus } = require('../Controllers/updatePayment'); // Import the controller

// Payment status update route
router.post('/payment-status', updatePaymentStatus);

module.exports = router;
