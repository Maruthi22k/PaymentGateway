const express = require('express');
const router = express.Router();
const { getFailureUrl } = require('../Controllers/fUrl'); // Import the controller

// Payment status update route
router.post('/failure', getFailureUrl);

module.exports = router;
