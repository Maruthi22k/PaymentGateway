// routes/transactionRoutes.js
const express = require('express');
const router = express.Router();
const settlementController = require('../Controllers/settlementController');

// Route to fetch transactions by merchantId
router.get('/settlements/:merchantId', settlementController.getsettlementTransactions);

module.exports = router;
