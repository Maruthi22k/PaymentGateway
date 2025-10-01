require('dotenv').config({ path: '../.env' }); // Adjust the path based on the location of your .env file // Load environment variables
const CryptoJS = require('crypto-js');
const Merchant = require('../Models/Saltkey');
const Transaction = require('../Models/Transaction');
const User = require('../Models/Merchants');
const moment = require('moment-timezone');

const decryptData = async(req, res) => {
  try {
    const { token1, token2, token3, token4 } = req.body;
    const merchantId = token1;
    const _id = merchantId;

    const merchant = await Merchant.findOne({ merchantId });
    if (!merchant) {
      return res.status(400).json({ success: false, message: 'Merchant ID invalid' });
    }

    const merchantDetails = await User.findOne({ _id });
    if (!merchantDetails) {
      return res.status(404).json({ success: false, message: 'Merchant details not found' });
    }

    const merchantMode = merchantDetails.mode;
    const hashedFetchedSaltKey = CryptoJS.SHA256(merchant.saltKey).toString(CryptoJS.enc.Hex);

    if (hashedFetchedSaltKey !== token3) {
      return res.status(401).json({ success: false, message: 'Authentication Failed' });
    }

    if (!merchant.isActive) {
      return res.status(403).json({ success: false, message: 'Merchant account is inactive' });
    }

    const ivParsed = CryptoJS.enc.Hex.parse(token4);
    const key = CryptoJS.enc.Utf8.parse(merchant.saltKey);

    const decryptedBytes = CryptoJS.AES.decrypt(token2, key, {
      iv: ivParsed,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);
    const parsedData = JSON.parse(decryptedData);

    if (parsedData.mode !== merchantMode) {
      return res.status(400).json({
        success: false,
        errorNumber: 'ERR-001',
        message: `You are in ${parsedData.mode} mode. Please select ${merchantMode} mode and try again.`
      });
    }

    const requiredFields = [
      'txnid',
      'merchantId',
      'productinfo',
      'amount',
      'email',
      'firstname',
      'lastname',
      'phone',
      'mode',
      'surl',
      'furl',
      'transactionTime'
    ];

    const missingFields = requiredFields.filter(field => !Object.prototype.hasOwnProperty.call(parsedData, field) || parsedData[field] === '');
    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `The following data is missing or empty: ${missingFields.join(', ')}`
      });
    }

    const maintxnid = moment().format('YYYYMMDDHHmmssSSS');
    const txnid = parsedData.txnid;

    const otransactionTime = moment.tz('Asia/Kolkata').toDate();

    const existingTransaction = await Transaction.findOne({
      $or: [{ maintxnid: maintxnid }, { txnid: txnid }]
    });

    if (existingTransaction) {
      return res.status(400).json({
        success: false,
        message: 'Transaction ID already exists. Please try a different one.'
      });
    }

    const transactionData = {
      maintxnid,
      txnid,
      merchantId: parsedData.merchantId,
      productinfo: parsedData.productinfo,
      amount: parsedData.amount,
      email: parsedData.email,
      firstname: parsedData.firstname,
      lastname: parsedData.lastname,
      phone: parsedData.phone,
      mode: parsedData.mode,
      surl: parsedData.surl,
      furl: parsedData.furl,
      status: 'proceed',
      transactionTime: parsedData.transactionTime,
      otransactionTime
    };

    const newTransaction = new Transaction(transactionData);
    const savedTransaction = await newTransaction.save();

    const TURL = process.env.TURL;
    const LURL = process.env.LURL;

    const redirectUrl = parsedData.mode === 'TEST'
      ? `${TURL}/${txnid}/${savedTransaction._id}`
      : `${LURL}/${txnid}/${savedTransaction._id}`;

    return res.status(200).json({
      success: true,
      redirectUrl
    });
  } catch (err) {
    console.error('Decryption error:', err);
    res.status(500).json({ error: 'Failed to decrypt data' });
  }
};

module.exports = { decryptData };
