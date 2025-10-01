const crypto = require('crypto');
const { generateTransactionId } = require('../Util/helpers');
const Transaction = require('../Models/Transaction');
const SaltKey = require('../Models/Saltkey'); // Assuming SaltKey is the model for your saltkeys collection

// Helper function to decrypt data
const decryptData = (encryptedData, key, iv) => {
  try {
    const decipher = crypto.createDecipheriv('aes-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    console.log('Decrypted data successfully:', decrypted);
    return decrypted;
  } catch (error) {
    console.error('Error decrypting data:', error);
    throw error;
  }
};

// Controller to handle payment data submission
const submitPaymentDatatest = async(req, res) => {
  console.log('Request received at submitPaymentDatatest with body:', req.body);
  const data = req.body;

  // Define required fields for the payment submission
  const requiredFields = ['merchantId', 'encryptedData', 'hashedSaltKey', 'iv'];

  // Check for missing fields
  const missingFields = requiredFields.filter((field) => !data[field]);
  if (missingFields.length > 0) {
    console.error(`Missing fields: ${missingFields.join(', ')}`);
    return res.status(400).json({
      status: 'error',
      message: `Missing fields: ${missingFields.join(', ')}`
    });
  }

  try {
    console.log('Fetching salt key for merchantId:', data.merchantId);

    // Fetch the salt key from the database for the given merchantId
    const saltkey = await SaltKey.findOne({
      merchantId: data.merchantId,
      isActive: true
    });

    if (!saltkey) {
      console.error('Salt key not found or inactive for merchantId:', data.merchantId);
      return res.status(401).json({
        status: 'error',
        message: 'Authentication credentials are incorrect'
      });
    }

    console.log('Salt key found:', saltkey.saltKey);

    // Hash the salt key from the database to compare with the provided hashedSaltKey
    const hash = crypto.createHash('sha256').update(saltkey.saltKey).digest('hex');
    console.log('Computed hash:', hash, '| Provided hash:', data.hashedSaltKey);

    if (hash !== data.hashedSaltKey) {
      console.error('Invalid salt key hash for merchantId:', data.merchantId);
      return res.status(401).json({
        status: 'error',
        message: 'Invalid salt key'
      });
    }

    // Decrypt the encrypted data
    console.log('Decrypting data...');
    const decryptedData = decryptData(data.encryptedData, saltkey.saltKey, data.iv);

    // Parse the decrypted data (assuming it's JSON)
    console.log('Parsing decrypted data...');
    const paymentDetails = JSON.parse(decryptedData);
    console.log('Decrypted payment details:', paymentDetails);

    // Generate a unique transaction ID
    const txnid = generateTransactionId();
    console.log('Generated transaction ID:', txnid);

    // Get the current date and time in UTC, then adjust it to IST (UTC +5:30)
    const currentUtcDate = new Date();
    const istOffset = 5.5 * 60 * 60 * 1000; // 5 hours 30 minutes in milliseconds
    const istDate = new Date(currentUtcDate.getTime() + istOffset);
    console.log('IST transaction time:', istDate);

    // Prepare the transaction data
    const paymentData = {
      txnid,
      merchantId: data.merchantId,
      ...paymentDetails, // Spread the decrypted payment details
      transactionTime: istDate // Store the IST time
    };

    console.log('Saving transaction data to database:', paymentData);

    // Save the transaction to the database
    const transaction = new Transaction({
      ...paymentData,
      status: 'process'
    });

    await transaction.save();
    console.log('Transaction saved successfully.');

    // Redirect with the transaction ID in the URL
    const redirectUrl = `${process.env.REDIRECT_URL}?txnid=${txnid}`;
    console.log('Redirect URL:', redirectUrl);

    return res.status(200).json({
      status: 'success',
      message: 'Payment data processed successfully',
      transactionId: txnid,
      redirectUrl
    });
  } catch (error) {
    console.error('Error during transaction processing:', error);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
};

module.exports = { submitPaymentDatatest };
