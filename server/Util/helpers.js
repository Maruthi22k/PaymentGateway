// utils/helpers.js
const generateTransactionId = () => {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString(); // Generate 10-digit unique txnid
};

module.exports = { generateTransactionId };
