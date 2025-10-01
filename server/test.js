const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// Encryption and decryption methods
const ALGORITHM = 'aes-256-cbc';
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key';
const IV_LENGTH = 16;

// Function to encrypt text
const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

// Route to send encrypted demo data
app.get('/get-encrypted-data', (req, res) => {
  // Demo data
  const demoData = {
    name: 'Lokesh',
    number: '9848948',
    address: 'AP Model School Opposite'
  };

  // Convert demo data to a string and encrypt it
  const demoDataString = JSON.stringify(demoData);
  const encryptedData = encrypt(demoDataString);

  res.json({ encryptedData });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
