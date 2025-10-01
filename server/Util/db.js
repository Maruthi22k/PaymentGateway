const mongoose = require('mongoose');
const { logger } = require('./logger');

const connectDB = async() => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://95.203.135.38:1200/merchants';

    const connection = await mongoose.connect(mongoURI, {
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      bufferCommands: false // Disable mongoose buffering
    });

    logger.info('MongoDB connected successfully', {
      host: connection.connection.host,
      database: connection.connection.name
    });

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error', { error: err.message });
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async() => {
      try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        logger.error('Error closing MongoDB connection', { error: error.message });
        process.exit(1);
      }
    });

  } catch (error) {
    logger.error('MongoDB connection failed', { error: error.message });
    logger.warn('Server will continue without database connection. Please start MongoDB to enable full functionality.');
    // Don't exit the process, let the server continue
  }
};

module.exports = connectDB;
