const mongoose = require('mongoose');
const dns = require('dns');

// Ensure reliable DNS resolution for MongoDB Atlas SRV records in Node.js
try {
  dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
} catch (e) {
  // Ignore if dns.setServers is restricted in certain sandbox environments
}

const connectDB = async () => {
  try {
    const connStr = process.env.MONGODB_URI;
    const conn = await mongoose.connect(connStr);
    console.log(`[MongoDB] Connected successfully: ${conn.connection.host} / ${conn.connection.name}`);
  } catch (error) {
    console.error(`[MongoDB Error] ${error.message}`);
    // Do not exit process immediately so server can run in demo/fallback mode if needed
  }
};

module.exports = connectDB;
