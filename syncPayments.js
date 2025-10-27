// syncPayments.js
require('dotenv').config();
const mongoose = require('mongoose');
const Loan = require('./models/loan');
const Payment = require('./models/payment');

(async () => {
  try {
    console.log("🔍 Starting payment synchronization...");

    // ✅ Ensure MONGODB_URI is loaded
    if (!process.env.MONGO_URI) {
      throw new Error("MONGODB_URI is missing in .env file");
    }

    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ Connected to MongoDB for synchronization...");

    // === Your syncing logic here ===
    const unsynced = await Payment.find({ timestamp: null });
    console.log(`📦 Found ${unsynced.length} unsynced payments...`);

    for (const pay of unsynced) {
      pay.timestamp = new Date();
      await pay.save();
      console.log(`✅ Synced payment for loan ID: ${pay.loanId}`);
    }

    console.log(`🎯 Successfully synchronized ${unsynced.length} payments.`);
  } catch (err) {
    console.error("❌ Error during synchronization:", err);
  } finally {
    await mongoose.connection.close();
    console.log("🔒 MongoDB connection closed.");
  }
})();
