// fixMissingColors.js
require('dotenv').config();
const mongoose = require('mongoose');
const Payment = require('./models/payment');

(async () => {
  try {
    console.log('🔍 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI);

    console.log('✅ Connected.');

    // 🟢 Fix payments marked as paid but missing color/status
    const paidFix = await Payment.updateMany(
      {
        paid: { $gt: 0 },
        $or: [{ color: { $exists: false } }, { status: { $exists: false } }]
      },
      { $set: { color: 'paid', status: 'paid' } }
    );

    console.log(`✅ Updated ${paidFix.modifiedCount} paid records with missing color/status.`);

    // 🔴 Optional: fix skipped ones too (uncomment if you want)
    /*
    const skippedFix = await Payment.updateMany(
      {
        skipped: true,
        $or: [{ color: { $exists: false } }, { status: { $exists: false } }]
      },
      { $set: { color: 'skipped', status: 'skipped' } }
    );
    console.log(`✅ Updated ${skippedFix.modifiedCount} skipped records.`);
    */

    console.log('🎨 All missing colors/status fixed.');
  } catch (err) {
    console.error('❌ Error:', err);
  } finally {
    await mongoose.connection.close();
    console.log('🔒 Connection closed.');
  }
})();
