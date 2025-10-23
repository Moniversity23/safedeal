const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  loanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Loan', required: true },
  date: { type: Date, required: true },
  expected: { type: Number, required: true },
  paid: { type: Number, default: 0 }, // Allow partial (0 for skipped, < expected for partial)
  skipped: { type: Boolean, default: false },

  // --- CRITICAL FIELDS ---
  officerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: null }
});

// ✅ SPEED BOOST: create indexes
paymentSchema.index({ date: 1 });        // Fast filtering by date
paymentSchema.index({ loanId: 1 });      // Fast lookup per loan
paymentSchema.index({ officerId: 1 });   // Fast filtering by officer
paymentSchema.index({ date: 1, officerId: 1 }); // Optional compound index for daily + officer queries

module.exports = mongoose.model('Payment', paymentSchema);
