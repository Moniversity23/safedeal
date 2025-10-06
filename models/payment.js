const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  loanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Loan', required: true },
  date: { type: Date, required: true },
  expected: { type: Number, required: true },
  paid: { type: Number, default: 0 }, // Allow partial (0 for skipped, < expected for partial)
  skipped: { type: Boolean, default: false },
  
  // --- CRITICAL FIXES BELOW ---
  // The field used to record WHICH officer made the collection
  officerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
  
  // The field used to record WHEN the collection was made, for dashboard tracking
  timestamp: { type: Date, default: null } 
  
});

module.exports = mongoose.model('Payment', paymentSchema);
