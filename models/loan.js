const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const loanSchema = new Schema({
    borrower: { type: String, required: false }, // FIX: Make optional
    officer: { type: String, required: false },   // FIX: Make optional
    
    // The core relationships remain required:
    borrowerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    loanOfficerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    

    principal: { type: Number, required: true },
    disbursementDate: { type: Date, required: true },
    schedule: { type: Array, default: [] } 
});

module.exports = mongoose.model('Loan', loanSchema);
