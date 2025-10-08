const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const userSchema = new Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true }, // NEW FIELD
    role: { type: String, enum: ['Admin', 'LoanOfficer', 'Borrower'], required: true },
    accountNumber: { type: String }, // NEW: For officers' transfer accounts
    accountName: { type: String }, // NEW: Account holder name
    bankName: { type: String }, // NEW: Bank name
    loanOfficerId: { type: Schema.Types.ObjectId, ref: 'User', default: null } 
});

// Hash the password before saving
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

// Method to compare passwords
userSchema.methods.comparePassword = function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);