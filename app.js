// 1. FIX: Load environment variables first.
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const moment = require('moment');
// const dotenv = require('dotenv').config(); // Redundant now that it's at the top

const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const User = require('./models/user');
const Loan = require('./models/loan');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const Payment = require('./models/payment');

const app = express();
const port = process.env.PORT || 3000;

// MongoDB connection
// 2. FIX: Read MONGO_URI to match your .env file.
const mongoURI = process.env.MONGO_URI || process.env.MONGODB_URI;


if (mongoURI) {
  mongoose.connect(mongoURI)
    .then(() => console.log('✅ Connected to MongoDB Atlas (SAFEDEAL)!'))
    .catch(err => console.error('❌ MongoDB connection failed:', err));
} else {
  console.warn('⚠️ Warning: MONGO_URI not found. Skipping MongoDB connection.');
}

// Session setup
let sessionStore;

if (mongoURI) {
  // Use MongoDB-backed session store if DB is available
  sessionStore = MongoStore.create({ mongoUrl: mongoURI });
} else {
  // Fallback to in-memory session store
  const sessionMemoryStore = new session.MemoryStore();
  sessionStore = sessionMemoryStore;
  console.warn('⚠️ Using in-memory session store (sessions will reset on restart).');
}
// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET, // moved to .env
  resave: false,
  saveUninitialized: false,
  // This now correctly receives the URI via the defined mongoURI variable
  store: MongoStore.create({ mongoUrl: mongoURI }), 
   cookie: {
    httpOnly: true,
    secure: false, // set true only if using https
    sameSite: 'lax', // important for mobile
    maxAge: 1000 * 60 * 60 * 24 * 7 // session lasts 7 days
  }
}));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public", { maxAge: "1d" }));
app.use(morgan('dev'));
app.use(helmet());
app.use(morgan("combined"));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(compression());

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', { message: 'Something went wrong!' });
});

// --- MIDDLEWARE FOR AUTHENTICATION AND ROLE CHECKING ---

const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
};

const isAdmin = (req, res, next) => {
    if (req.session.userId && req.session.role === 'Admin') {
        return next();
    }
    return res.redirect('/login');
};

const isLoanOfficer = (req, res, next) => {
    if (req.session.userId && req.session.role === 'LoanOfficer') {
        return next();
    }
    // Loan Officer dashboard link should point to /officer-dashboard, NOT /
    return res.redirect('/login');
};

const isBorrower = (req, res, next) => {
    if (req.session.userId && req.session.role === 'Borrower') {
        return next();
    }
    return res.redirect('/login');
};

// --- HELPER FUNCTIONS ---

// All financial outputs are rounded up to the nearest whole number (Math.ceil)
function calculateDailyPayment(principal) {
    // Total repayable is Principal * 1.2
    return Math.ceil((principal * 1.2) / 40); 
}

function calculateDailyInterestPortion(principal) {
    return Math.ceil((principal * 0.2) / 40);
}

function calculateOfficerDailyShare(principal, officerRate = 0.25) {  // Updated: Param for rate (0.25 default for first officer, pass 0.17 for second)
    return Math.ceil(calculateDailyInterestPortion(principal) * officerRate);
}

// FIX: Ensure officerId is included in the payment records for collection tracking
async function createPaymentSchedule(loan) {
    const start = moment(loan.disbursementDate).add(1, 'days');
    const payments = [];
    const dailyAmount = calculateDailyPayment(loan.principal);
    
    for (let i = 0; i < 40; i++) {
        const date = start.clone().add(i, 'days').format('YYYY-MM-DD');
        payments.push({
            loanId: loan._id,
            date,
            expected: dailyAmount,
            paid: 0, 
            skipped: false,
            timestamp: null, 
            officerId: loan.loanOfficerId // CRITICAL: Embed the LO's ID
        });
    }
    await Payment.insertMany(payments);
}

// --- AUTHENTICATION ROUTES (LOGIN/LOGOUT/SETUP) ---

app.get('/setup-admin', async (req, res) => {
    try {
        const adminCount = await User.countDocuments({ role: 'Admin' });
        if (adminCount === 0) {
            const adminUser = new User({
                username: 'admin',
                password: 'password', 
                fullName: 'System Admin', 
                role: 'Admin'
            });
            await adminUser.save();
            return res.send('Initial Admin user created (username: admin, password: password, Full Name: System Admin). PLEASE CHANGE IT!');
        }
        res.send('Admin user already exists.');
    } catch (error) {
        res.status(500).send('Error setting up admin: ' + error.message);
    }
});

// ---------------- LOGIN ROUTE ----------------
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // ✅ Check for empty fields
    if (!username || !password) {
      return res.render('login', { error: 'Please enter both username and password.' });
    }

    // ✅ Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.render('login', { error: 'No account found with that username.' });
    }

    // ✅ Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.render('login', { error: 'Incorrect password. Please try again.' });
    }

    // ✅ Store session data
    req.session.userId = user._id;
    req.session.role = user.role;
    req.session.username = user.username;
    req.session.fullName = user.fullName;

    // ✅ Role-based redirects
    if (user.role === 'Admin') {
      return res.redirect('/');
    } else if (user.role === 'LoanOfficer') {
      return res.redirect('/officer-dashboard');
    } else if (user.role === 'Borrower') {
      return res.redirect('/borrower-dashboard');
    } else {
      // ✅ Catch unknown roles safely
      return res.render('login', { error: 'Unknown user role. Please contact support.' });
    }

  } catch (err) {
    console.error('Login Error:', err);
    res.render('login', { error: 'Something went wrong. Please try again later.' });
  }
});


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.redirect('/');
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// --- ROLE-BASED DASHBOARD ROUTES ---

// Admin Dashboard 
app.get('/', isAuthenticated, isAdmin, async (req, res) => {
    // Role check already handled by isAdmin middleware
    const today = moment().format('YYYY-MM-DD');

    // ✨ FIX: Use UTC to define the start and end of the day for consistent tracking
    const now = new Date();
    const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
    const todayEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 59, 59, 999));

    const loans = await Loan.find().populate('borrowerId loanOfficerId');
    let expectedToday = 0;
    let activeLoans = loans.length;
    let portfolioAtRisk = 0;

    for (const loan of loans) {
        const paymentToday = await Payment.findOne({ loanId: loan._id, date: today });
        if (paymentToday && !paymentToday.skipped) {
            expectedToday += paymentToday.expected;
        }
        const overdueCount = await Payment.countDocuments({
            loanId: loan._id,
            date: { $lt: today },
            paid: { $lt: calculateDailyPayment(loan.principal) },
            skipped: false
        });
        if (overdueCount > 0) portfolioAtRisk++;
    }
    portfolioAtRisk = activeLoans > 0 ? ((portfolioAtRisk / activeLoans) * 100).toFixed(1) : 0;

    // CRITICAL: Calculate collectedToday based on the timestamp field
    const todayCollections = await Payment.find({
        timestamp: { $gte: todayStart, $lte: todayEnd },
        paid: { $gt: 0 }
    }).lean();

    const collectedToday = todayCollections.reduce((sum, p) => sum + p.paid, 0);

    const accumulatedResult = await Payment.aggregate([
        { $group: { _id: null, total: { $sum: '$paid' } } }
    ]);
    const accumulatedTotalCollected = accumulatedResult.length > 0 ? accumulatedResult[0].total : 0;

    console.log(`Admin Dashboard - UTC Start: ${todayStart.toISOString()}, UTC End: ${todayEnd.toISOString()}, Collected: ${collectedToday}`);

    // NEW: Per-officer stats
    // NEW: Per-officer stats
const officers = await User.find({ role: 'LoanOfficer' }); // Removed populate – fetch loans in loop
const officersSummary = [];
for (const officer of officers) {
    const officerLoans = await Loan.find({ loanOfficerId: officer._id });
    const disbursed = officerLoans.reduce((sum, l) => sum + l.principal, 0);
    
    let officerExpectedToday = 0;
    let officerCollectedToday = 0;
    let officerGeneralCollected = 0;
    
    for (const oLoan of officerLoans) {
        const oPaymentToday = await Payment.findOne({ loanId: oLoan._id, date: today });
        if (oPaymentToday && !oPaymentToday.skipped) {
            officerExpectedToday += oPaymentToday.expected;
        }
    }
    
    const officerTodayCollections = await Payment.find({
        officerId: officer._id,
        timestamp: { $gte: todayStart, $lte: todayEnd },
        paid: { $gt: 0 }
    });
    officerCollectedToday = officerTodayCollections.reduce((sum, p) => sum + p.paid, 0);
    
    const officerAllPayments = await Payment.find({ loanId: { $in: officerLoans.map(l => l._id) }, paid: { $gt: 0 } });
    officerGeneralCollected = officerAllPayments.reduce((sum, p) => sum + p.paid, 0);
    
    const rate = officer.username === 'faith' ? 0.25 : 0.17; // Distinction logic (update as needed)
    
    officersSummary.push({
        officer: officer.fullName,
        disbursed: Math.ceil(disbursed),
        expectedToday: Math.ceil(officerExpectedToday),
        collectedToday: Math.ceil(officerCollectedToday),
        generalCollected: Math.ceil(officerGeneralCollected),
        rate
    });
}

    res.render('dashboard', {
        today,
        expectedToday: Math.ceil(expectedToday),
        collectedToday: Math.ceil(collectedToday),
        accumulatedTotalCollected: Math.ceil(accumulatedTotalCollected),
        activeLoans,
        portfolioAtRisk,
        totalDisbursed: loans.reduce((sum, l) => sum + l.principal, 0),
        officersSummary, // NEW: Pass per-officer data
        user: req.session
    });
});

// Borrower Dashboard 
// Borrower Dashboard 
// Borrower Dashboard 
app.get('/borrower-dashboard', isAuthenticated, isBorrower, async (req, res) => {
    const loans = await Loan.find({ borrowerId: req.session.userId }).populate('loanOfficerId', 'fullName accountNumber accountName bankName').sort({ disbursementDate: -1 }); // All loans, newest first
    if (loans.length === 0) return res.render('borrower-dashboard', { loans: [], user: req.session, moment });

    const borrowerLoans = []; // Array of per-loan data

    for (const loan of loans) {
        const totalRepay = Math.ceil(loan.principal * 1.2);
        const dailyPayment = calculateDailyPayment(loan.principal);
        
        // Fetch payments for this loan only
        const allPayments = await Payment.find({ loanId: loan._id }).sort({ date: 1 }).lean();
        
        const totalPaidAmount = allPayments.reduce((sum, p) => sum + (p.paid || 0), 0);
        const remainingBalance = Math.ceil(totalRepay - totalPaidAmount);
        
        // Build 40-day calendar for this loan
        const paymentCalendar = [];
        const startDate = moment(loan.disbursementDate).add(1, 'days'); // Day 1 due date
        let paidSlots = 0;
        
        for (let i = 0; i < 40; i++) {
            const dueDate = startDate.clone().add(i, 'days');
            const dueDateStr = dueDate.format('YYYY-MM-DD');
            
            const paymentRecord = allPayments.find(p => moment(p.date).format('YYYY-MM-DD') === dueDateStr);
            
            const slot = {
                day: i + 1, // 1-40
                dueDate: dueDateStr,
                expected: dailyPayment,
                paid: paymentRecord ? paymentRecord.paid || 0 : 0,
                skipped: paymentRecord ? paymentRecord.skipped : false,
                status: 'pending', // Default gray (future)
                color: 'gray' // CSS class for EJS
            };
            
            const now = moment(); // Current date
            const isPastDue = dueDate.isBefore(now, 'day');
            const isToday = dueDate.isSame(now, 'day');
            const isFuture = dueDate.isAfter(now, 'day');
            
            if (slot.paid > 0) {
                slot.status = 'paid';
                slot.color = 'green';
                paidSlots++;
                console.log(`Loan ${loan._id} Slot ${slot.day} (${dueDateStr}): Paid ${slot.paid} - Green`);
            } else if (slot.skipped || (isPastDue && slot.paid === 0)) {
                slot.status = 'skipped/unpaid';
                slot.color = 'red';
            } else if (isFuture) {
                slot.status = 'pending';
                slot.color = 'gray';
            } else if (isToday) {
                slot.status = 'due today';
                slot.color = 'orange';
            }
            
            paymentCalendar.push(slot);
        }
        
        const progress = `${paidSlots}/40`;
        
        // Calendar helpers for this loan's alignment
        const firstDueMoment = startDate.clone();
        const calendarStartMoment = firstDueMoment.clone().startOf('isoWeek');
        const lastDueMoment = startDate.clone().add(39, 'days');
        
        borrowerLoans.push({
            loan, // Full loan object
            totalRepay,
            dailyPayment,
            remainingBalance,
            progress,
            paidSlots, // NEW: For filter check
            paymentCalendar,
            firstDue: firstDueMoment.format('YYYY-MM-DD'),
            calendarStart: calendarStartMoment.format('YYYY-MM-DD'),
            lastDue: lastDueMoment.format('YYYY-MM-DD')
        });
    }

    // NEW: Filter to show only incomplete loans (paidSlots < 40)
    const activeLoans = borrowerLoans.filter(loanData => loanData.paidSlots < 40);

    res.render('borrower-dashboard', { 
        loans: activeLoans, // Only active/incomplete
        user: req.session,
        moment
    });
});

// Loan Officer Dashboard (FIXED FOR LOAN AMOUNT)
app.get('/officer-dashboard', isAuthenticated, isLoanOfficer, async (req, res) => {
    const today = moment().format('YYYY-MM-DD');

    // ✨ FIX: Use UTC to define the start and end of the day
    const now = new Date();
    const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
    const todayEnd = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 59, 59, 999));

    const loans = await Loan.find({ loanOfficerId: req.session.userId }).populate('borrowerId');
    const totalLoansAmount = loans.reduce((sum, l) => sum + l.principal, 0); // NEW: Disbursed total

    let todayExpected = 0;
    let defaulters = [];
    let allBorrowersPaid = true;

    for (const loan of loans) {
        const paymentToday = await Payment.findOne({ loanId: loan._id, date: today });
        if (paymentToday && !paymentToday.skipped) {
            todayExpected += paymentToday.expected;
            if (paymentToday.paid < paymentToday.expected || paymentToday.paid === 0) {
                defaulters.push({
                    borrower: loan.borrowerId.fullName || loan.borrowerId.username,
                    expected: paymentToday.expected,
                    collected: paymentToday.paid || 0
                });
                allBorrowersPaid = false;
            }
        }
    }

    // Collected TODAY (by LO) based on timestamp
    const todayCollections = await Payment.find({
        officerId: req.session.userId,
        timestamp: { $gte: todayStart, $lte: todayEnd },
        paid: { $gt: 0 }
    });

    const todayCollected = todayCollections.reduce((sum, p) => sum + p.paid, 0);

    // NEW: General collected for this officer (all time)
    const generalCollections = await Payment.find({
        officerId: req.session.userId,
        paid: { $gt: 0 }
    });
    const generalCollected = generalCollections.reduce((sum, p) => sum + p.paid, 0);

    // Rate for this officer
    const officerRate = req.session.username === 'faith' ? 0.25 : 0.17; // Distinction logic

    if (todayExpected === 0) allBorrowersPaid = true;

    res.render('officer-dashboard', {
        today,
        totalLoansAmount: Math.ceil(totalLoansAmount), // NEW: Disbursed
        todayExpected: Math.ceil(todayExpected),
        todayCollected: Math.ceil(todayCollected),
        generalCollected: Math.ceil(generalCollected), // NEW: General
        defaulters,
        allBorrowersPaid,
        officerRate, // NEW: For commission display if needed
        user: req.session,
        moment
    });
});

// --- PAYMENT TRACKING ROUTES ---

// Daily view/edit (officer/admin only)
app.get('/daily/:date', isAuthenticated, async (req, res) => {
    // Allow admin or loan officer
    const userRole = req.session.role; // Extract user role here
    if (userRole !== 'Admin' && userRole !== 'LoanOfficer') {
        return res.status(403).send('Access Denied: Admin or Loan Officer required.');
    }
    
    const date = req.params.date;
    let loans;
    if (userRole === 'LoanOfficer') {
        // Officer sees only assigned loans
        loans = await Loan.find({ loanOfficerId: req.session.userId }).populate('borrowerId');
    } else {
        // Admin sees all
        loans = await Loan.find().populate('borrowerId');
    }
    
    const dailyData = [];
    let totalExpected = 0;
    let totalCollected = 0;
    const defaulters = []; 
    
    for (const loan of loans) {
        let payment = await Payment.findOne({ loanId: loan._id, date });
        const isWithinLoanPeriod = moment(date).isBetween(
            moment(loan.disbursementDate).add(1, 'days'),
            moment(loan.disbursementDate).add(40, 'days'),
            null, '[]'
        );
        if (!payment && isWithinLoanPeriod) {
            payment = new Payment({
                loanId: loan._id,
                date,
                expected: calculateDailyPayment(loan.principal),
                paid: 0, // Default unpaid until marked
                skipped: false,
                officerId: loan.loanOfficerId, // Ensure officerId is set upon creation
            });
            await payment.save();
        } else if (payment && payment.paid === 0 && !payment.skipped) {
            // No change needed here
        }

        if (payment) {
            totalExpected += payment.expected;
            totalCollected += payment.paid || 0; // total collected for THIS due date
            if (payment.paid < payment.expected && !payment.skipped) {
                defaulters.push({
                    borrower: loan.borrowerId.fullName || loan.borrowerId.username,
                    expected: payment.expected,
                    collected: payment.paid || 0
                });
            }
            dailyData.push({ loan, payment });
        }
    }
    
    res.render('daily', { 
        date, 
        dailyData, 
        totalExpected: Math.ceil(totalExpected), 
        totalCollected: Math.ceil(totalCollected), 
        defaulters, 
        user: req.session,
        userRole, 
        moment  
    });
});

// Simplified payment update route: Mark Full Payment
app.post('/daily/mark-paid', isAuthenticated, async (req, res) => {
    if (req.session.role !== 'Admin' && req.session.role !== 'LoanOfficer') {
         return res.status(403).send('Access Denied: Only Admin and Loan Officers can update payments.');
    }
    
    const { paymentId, date, expectedAmount } = req.body;
    
    // Mark as paid the full expected amount
    const update = {
        skipped: false,
        paid: parseFloat(expectedAmount),
        officerId: req.session.userId, // Record the LO who collected the payment
        timestamp: new Date() // CRITICAL FIX: Record the exact time the LO clicked 'Paid'
    };
    
    try {
        const updatedPayment = await Payment.findByIdAndUpdate(
            paymentId, 
            update, 
            { new: true, runValidators: true }
        );
        if (!updatedPayment) {
            console.error('Payment not found for ID:', paymentId);
            return res.status(404).send('Payment not found.');
        }
        console.log('Payment marked paid:', { 
            id: updatedPayment._id, 
            date: updatedPayment.date, 
            paid: updatedPayment.paid, 
            timestamp: updatedPayment.timestamp // Should be visible here
        });
        res.redirect(`/daily/${date}`);
    } catch (error) {
        console.error('Update error:', error);
        res.status(500).send('Failed to update payment: ' + error.message);
    }
});

// --- REMAINING ADMIN/GENERAL ROUTES ---

app.post('/users/add', isAuthenticated, isAdmin, async (req, res) => {
    const { username, password, fullName, role, accountNumber, accountName, bankName } = req.body;
    try {
        const newUser = new User({ 
            username, 
            password, 
            fullName, 
            role, 
            accountNumber: accountNumber || undefined,
            accountName: accountName || undefined, // NEW
            bankName: bankName || undefined // NEW
        });
        await newUser.save();
        res.redirect('/users/manage');
    } catch (error) {
        res.status(400).send('Error creating user: ' + error.message);
    }
});

app.get('/users/manage', isAuthenticated, isAdmin, async (req, res) => {
    const users = await User.find().select('-password'); // Excludes password, includes all else
    res.render('user-management', { users, user: req.session });
});

app.get('/loans', isAuthenticated, isAdmin, async (req, res) => {
    const loans = await Loan.find().populate('loanOfficerId', 'fullName accountNumber accountName bankName');
    const loanOfficers = await User.find({ role: 'LoanOfficer' });
    const borrowers = await User.find({ role: 'Borrower' });
    res.render('loans', { loans, loanOfficers, borrowers, user: req.session });
});

app.post('/loans/add', isAuthenticated, isAdmin, async (req, res) => {
    const { borrowerId, officerId, date, principal } = req.body;
    
    try {
        const borrowerUser = await User.findById(borrowerId);
        const officerUser = await User.findById(officerId);

        if (!borrowerUser || !officerUser) return res.status(400).send('Borrower or Officer not found.');

        const newLoan = new Loan({
            borrowerId: borrowerUser._id,
            loanOfficerId: officerUser._id,
            borrower: borrowerUser.fullName || borrowerUser.username, 
            officer: officerUser.fullName || officerUser.username,     
            disbursementDate: date,
            principal: parseInt(principal)
        });
        const savedLoan = await newLoan.save();
        
        // This helper now creates payment records with officerId embedded
        await createPaymentSchedule(savedLoan); 
        
        res.redirect('/loans');
    } catch (error) {
        console.error('Error creating loan:', error);
        res.status(500).send('Failed to create loan: ' + error.message);
    }
});

app.get('/customers', isAuthenticated, isAdmin, async (req, res) => {
    const loans = await Loan.find().populate('loanOfficerId', 'accountNumber accountName bankName');
    const customers = [];
    
    for (const loan of loans) {
        const totalRepay = loan.principal + (loan.principal * 0.2);
        const paymentsMade = await Payment.find({ loanId: loan._id, paid: { $gt: 0 } });
        
        const totalPaid = paymentsMade.reduce((sum, payment) => sum + payment.paid, 0);
        const remainingBalance = totalRepay - totalPaid;
        
        customers.push({
            borrower: loan.borrower,
            officer: loan.officer,
            accountNumber: loan.loanOfficerId.accountNumber,
            bankName: loan.loanOfficerId.bankName,
            accountName: loan.loanOfficerId.accountName,
            principal: Math.ceil(loan.principal),
            remainingBalance: Math.ceil(remainingBalance)
        });
    }
    
    res.render('customers', { customers, user: req.session });
});

// Loan Details Page (admin/officer only)
app.get('/loan-details/:id', isAuthenticated, async (req, res) => {
    if (req.session.role !== 'Admin' && req.session.role !== 'LoanOfficer') {
        return res.status(403).send('Access Denied: Admin or Loan Officer required.');
    }
    
    const loanId = req.params.id;
    const loan = await Loan.findById(loanId).populate('borrowerId loanOfficerId', 'fullName accountNumber accountName bankName');
    if (!loan) return res.status(404).send('Loan not found.');
    
    const totalRepay = Math.ceil(loan.principal * 1.2);
    const dailyPayment = calculateDailyPayment(loan.principal);
    
    // Fetch with .lean() for plain objects; ensure fresh data
    const allPayments = await Payment.find({ loanId: loan._id }).sort({ date: 1 }).lean();
    
    const totalPaidAmount = allPayments.reduce((sum, p) => sum + (p.paid || 0), 0);
    const remainingBalance = Math.ceil(totalRepay - totalPaidAmount);
    
    // Build 40-day calendar: Each slot keyed by due date, with status for color
    const paymentCalendar = [];
    const startDate = moment(loan.disbursementDate).add(1, 'days'); // Day 1 due date
    let paidSlots = 0;
    
    for (let i = 0; i < 40; i++) {
        const dueDate = startDate.clone().add(i, 'days');
        const dueDateStr = dueDate.format('YYYY-MM-DD');
        
        // Explicit string match: Ensure date stored as string in schema if needed
        const paymentRecord = allPayments.find(p => moment(p.date).format('YYYY-MM-DD') === dueDateStr);
        
        const slot = {
            day: i + 1, // 1-40
            dueDate: dueDateStr,
            expected: dailyPayment,
            paid: paymentRecord ? paymentRecord.paid || 0 : 0,
            skipped: paymentRecord ? paymentRecord.skipped : false,
            status: 'pending', // Default gray (future)
            color: 'gray' // CSS class for EJS
        };
        
        const now = moment(); // Current date
        const isPastDue = dueDate.isBefore(now, 'day');
        const isToday = dueDate.isSame(now, 'day');
        const isFuture = dueDate.isAfter(now, 'day');
        
        if (slot.paid > 0) {
            slot.status = 'paid';
            slot.color = 'green';
            paidSlots++;
        } else if (slot.skipped || (isPastDue && slot.paid === 0)) {
            slot.status = 'skipped/unpaid';
            slot.color = 'red';
        } else if (isFuture) {
            slot.status = 'pending';
            slot.color = 'gray';
        } else if (isToday) {
            slot.status = 'due today';
            slot.color = 'orange'; // Optional: Highlight today if unpaid
        }
        
        paymentCalendar.push(slot);
    }
    
    const progress = `${paidSlots}/40`;
    
    // Calendar helpers for alignment
    const firstDueMoment = startDate.clone();
    const calendarStartMoment = firstDueMoment.clone().startOf('isoWeek'); // Monday of first due's week
    const lastDueMoment = startDate.clone().add(39, 'days');
    
    res.render('loan-details', { 
        loan, 
        paymentCalendar, 
        totalRepay, 
        remainingBalance, 
        progress,
        dailyPayment,
        user: req.session,
        moment, // Pass moment for EJS date formatting
        firstDue: firstDueMoment.format('YYYY-MM-DD'), // For reference
        calendarStart: calendarStartMoment.format('YYYY-MM-DD'), // Monday start
        lastDue: lastDueMoment.format('YYYY-MM-DD') // End for bounding
    });
});


// Mark All Paid for a Loan (admin/officer only)
// Mark multiple days as paid (1–40)
app.post('/loan-details/:id/mark-multiple-paid', isAuthenticated, async (req, res) => {
    if (req.session.role !== 'Admin' && req.session.role !== 'LoanOfficer') {
        return res.status(403).send('Access Denied: Admin or Loan Officer required.');
    }

    const loanId = req.params.id;
    const daysCount = parseInt(req.body.daysCount, 10);

    if (isNaN(daysCount) || daysCount < 1 || daysCount > 40) {
        return res.status(400).send('Invalid days count. Please enter a number between 1 and 40.');
    }

    const loan = await Loan.findById(loanId);
    if (!loan) return res.status(404).send('Loan not found.');

    const startDate = moment(loan.disbursementDate).add(1, 'days');
    const dailyPayment = calculateDailyPayment(loan.principal);
    const now = new Date();

    for (let i = 0; i < daysCount; i++) {
        const dueDate = startDate.clone().add(i, 'days').format('YYYY-MM-DD');
        await Payment.findOneAndUpdate(
            { loanId: loan._id, date: dueDate },
            { paid: dailyPayment, skipped: false, timestamp: now, officerId: req.session.userId },
            { upsert: true }
        );
    }

    res.redirect(`/loan-details/${loanId}`);
});


// Flexible Bi-Weekly Summary (admin only)
// Flexible Bi-Weekly Summary (admin/officer)
// Flexible Bi-Weekly Summary (admin/officer)
app.get('/biweekly-flexible', isAuthenticated, async (req, res) => {
  if (req.session.role !== 'Admin' && req.session.role !== 'LoanOfficer') {
    return res.status(403).send('Access Denied: Admin or Loan Officer required.');
  }

  const { startDate, endDate } = req.query;
  let periods = [];

  // Default periods
  if (!startDate || !endDate) {
    const startRef = moment('2025-09-14');
    const now = moment();
    const numPeriods = Math.ceil(now.diff(startRef, 'days') / 14) + 3;

    for (let i = 0; i < numPeriods; i++) {
      const periodStart = startRef.clone().add(i * 14, 'days');
      const periodEnd = periodStart.clone().add(13, 'days');
      periods.push({ start: periodStart.format('YYYY-MM-DD'), end: periodEnd.format('YYYY-MM-DD') });
    }
  } else {
    periods = [{ start: moment(startDate).format('YYYY-MM-DD'), end: moment(endDate).format('YYYY-MM-DD') }];
  }

  // ✅ Preload all users (for officer rate lookup)
  const allUsers = await User.find({}, 'username _id').lean();
  const officerRates = {};
  for (const user of allUsers) {
    officerRates[user._id.toString()] = user.username === 'faith' ? 0.25 : 0.17;
  }

  const summaries = [];

  for (const period of periods) {
    const paymentsQuery = { date: { $gte: period.start, $lte: period.end } };
    if (req.session.role === 'LoanOfficer') {
      paymentsQuery.officerId = req.session.userId;
    }

    // ✅ Use lean query (faster, no Mongoose document overhead)
    const payments = await Payment.find(paymentsQuery)
      .populate({ path: 'loanId', select: 'principal loanOfficerId officer' })
      .lean();

    let expected = 0, collected = 0, totalInterest = 0;
    const officerShares = {};

    for (const payment of payments) {
      const loan = payment.loanId;
      if (!loan) continue;

      const rate = officerRates[loan.loanOfficerId?.toString()] || 0.17;
      const dailyInterest = calculateDailyInterestPortion(loan.principal);
      const officerShare = calculateOfficerDailyShare(loan.principal, rate);

      if (!officerShares[loan.officer]) officerShares[loan.officer] = 0;

      expected += payment.expected || 0;
      const paidAmount = payment.paid ?? 0;
      collected += paidAmount;

      if (payment.expected > 0) {
        const paidRatio = paidAmount / payment.expected;
        totalInterest += dailyInterest * paidRatio;
        officerShares[loan.officer] += officerShare * paidRatio;
      }
    }

    summaries.push({
      start: period.start,
      end: period.end,
      expected: Math.ceil(expected),
      collected: Math.ceil(collected),
      totalInterest: Math.ceil(totalInterest),
      officerShares,
    });
  }

  res.render('biweekly-flexible', { periods: summaries, user: req.session, moment });
});

app.get('/offline.ejs', (req, res) => {
  res.render('offline');
});


app.listen(port, () => {
    console.log(`App running on http://localhost:${port}`);
    console.log('--- IMPORTANT --- Navigate to /setup-admin first to create your initial admin user.');
});