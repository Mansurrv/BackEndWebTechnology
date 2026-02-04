const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');

// --- MongoDB Connection - UPDATED for Mongoose 6+ ---
mongoose.connect('mongodb://127.0.0.1:27017/f1Database')
.then(() => {
    console.log("MongoDB connected successfully");
    createDriversCollection();
})
.catch(err => console.error("MongoDB connection error:", err.message));

// --- Alternative connection string if you need options ---
// mongoose.connect('mongodb://127.0.0.1:27017/f1Database', {
//     // These options are automatically set in Mongoose 6+
//     // serverSelectionTimeoutMS: 5000,
//     // socketTimeoutMS: 45000,
// })
// .then(() => {
//     console.log("MongoDB connected successfully");
//     createDriversCollection();
// })
// .catch(err => console.error("MongoDB connection error:", err.message));

// --- Driver Schema & Model ---
const driverSchema = new mongoose.Schema({
    name: { type: String, required: true },
    team: { type: String, required: true },
    points: { type: Number, default: 0 },
    wins: { type: Number, default: 0 },
    podiums: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const Driver = mongoose.model('Driver', driverSchema);

// --- User Schema & Model ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { 
        type: String, 
        required: true, 
        unique: true,
        lowercase: true,
        trim: true
    },
    password: { type: String, required: true },
    apiKeys: [{
        key: { type: String, required: true, unique: true },
        name: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
        lastUsed: { type: Date },
        isActive: { type: Boolean, default: true }
    }],
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// --- API Key Utilities ---
const crypto = require('crypto');

function generateAPIKey() {
    return crypto.randomBytes(32).toString('hex');
}

function generateAPIKeyPrefix(key) {
    return `f1_${key.substring(0, 8)}`;
}

// --- API Authentication Middleware ---
async function requireAPIKey(req, res, next) {
    try {
        const apiKey = req.headers['x-api-key'] || req.query.apiKey;
        
        if (!apiKey) {
            return res.status(401).json({ 
                error: 'API key is required',
                message: 'Please provide a valid API key in the x-api-key header or apiKey query parameter'
            });
        }
        
        // Find user by API key
        const user = await User.findOne({ 
            'apiKeys.key': apiKey,
            'apiKeys.isActive': true
        });
        
        if (!user) {
            return res.status(401).json({ 
                error: 'Invalid API key',
                message: 'The provided API key is invalid or inactive'
            });
        }
        
        // Update last used timestamp
        await User.updateOne(
            { _id: user._id, 'apiKeys.key': apiKey },
            { $set: { 'apiKeys.$.lastUsed': new Date() } }
        );
        
        // Attach user to request
        req.apiUser = {
            id: user._id,
            name: user.name,
            email: user.email
        };
        
        next();
    } catch (err) {
        console.error('API key validation error:', err.message);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'Failed to validate API key'
        });
    }
}

// --- Combined Authentication Middleware ---
function requireAuth(req, res, next) {
    // Check for API key first (for API requests)
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    
    if (apiKey) {
        return requireAPIKey(req, res, next);
    }
    
    // Fall back to session authentication (for web UI)
    if (!req.session.user) {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ 
                error: 'Unauthorized',
                message: 'API key or session required'
            });
        }
        return res.redirect('/login?error=Please login to access this page');
    }
    
    next();
}

// API Key Management Routes
app.get('/profile/api-keys', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        res.render('api-keys', {
            user: req.session.user,
            apiKeys: user.apiKeys || [],
            success: req.query.success,
            error: req.query.error
        });
    } catch (err) {
        console.error('API keys fetch error:', err.message);
        res.redirect('/profile?error=Failed to load API keys');
    }
});

app.post('/profile/api-keys/create', requireAuth, async (req, res) => {
    try {
        const { keyName } = req.body;
        
        if (!keyName || keyName.trim().length < 2) {
            return res.redirect('/profile/api-keys?error=API key name must be at least 2 characters long');
        }
        
        const newAPIKey = generateAPIKey();
        const keyPrefix = generateAPIKeyPrefix(newAPIKey);
        
        await User.findByIdAndUpdate(
            req.session.user.id,
            {
                $push: {
                    apiKeys: {
                        key: newAPIKey,
                        name: keyName.trim(),
                        createdAt: new Date()
                    }
                }
            }
        );
        
        // Show the full key only once for user to copy
        res.render('api-key-created', {
            user: req.session.user,
            apiKey: newAPIKey,
            keyPrefix: keyPrefix,
            keyName: keyName.trim(),
            success: 'API key created successfully'
        });
        
    } catch (err) {
        console.error('API key creation error:', err.message);
        res.redirect('/profile/api-keys?error=Failed to create API key');
    }
});

app.post('/profile/api-keys/revoke/:keyId', requireAuth, async (req, res) => {
    try {
        await User.updateOne(
            { _id: req.session.user.id, 'apiKeys._id': req.params.keyId },
            { $set: { 'apiKeys.$.isActive': false } }
        );
        
        res.redirect('/profile/api-keys?success=API key revoked successfully');
    } catch (err) {
        console.error('API key revocation error:', err.message);
        res.redirect('/profile/api-keys?error=Failed to revoke API key');
    }
});

app.post('/profile/api-keys/delete/:keyId', requireAuth, async (req, res) => {
    try {
        await User.updateOne(
            { _id: req.session.user.id },
            { $pull: { apiKeys: { _id: req.params.keyId } } }
        );
        
        res.redirect('/profile/api-keys?success=API key deleted successfully');
    } catch (err) {
        console.error('API key deletion error:', err.message);
        res.redirect('/profile/api-keys?error=Failed to delete API key');
    }
});

// --- Seed initial drivers if empty ---
async function createDriversCollection() {
    try {
        const count = await Driver.countDocuments();
        if (count === 0) {
            console.log('Seeding initial drivers data...');
            await seedInitialData();
        } else {
            console.log(`Found ${count} drivers in database`);
        }
    } catch (err) {
        console.error('Error creating collection:', err.message);
    }
}

async function seedInitialData() {
    const initialDrivers = [
        { name: 'Max Verstappen', team: 'Red Bull', points: 395, wins: 14, podiums: 18 },
        { name: 'Lando Norris', team: 'McLaren', points: 285, wins: 2, podiums: 12 },
        { name: 'Charles Leclerc', team: 'Ferrari', points: 252, wins: 2, podiums: 8 },
        { name: 'Sergio Perez', team: 'Red Bull', points: 229, wins: 2, podiums: 10 },
        { name: 'Oscar Piastri', team: 'McLaren', points: 197, wins: 1, podiums: 7 }
    ];

    try {
        await Driver.insertMany(initialDrivers);
        console.log('Initial drivers data seeded');
    } catch (err) {
        console.error('Error seeding data:', err.message);
    }
}

// --- Express Middlewares ---
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: 'f1-tracker-secret-key-2024-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        secure: false,
        httpOnly: true
    }
}));

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url} - ${req.session.user ? 'User: ' + req.session.user.email : 'Guest'}`);
    next();
});

// Make user data available to all views
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.isAuthenticated = !!req.session.user;
    next();
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login?error=Please login to access this page');
    }
    next();
}

// --- API Routes with dual authentication ---

// Get all drivers - Public
app.get('/api/drivers', async (req, res) => {
    try {
        const drivers = await Driver.find().sort({ points: -1 });
        res.status(200).json(drivers);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get single driver - Public
app.get('/api/drivers/:id', async (req, res) => {
    try {
        const driver = await Driver.findById(req.params.id);
        if (!driver) return res.status(404).json({ error: 'Driver not found' });
        res.status(200).json(driver);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create driver - Protected (Session OR API Key)
app.post('/api/drivers', requireAuth, async (req, res) => {
    try {
        const { name, team, points, wins, podiums } = req.body;

        if (!name || !team) {
            return res.status(400).json({ error: 'Missing required fields: name and team are required' });
        }

        const driver = new Driver({
            name,
            team,
            points: points ? parseInt(points) : 0,
            wins: wins ? parseInt(wins) : 0,
            podiums: podiums ? parseInt(podiums) : 0
        });

        await driver.save();
        res.status(201).json(driver);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update driver - Protected (Session OR API Key)
app.put('/api/drivers/:id', requireAuth, async (req, res) => {
    try {
        const { name, team, points, wins, podiums } = req.body;

        if (!name || !team) {
            return res.status(400).json({ error: 'Missing required fields: name and team are required' });
        }

        const updatedDriver = await Driver.findByIdAndUpdate(
            req.params.id,
            {
                name,
                team,
                points: points ? parseInt(points) : 0,
                wins: wins ? parseInt(wins) : 0,
                podiums: podiums ? parseInt(podiums) : 0
            },
            { new: true, runValidators: true }
        );

        if (!updatedDriver) return res.status(404).json({ error: 'Driver not found' });
        res.status(200).json(updatedDriver);
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete driver - Protected (Session OR API Key)
app.delete('/api/drivers/:id', requireAuth, async (req, res) => {
    try {
        const deletedDriver = await Driver.findByIdAndDelete(req.params.id);
        if (!deletedDriver) return res.status(404).json({ error: 'Driver not found' });
        res.status(200).json({ 
            message: 'Driver deleted successfully', 
            deletedId: deletedDriver._id 
        });
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API Documentation endpoint
app.get('/api/docs', (req, res) => {
    const docs = {
        name: "F1 Tracker API",
        version: "1.0.0",
        description: "API for accessing and managing Formula 1 driver statistics",
        authentication: {
            methods: [
                {
                    type: "Session",
                    description: "For web interface - login via /login endpoint",
                    usage: "Browser cookies automatically"
                },
                {
                    type: "API Key",
                    description: "For programmatic access",
                    usage: "Add 'x-api-key' header or 'apiKey' query parameter"
                }
            ]
        },
        endpoints: {
            public: [
                { path: "/api/drivers", method: "GET", auth: "None", description: "Get all drivers" },
                { path: "/api/drivers/:id", method: "GET", auth: "None", description: "Get specific driver" },
                { path: "/api/constructors", method: "GET", auth: "None", description: "Get all constructors" },
                { path: "/api/info", method: "GET", auth: "None", description: "Get API information" }
            ],
            protected: [
                { path: "/api/drivers", method: "POST", auth: "Session or API Key", description: "Create new driver" },
                { path: "/api/drivers/:id", method: "PUT", auth: "Session or API Key", description: "Update driver" },
                { path: "/api/drivers/:id", method: "DELETE", auth: "Session or API Key", description: "Delete driver" }
            ]
        },
        example: {
            with_api_key: "curl -H 'x-api-key: YOUR_API_KEY' https://yourdomain.com/api/drivers",
            with_query_param: "curl https://yourdomain.com/api/drivers?apiKey=YOUR_API_KEY"
        }
    };
    res.json(docs);
});

// --- Page Routes ---
app.get('/', (req, res) => { 
    res.render('index', { 
        user: req.session.user,
        success: req.query.success,
        error: req.query.error
    }); 
});

app.get('/constructorsPage', (req, res) => { 
    res.render('constructorsPage', { user: req.session.user }); 
});

app.get('/driversPage', (req, res) => { 
    res.render('driversPage', { user: req.session.user }); 
});

app.get('/contact', (req, res) => { 
    res.render('contact', { user: req.session.user }); 
});

app.get('/add', requireAuth, (req, res) => { 
    res.render('add', { user: req.session.user }); 
});

app.get('/mongo', (req, res) => { 
    res.render('mongo', { user: req.session.user }); 
});

// Login page
app.get('/login', (req, res) => { 
    if (req.session.user) {
        return res.redirect('/?success=Already logged in');
    }
    
    const data = {
        error: req.query.error,
        success: req.query.success,
        showRegister: req.query.register === 'true'
    };
    
    res.render('login', data); 
});

// Logout route
app.get('/logout', (req, res) => {
    const userEmail = req.session.user ? req.session.user.email : 'Unknown';
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.redirect('/?error=Logout failed');
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        console.log(`User logged out: ${userEmail}`);
        res.redirect('/?success=Logged out successfully');
    });
});

// --- Authentication Routes ---
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;
        
        console.log('Registration attempt for:', email);
        
        // Validation
        if (!name || !email || !password || !confirmPassword) {
            return res.redirect('/login?register=true&error=All fields are required');
        }
        
        if (password !== confirmPassword) {
            return res.redirect('/login?register=true&error=Passwords do not match');
        }
        
        if (password.length < 6) {
            return res.redirect('/login?register=true&error=Password must be at least 6 characters long');
        }
        
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.redirect('/login?register=true&error=Please enter a valid email address');
        }
        
        const normalizedEmail = email.toLowerCase().trim();
        
        // Check if user already exists
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.redirect('/login?register=true&error=Email already registered');
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Create new user
        const user = new User({
            name: name.trim(),
            email: normalizedEmail,
            password: hashedPassword
        });
        
        await user.save();
        console.log('User registered successfully:', user.email);
        
        // Create session
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email,
            createdAt: user.createdAt
        };
        
        res.redirect('/?success=Registration successful! Welcome to F1 Tracker');
        
    } catch (err) {
        console.error('Registration error:', err.message);
        if (err.code === 11000) {
            return res.redirect('/login?register=true&error=Email already registered');
        }
        res.redirect('/login?register=true&error=Registration failed. Please try again.');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt for:', email);
        
        if (!email || !password) {
            return res.redirect('/login?error=Email and password are required');
        }
        
        const normalizedEmail = email.toLowerCase().trim();
        
        // Find user
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            console.log('User not found:', normalizedEmail);
            return res.redirect('/login?error=Invalid email or password');
        }
        
        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.log('Invalid password for:', normalizedEmail);
            return res.redirect('/login?error=Invalid email or password');
        }
        
        // Create session
        req.session.user = {
            id: user._id,
            name: user.name,
            email: user.email,
            createdAt: user.createdAt
        };
        
        console.log('Login successful for:', user.email);
        res.redirect('/?success=Login successful!');
        
    } catch (err) {
        console.error('Login error:', err.message);
        res.redirect('/login?error=Login failed. Please try again.');
    }
});

// Profile page route
app.get('/profile', requireAuth, (req, res) => { 
    res.render('profile', { 
        user: req.session.user,
        success: req.query.success,
        error: req.query.error
    }); 
});

// Profile update route
app.post('/profile/update', requireAuth, async (req, res) => {
    try {
        const { name, currentPassword, newPassword, confirmPassword } = req.body;
        const userId = req.session.user.id;
        
        console.log('Profile update attempt for:', req.session.user.email);
        
        // Validation
        if (!name) {
            return res.redirect('/profile?error=Name is required');
        }
        
        const updates = { name: name.trim() };
        
        // If changing password
        if (currentPassword || newPassword || confirmPassword) {
            if (!currentPassword || !newPassword || !confirmPassword) {
                return res.redirect('/profile?error=All password fields are required to change password');
            }
            
            if (newPassword !== confirmPassword) {
                return res.redirect('/profile?error=New passwords do not match');
            }
            
            if (newPassword.length < 6) {
                return res.redirect('/profile?error=New password must be at least 6 characters long');
            }
            
            // Get current user
            const user = await User.findById(userId);
            if (!user) {
                return res.redirect('/profile?error=User not found');
            }
            
            // Verify current password
            const validPassword = await bcrypt.compare(currentPassword, user.password);
            if (!validPassword) {
                return res.redirect('/profile?error=Current password is incorrect');
            }
            
            // Hash new password
            const saltRounds = 10;
            updates.password = await bcrypt.hash(newPassword, saltRounds);
        }
        
        // Update user
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updates,
            { new: true }
        );
        
        // Update session
        req.session.user = {
            id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            createdAt: updatedUser.createdAt
        };
        
        console.log('Profile updated for:', updatedUser.email);
        res.redirect('/profile?success=Profile updated successfully');
        
    } catch (err) {
        console.error('Profile update error:', err.message);
        res.redirect('/profile?error=Profile update failed. Please try again.');
    }
});

// Account deletion route
app.post('/profile/delete', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const { confirmEmail } = req.body;
        
        if (!confirmEmail) {
            return res.redirect('/profile?error=Please confirm your email');
        }
        
        if (confirmEmail !== req.session.user.email) {
            return res.redirect('/profile?error=Email does not match');
        }
        
        // Delete user
        await User.findByIdAndDelete(userId);
        
        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
            }
            res.redirect('/?success=Your account has been deleted');
        });
        
    } catch (err) {
        console.error('Account deletion error:', err.message);
        res.redirect('/profile?error=Account deletion failed. Please try again.');
    }
});

// ... Rest of your API routes (keep them as they were) ...

const PORT = process.env.PORT || 3030;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('\n=== F1 Tracker Application ===');
    console.log('Database:', mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected');
    console.log('\nAuthentication Methods:');
    console.log('  1. Session-based (Web UI)');
    console.log('  2. API Key (Programmatic access)');
    console.log('\nProtected Routes:');
    console.log('  GET  /add                - Add driver page (Session)');
    console.log('  POST /api/drivers        - Add new driver (Session OR API Key)');
    console.log('  PUT  /api/drivers/:id    - Update driver (Session OR API Key)');
    console.log('  DEL  /api/drivers/:id    - Delete driver (Session OR API Key)');
    console.log('\nAPI Management:');
    console.log('  GET  /profile/api-keys   - Manage API keys');
    console.log('  GET  /api/docs           - API documentation');
    console.log('====================================');
});