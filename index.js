require('dotenv').config();

const express      = require('express');
const bcrypt       = require('bcrypt');
const jwt          = require('jsonwebtoken');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const mysql        = require('mysql');
const https        = require('https');
const fs           = require('fs');
const winston      = require('winston');
const cookieParser = require('cookie-parser');

const authenticateToken = require('./middleware/authenticateToken');
const checkApiKey       = require('./middleware/checkApiKey');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ── LOGGER ────────────────────────────────────────────
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});
logger.info('Application started');

// ── HELMET SECURITY HEADERS ───────────────────────────
app.use(helmet());
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc:              ["'self'"],
        scriptSrc:               ["'self'"],
        styleSrc:                ["'self'", "'unsafe-inline'"],
        imgSrc:                  ["'self'", "data:"],
        objectSrc:               ["'none'"],
        frameAncestors:          ["'none'"],
        formAction:              ["'self'"],
        upgradeInsecureRequests: [],
        blockAllMixedContent:    [],
    }
}));

// ── CORS ──────────────────────────────────────────────
app.use(cors({
    origin: ['http://localhost:5000', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
    credentials: true
}));

// ── RATE LIMITERS ─────────────────────────────────────
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests. Try again later.'
});

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts. Wait 10 minutes.'
});

app.use(generalLimiter);

// ── DATABASE ──────────────────────────────────────────
const pool = mysql.createPool({
    host:     process.env.DB_HOST,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// ── LOGIN ATTEMPT TRACKER ─────────────────────────────
const loginAttempts = {};

// ── LOGIN ROUTE ───────────────────────────────────────
app.post('/login', loginLimiter, async function(req, res) {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Missing credentials');
    }

    // Check lockout
    if (loginAttempts[username] && loginAttempts[username].count >= 5) {
        const timePassed = Date.now() - loginAttempts[username].lastAttempt;
        if (timePassed < 10 * 60 * 1000) {
            logger.warn(`Account locked: ${username}`);
            return res.status(429).send('Too many failed attempts. Try again later.');
        } else {
            loginAttempts[username] = { count: 0, lastAttempt: null };
        }
    }

    pool.query('SELECT * FROM admin WHERE username = ?', [username], async function(err, rows) {
        if (err || rows.length === 0) {
            logger.warn(`Failed login for: ${username}`);
            return res.status(400).send('User not found');
        }

        const isMatch = await bcrypt.compare(password, rows[0].password);
        if (isMatch) {
            loginAttempts[username] = { count: 0, lastAttempt: null };
            logger.info(`Successful login: ${username}`);
            const token = jwt.sign(
                { id: rows[0].id, username: rows[0].username },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            res.status(200).send({ message: 'Authentication successful', token });
        } else {
            if (!loginAttempts[username]) {
                loginAttempts[username] = { count: 0, lastAttempt: null };
            }
            loginAttempts[username].count++;
            loginAttempts[username].lastAttempt = Date.now();
            logger.warn(`Wrong password for: ${username} | Attempt #${loginAttempts[username].count}`);
            return res.status(401).send('Invalid credentials');
        }
    });
});

// ── CRUD ROUTES ───────────────────────────────────────
app.post('/create', checkApiKey, authenticateToken, function(req, res) {
    var userData = {
        name:       req.body.Name,
        studentID:  req.body.StudentID,
        department: req.body.Department
    };
    pool.query('INSERT INTO user SET ?', userData, function(err) {
        if (err) return res.status(400).send('Unable to insert');
        logger.info(`User created: ${req.body.Name}`);
        res.status(200).send('User Added');
    });
});

app.get('/list', checkApiKey, authenticateToken, function(req, res) {
    pool.query('SELECT * FROM user', (err, result) => {
        if (err) return res.status(400).send('Error in Connection');
        res.status(200).send(result);
    });
});

app.delete('/delete/:id', checkApiKey, authenticateToken, function(req, res) {
    pool.query('DELETE FROM user WHERE studentID = ?', [req.params.id], (err) => {
        if (err) return res.status(400).send('User not found');
        logger.info(`User deleted: ID ${req.params.id}`);
        pool.query('SELECT * FROM user', (err, result) => {
            if (err) return res.status(400).send('Error in Connection');
            res.status(200).send(result);
        });
    });
});

// ── HTTPS SERVER ──────────────────────────────────────
const httpsOptions = {
    key:  fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};
https.createServer(httpsOptions, app).listen(8443, () => {
    logger.info('HTTPS Server running on port 8443');
});