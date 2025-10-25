// To run this: npm install express jsonwebtoken cookie-parser cors

const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors'); // <--- ADDED: Import CORS
const app = express();
const PORT = 3000;

// =======================================================
// CONFIGURATION AND SECRETS
// NOTE: Use environment variables (.env file) in a real project
// =======================================================

const ACCESS_TOKEN_SECRET = 'your_access_secret_key';
const REFRESH_TOKEN_SECRET = 'your_refresh_secret_key';

// Token Expiry Times
const ACCESS_TOKEN_EXPIRY = '1m'; // 1 minute (short-lived)
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days (long-lived)

// =======================================================
// MIDDLEWARE (CRUCIAL FOR PARSING req.body)
// =======================================================
// ADDED: Allow cross-origin requests and enable cookie transfer (credentials: true)
app.use(cors({
    // 'origin: true' allows any origin to connect, which is necessary when running client.html locally (file://)
    origin: true, 
    // 'credentials: true' is CRITICAL for the browser to send the HTTP-Only cookie
    credentials: true 
}));

app.use(express.json()); // <--- This is REQUIRED to parse JSON body data
app.use(cookieParser());

// =======================================================
// SIMULATED DATABASE (In a real app, use MongoDB, PostgreSQL, etc.)
// =======================================================

// User data storage
const users = [{ id: 1, username: 'testuser', password: 'password' }];

// Refresh Token Whitelist (Server-side storage for active refresh tokens)
let refreshTokens = [];

// =======================================================
// HELPER FUNCTIONS
// =======================================================

/**
 * Generates both an Access Token and a Refresh Token for a user.
 * @param {object} user - The user payload (e.g., { id, username })
 * @returns {object} { accessToken, refreshToken }
 */
const generateTokens = (user) => {
    // Access Token: Short-lived, minimal payload
    const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        ACCESS_TOKEN_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    // Refresh Token: Long-lived, minimal payload, signed with a separate secret
    // MODIFIED: Including username in refresh token payload for robustness (Change 1)
    const refreshToken = jwt.sign(
        { id: user.id, username: user.username },
        REFRESH_TOKEN_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    return { accessToken, refreshToken };
};

// =======================================================
// MIDDLEWARE: ACCESS TOKEN VALIDATION
// =======================================================

/**
 * Middleware to verify the Access Token on protected routes.
 */
function verifyAccessToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects: Bearer <token>

    if (token == null) {
        // 401: Client needs to authenticate (either login or refresh)
        return res.status(401).send('Access Token required.');
    }

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            // 401: Token is expired or invalid. Client must attempt refresh.
            return res.status(401).send('Access Token expired or invalid.');
        }
        // Token is valid, attach user payload and proceed
        req.user = user;
        next();
    });
}

// =======================================================
// SYSTEM ROUTES
// =======================================================

/**
 * @route GET /
 * Provides a simple status check for the running API.
 */
app.get('/', (req, res) => {
    res.json({
        message: 'JWT Token Refresh API is running.',
        status: 'OK',
        documentation: 'Use POST to /login, POST to /token/refresh, and GET to /protected.'
    });
});

// =======================================================
// AUTHENTICATION ENDPOINTS
// =======================================================

/**
 * @route POST /login
 * Authenticates user, issues tokens, and sets the refresh token cookie.
 */
app.post('/login', (req, res) => {
    const { username, password } = req.body; 

    // 1. Authenticate User (In a real app, hash and compare passwords)
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).send('Invalid Credentials');
    }

    // 2. Generate Tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // 3. Store Refresh Token in DB (Whitelist)
    refreshTokens.push(refreshToken);

    // 4. Send Refresh Token in a secure HTTP-Only Cookie
    res.cookie('jwt', refreshToken, {
        httpOnly: true, // Crucial for XSS mitigation
        secure: false, // Set to true in production (requires HTTPS)
        sameSite: 'Lax', // Good security practice
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days (matching token expiry)
    });

    // 5. Send Access Token in the response body
    return res.json({ accessToken });
});

/**
 * @route POST /token/refresh
 * Exchanges a valid Refresh Token for a new Access Token.
 */
app.post('/token/refresh', (req, res) => {
    // 1. Get Refresh Token from HTTP-Only Cookie
    const refreshToken = req.cookies.jwt;

    if (!refreshToken) {
        // This is the most likely cause of the 401 error if the client failed to send the cookie.
        return res.status(401).send('No Refresh Token provided in cookie.');
    }

    // 2. Check server-side whitelist (Database check)
    if (!refreshTokens.includes(refreshToken)) {
        // Token is not recognized or was manually revoked
        return res.status(403).send('Invalid Refresh Token (Server denied).');
    }

    // 3. Verify Refresh Token signature and expiry
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            // Token is expired, tampered with, or failed verification
            // Immediately revoke the bad token and clear the cookie
            refreshTokens = refreshTokens.filter(token => token !== refreshToken);
            res.clearCookie('jwt');
            return res.status(403).send('Forbidden (Refresh Token expired or invalid).');
        }

        // 4. Token is valid. Issue a new Access Token and a new Refresh Token (Rotation).
        // Using decoded.username (Change 2)
        const user = { id: decoded.id, username: decoded.username || 'testuser' }; 
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

        // MODIFIED: Implement Refresh Token Rotation (Change 3)
        // a. Remove the old token from the whitelist (revoke)
        refreshTokens = refreshTokens.filter(token => token !== refreshToken);
        
        // b. Add the new token to the whitelist
        refreshTokens.push(newRefreshToken);

        // c. Send the new Refresh Token in a secure HTTP-Only Cookie
        res.cookie('jwt', newRefreshToken, {
            httpOnly: true, // Crucial for XSS mitigation
            secure: false, // Set to true in production (requires HTTPS)
            sameSite: 'Lax', // Good security practice
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days (matching token expiry)
        });

        // d. Send the new Access Token in the response body
        return res.json({ accessToken });
    });
});

/**
 * @route POST /logout
 * Invalidates the current Refresh Token and clears the cookie.
 */
app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.jwt;

    // 1. Remove the token from the server-side list (Revocation)
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    console.log(`Token revoked. Current active refresh tokens: ${refreshTokens.length}`);

    // 2. Clear the cookie on the client side
    res.clearCookie('jwt');

    res.sendStatus(204); // Success, No Content
});

// =======================================================
// PROTECTED ROUTES
// =======================================================

/**
 * @route GET /protected
 * A route accessible only with a valid Access Token.
 */
app.get('/protected', verifyAccessToken, (req, res) => {
    res.json({
        message: `Welcome, ${req.user.username}! This is protected data accessed via a valid Access Token.`,
        userId: req.user.id
    });
});

// =======================================================
// SERVER START
// =======================================================

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`ACCESS_TOKEN_EXPIRY: ${ACCESS_TOKEN_EXPIRY}`);
});
