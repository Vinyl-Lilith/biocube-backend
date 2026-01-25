// server.js - Patched for frontend compatibility and improved auth handling

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const xlsx = require('xlsx');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "29f1507d30a50e8305661931fcb9d466"; // In prod, use env var

// --- MIDDLEWARE ---
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' })); // Increased limit for Camera Base64
app.use(morgan('dev')); // Logging

// --- IN-MEMORY STORAGE ---
// Note: On Render Free Tier, this resets on deploy/sleep. 
// For permanent storage, connect a MongoDB Atlas database.
const users = []; // [{ username, hash, role }]
const logs = [];  // [{ timestamp, ...sensorData }]
let systemState = {
    telemetry: {},
    camera_feed: null, // Base64 string (without data: prefix)
    settings: {
        auto_mode: true,
        thresholds: { temp: 24.0, soil: 400, n: 50, p: 20, k: 30 }
    },
    command_queue: [] // Commands waiting for Pi
};

// --- HELPERS ---
const hashPassword = (password) => bcrypt.hashSync(password, 8);
const verifyPassword = (password, hash) => bcrypt.compareSync(password, hash);
const generateToken = (user) => jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });

// Extract token helper: supports "Bearer <token>" or raw token in header or ?token= query param
const extractTokenFromReq = (req) => {
    // header (Authorization) or fallback to query param
    let token = req.headers['authorization'] || req.headers['Authorization'] || req.query.token || null;
    if (!token) return null;
    if (typeof token === 'string' && token.toLowerCase().startsWith('bearer ')) {
        token = token.slice(7).trim();
    }
    return token;
};

// Middleware to verify Token (supports header or ?token=)
const authenticate = (req, res, next) => {
    const token = extractTokenFromReq(req);
    if (!token) return res.status(403).json({ error: "No token provided" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Unauthorized", details: err.message });
        req.user = decoded;
        next();
    });
};

// --- ROUTES: Root / Health-check ---
app.get('/', (req, res) => {
    res.send('BioCube Backend OK');
});

// --- ROUTES: AUTH ---
// Register
app.post('/api/register', (req, res) => {
    const { username, password, isAdmin } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const uname = String(username).trim();
    if (users.find(u => u.username === uname)) {
        return res.status(400).json({ error: "Username taken" });
    }

    const newUser = {
        username: uname,
        hash: hashPassword(String(password)),
        role: isAdmin ? 'admin' : 'viewer'
    };
    users.push(newUser);
    return res.json({ message: "User created", token: generateToken(newUser), role: newUser.role });
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    const user = users.find(u => u.username === String(username).trim());
    
    if (!user || !verifyPassword(String(password), user.hash)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    
    return res.json({ message: "Welcome back", token: generateToken(user), role: user.role });
});

// --- ROUTES: PI INTERFACE ---
// The Pi calls this every ~2 seconds
app.post('/api/sync', (req, res) => {
    const { device_id, sensor_data, camera_feed } = req.body || {};

    // 1. Update State
    if (sensor_data && typeof sensor_data === 'object') {
        systemState.telemetry = sensor_data;
        // Add to logs
        logs.push({
            timestamp: new Date(),
            ...sensor_data
        });
        // Keep logs capped at ~24 hours (assuming 1 log/sec = 86400 max)
        if (logs.length > 86400) logs.shift(); 
    }
    if (camera_feed) systemState.camera_feed = camera_feed; // assume raw base64 string without data: prefix

    // 2. Prepare Response (Commands for Pi)
    const response = {
        settings: systemState.settings
    };

    // If there is a manual command waiting, send it once then remove it
    if (systemState.command_queue.length > 0) {
        response.manual_command = systemState.command_queue.shift();
    }

    res.json(response);
});

// --- ROUTES: WEB APP INTERFACE ---
// Status endpoint used by frontend polling (requires auth)
app.get('/api/status', authenticate, (req, res) => {
    res.json({
        telemetry: systemState.telemetry || {},
        camera: systemState.camera_feed || null,
        settings: systemState.settings || {},
        pi_connected: !!(systemState.telemetry && Object.keys(systemState.telemetry).length)
    });
});

// Get Dashboard Data
app.get('/api/dashboard', authenticate, (req, res) => {
    res.json({
        telemetry: systemState.telemetry,
        camera: systemState.camera_feed,
        settings: systemState.settings,
        logs_count: logs.length
    });
});

// Send Manual Command
app.post('/api/command', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
    if (systemState.settings.auto_mode) return res.status(400).json({ error: "Turn off Auto Mode first" });

    const command = req.body; // e.g., { "pump_water": true }
    if (!command || typeof command !== 'object') return res.status(400).json({ error: "Invalid command" });

    systemState.command_queue.push(command);
    res.json({ message: "Command queued" });
});

// Update Settings
app.post('/api/settings', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });

    const { auto_mode, thresholds } = req.body || {};
    if (auto_mode !== undefined) systemState.settings.auto_mode = !!auto_mode;
    if (thresholds && typeof thresholds === 'object') systemState.settings.thresholds = { ...systemState.settings.thresholds, ...thresholds };

    res.json({ message: "Settings updated", settings: systemState.settings });
});

// Download Excel Logs
app.get('/api/export', (req, res) => {
    // Allow token either via header or query param for compatibility
    const token = extractTokenFromReq(req);
    if (!token) return res.status(403).json({ error: "No token provided" });

    // Verify token before exporting
    try {
        jwt.verify(token, SECRET_KEY);
    } catch (err) {
        return res.status(401).json({ error: "Unauthorized", details: err.message });
    }

    const type = req.query.type || 'standard'; // 'standard' or 'depth'

    // Filter Data
    const data = logs.map(log => {
        if (type === 'standard') {
            return {
                Time: log.timestamp,
                Temp_In: log.temp_in,
                Hum_In: log.hum_in,
                Soil: log.soil,
                NPK_N: log.npk_n,
                NPK_P: log.npk_p,
                NPK_K: log.npk_k
            };
        } else {
            // For "depth", return the entire log object (note: keep structure reasonable)
            return {
                Time: log.timestamp,
                ...Object.fromEntries(Object.entries(log).filter(([k]) => k !== 'timestamp'))
            };
        }
    });

    // Create Sheet
    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(data);
    xlsx.utils.book_append_sheet(wb, ws, "BioCube Logs");

    // Write to Buffer
    const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Disposition', `attachment; filename="BioCube_${type}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
});

// Catch-all for unknown routes (optional friendly JSON)
app.use((req, res, next) => {
    if (req.path && req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API route not found' });
    }
    next();
});

// Basic error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', details: err.message });
});

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`BioCube Server running on port ${PORT}`);
});
