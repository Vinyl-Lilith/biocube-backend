const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const xlsx = require('xlsx');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "29f1507d30a50e8305661931fcb9d466"; // In prod, use env var

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
    camera_feed: null, // Base64 string
    settings: {
        auto_mode: true,
        thresholds: { temp: 24.0, soil: 400, n: 50, p: 20, k: 30 }
    },
    command_queue: [] // Commands waiting for Pi
};

// --- AUTHENTICATION HELPERS ---
const hashPassword = (password) => bcrypt.hashSync(password, 8);
const verifyPassword = (password, hash) => bcrypt.compareSync(password, hash);
const generateToken = (user) => jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });

// Middleware to verify Token
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "No token provided" });
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Unauthorized" });
        req.user = decoded;
        next();
    });
};

// --- ROUTES: AUTH ---

app.post('/api/register', (req, res) => {
    const { username, password, isAdmin } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: "Username taken" });
    }

    const newUser = {
        username,
        hash: hashPassword(password),
        role: isAdmin ? 'admin' : 'viewer'
    };
    users.push(newUser);
    res.json({ message: "User created", token: generateToken(newUser) });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user || !verifyPassword(password, user.hash)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    
    res.json({ message: "Welcome back", token: generateToken(user), role: user.role });
});

// --- ROUTES: PI INTERFACE ---

// The Pi calls this every 2 seconds
app.post('/api/sync', (req, res) => {
    const { device_id, sensor_data, camera_feed } = req.body;

    // 1. Update State
    if (sensor_data) {
        systemState.telemetry = sensor_data;
        // Add to logs
        logs.push({
            timestamp: new Date(),
            ...sensor_data
        });
        // Keep logs capped at ~24 hours (assuming 1 log/sec = 86400 max)
        if (logs.length > 86400) logs.shift(); 
    }
    if (camera_feed) systemState.camera_feed = camera_feed;

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
    systemState.command_queue.push(command);
    res.json({ message: "Command queued" });
});

// Update Settings
app.post('/api/settings', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });

    const { auto_mode, thresholds } = req.body;
    if (auto_mode !== undefined) systemState.settings.auto_mode = auto_mode;
    if (thresholds) systemState.settings.thresholds = { ...systemState.settings.thresholds, ...thresholds };

    res.json({ message: "Settings updated", settings: systemState.settings });
});

// Download Excel Logs
app.get('/api/export', authenticate, (req, res) => {
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
            return log; // Return everything for in-depth
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

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`BioCube Server running on port ${PORT}`);
});
