// server.js - Persisted users & commands + status & command ack support

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const xlsx = require('xlsx');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "29f1507d30a50e8305661931fcb9d466";

// --- DATA PERSISTENCE FILES ---
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const COMMANDS_FILE = path.join(DATA_DIR, 'commands.json');

const safeReadJson = (file, fallback) => {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw || 'null') || fallback;
  } catch (e) {
    console.error('JSON read error', file, e);
    return fallback;
  }
};
const safeWriteJson = (file, obj) => {
  try {
    fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.error('JSON write error', file, e);
  }
};

// Load persisted items
let users = safeReadJson(USERS_FILE, []); // [{username, hash, role, banned}]
let persistedCommands = safeReadJson(COMMANDS_FILE, []); // [{id, command, status, created_at, executed_at}]

// --- IN-MEMORY STATE ---
const logs = [];
let systemState = {
  telemetry: {},
  camera_feed: null,
  settings: {
    auto_mode: true,
    thresholds: { temp: 24.0, hum: 60, soil: 400, n: 50, p: 20, k: 30 }
  },
  command_queue: []
};

// restore queued commands
persistedCommands.forEach(c => { if (c.status === 'queued') systemState.command_queue.push(c); });

// --- MIDDLEWARE ---
app.use(cors());
app.use(bodyParser.json({ limit: '20mb' }));
app.use(morgan('dev'));

// --- HELPERS ---
const hashPassword = (password) => bcrypt.hashSync(password, 8);
const verifyPassword = (password, hash) => bcrypt.compareSync(password, hash);
const generateToken = (user) => jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
const normalizeAuthHeader = (hdr) => {
  if (!hdr) return null;
  if (typeof hdr !== 'string') return null;
  if (hdr.startsWith('Bearer ')) return hdr.slice(7);
  return hdr;
};

// AUTH middleware (rejects banned users)
const authenticate = (req, res, next) => {
  const raw = req.headers['authorization'] || req.query.token;
  const token = normalizeAuthHeader(raw);
  if (!token) return res.status(403).json({ error: "No token provided" });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    const u = users.find(x => x.username === decoded.username);
    if (!u) return res.status(401).json({ error: "User not found" });
    if (u.banned) return res.status(403).json({ error: "Account banned" });
    req.user = decoded;
    next();
  });
};

// --- ROUTES ---
// Root
app.get('/', (req, res) => res.send('BioCube Backend Running'));

// Register - first user becomes admin
app.post('/api/register', (req, res) => {
  const { username, password, isAdmin } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: "Username taken" });

  const autoAdmin = users.length === 0;
  const newUser = {
    username,
    hash: hashPassword(password),
    role: autoAdmin ? 'admin' : (isAdmin ? 'admin' : 'viewer'),
    banned: false
  };
  users.push(newUser);
  safeWriteJson(USERS_FILE, users);

  const token = generateToken(newUser);
  res.json({ message: "User created", token, role: newUser.role });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  const u = users.find(x => x.username === username);
  if (!u) return res.status(401).json({ error: "Invalid credentials" });
  if (u.banned) return res.status(403).json({ error: "Account banned" });
  if (!verifyPassword(password, u.hash)) return res.status(401).json({ error: "Invalid credentials" });
  const token = generateToken(u);
  res.json({ message: "Welcome back", token, role: u.role });
});

// Admin - list users
app.get('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const safe = users.map(u => ({ username: u.username, role: u.role, banned: !!u.banned }));
  res.json(safe);
});

// Admin - delete user
app.delete('/api/user/:username', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const { username } = req.params;
  const idx = users.findIndex(u => u.username === username);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  users.splice(idx, 1);
  safeWriteJson(USERS_FILE, users);
  res.json({ message: `User ${username} removed` });
});

// Admin - ban/unban
app.post('/api/user/:username/ban', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const { username } = req.params;
  const u = users.find(x => x.username === username);
  if (!u) return res.status(404).json({ error: "User not found" });
  u.banned = true;
  safeWriteJson(USERS_FILE, users);
  res.json({ message: `${username} banned` });
});
app.post('/api/user/:username/unban', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const { username } = req.params;
  const u = users.find(x => x.username === username);
  if (!u) return res.status(404).json({ error: "User not found" });
  u.banned = false;
  safeWriteJson(USERS_FILE, users);
  res.json({ message: `${username} unbanned` });
});

// PI sync - accepts last_executed_command_id and returns settings & next manual command
app.post('/api/sync', (req, res) => {
  const { device_id, sensor_data, camera_feed, last_executed_command_id } = req.body || {};
  if (sensor_data && typeof sensor_data === 'object') {
    systemState.telemetry = sensor_data;
    logs.push({ timestamp: new Date(), ...sensor_data });
    if (logs.length > 86400) logs.shift();
  }
  if (camera_feed) systemState.camera_feed = camera_feed;

  // if Pi acked a command id, mark it executed
  if (last_executed_command_id) {
    const c = persistedCommands.find(x => x.id === last_executed_command_id);
    if (c && c.status !== 'executed') {
      c.status = 'executed';
      c.executed_at = new Date().toISOString();
      safeWriteJson(COMMANDS_FILE, persistedCommands);
      // remove from queue
      systemState.command_queue = systemState.command_queue.filter(x => x.id !== last_executed_command_id);
    }
  }

  let response = { settings: systemState.settings };
  // send first queued command (but do not remove it — wait for Pi ack)
  if (systemState.command_queue.length > 0) {
    response.manual_command = systemState.command_queue[0];
  }

  res.json(response);
});

// Status endpoint used by frontend polling
app.get('/api/status', authenticate, (req, res) => {
  res.json({
    telemetry: systemState.telemetry || {},
    camera: systemState.camera_feed || null,
    settings: systemState.settings || {},
    pi_connected: !!(systemState.telemetry && Object.keys(systemState.telemetry).length)
  });
});

// Dashboard data (auth)
app.get('/api/dashboard', authenticate, (req, res) => {
  res.json({
    telemetry: systemState.telemetry,
    camera: systemState.camera_feed,
    settings: systemState.settings,
    logs_count: logs.length,
    commands: persistedCommands.slice(-20)
  });
});

// Create manual command (admin only). Returns the command object with id.
app.post('/api/command', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  if (systemState.settings.auto_mode) return res.status(400).json({ error: "Turn off Auto Mode first" });

  const body = req.body || {};
  const id = `cmd_${Date.now()}_${Math.floor(Math.random()*10000)}`;
  const cmdObj = {
    id,
    command: body,
    status: 'queued',
    created_at: new Date().toISOString(),
    executed_at: null
  };

  persistedCommands.push(cmdObj);
  safeWriteJson(COMMANDS_FILE, persistedCommands);

  // push to in-memory queue (for immediate delivery to Pi)
  systemState.command_queue.push(cmdObj);

  res.json({ message: "Command queued", command: cmdObj });
});

// Get command status
app.get('/api/command/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const cmd = persistedCommands.find(c => c.id === id);
  if (!cmd) return res.status(404).json({ error: "Command not found" });
  res.json(cmd);
});

// Settings (admin)
app.post('/api/settings', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const { auto_mode, thresholds } = req.body || {};
  if (auto_mode !== undefined) systemState.settings.auto_mode = !!auto_mode;
  if (thresholds && typeof thresholds === 'object') systemState.settings.thresholds = { ...systemState.settings.thresholds, ...thresholds };
  res.json({ message: "Settings updated", settings: systemState.settings });
});

// Export logs
app.get('/api/export', authenticate, (req, res) => {
  const type = req.query.type || 'standard';
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
      return log;
    }
  });

  const wb = xlsx.utils.book_new();
  const ws = xlsx.utils.json_to_sheet(data);
  xlsx.utils.book_append_sheet(wb, ws, "BioCube Logs");
  const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });

  res.setHeader('Content-Disposition', `attachment; filename="BioCube_${type}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

// Catch-all
app.use((req, res, next) => {
  if (req.path && req.path.startsWith('/api/')) return res.status(404).json({ error: 'API route not found' });
  next();
});

app.listen(PORT, () => console.log(`BioCube Server running on port ${PORT}`));
