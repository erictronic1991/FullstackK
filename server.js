const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your-secret-key-please-change-this';

app.use(cors());
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database('./todo-auth.db', (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Connected to SQLite database.');
});

// Create users and tasks tables if they don't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      text TEXT,
      user_id INTEGER,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });

    req.user = user;
    next();
  });
}

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password are required' });

  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(sql, [username, hashedPassword], function(err) {
    if (err) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password are required' });

  const sql = `SELECT * FROM users WHERE username = ?`;
  db.get(sql, [username], async (err, user) => {
    if (err) throw err;
    if (!user) return res.status(400).json({ message: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Invalid password' });

    // Generate JWT
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
      expiresIn: '1h',
    });
    res.json({ token });
  });
});

// Get tasks for logged-in user
app.get('/tasks', authenticateToken, (req, res) => {
  const sql = 'SELECT id, text FROM tasks WHERE user_id = ?';
  db.all(sql, [req.user.id], (err, rows) => {
    if (err) {
      return res.status(500).json({ message: err.message });
    }
    res.json(rows);
  });
});

// Add new task for logged-in user
app.post('/tasks', authenticateToken, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: 'Task text is required' });

  const sql = 'INSERT INTO tasks (text, user_id) VALUES (?, ?)';
  db.run(sql, [text, req.user.id], function(err) {
    if (err) {
      return res.status(500).json({ message: err.message });
    }
    res.status(201).json({ id: this.lastID, text });
  });
});

// Start server
app.get('/', (req, res) => {
    res.send('Welcome to the backend server');
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
