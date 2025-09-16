// server.js
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const DB_FILE = './database.db';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'info@battagliaracingcar.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Prova1234!';

// open database (create if not exists)
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('SQLite error:', err.message);
    process.exit(1);
  }
  console.log('SQLite DB opened:', DB_FILE);
});

// initialize schema and default admin
function ensureSchemaAndAdmin() {
  db.serialize(() => {
    // users
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      role TEXT DEFAULT 'tech',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`);

    // vehicles
    db.run(`CREATE TABLE IF NOT EXISTS vehicles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      chassis_number TEXT,
      plate TEXT,
      engine_serial TEXT,
      km_or_hours INTEGER DEFAULT 0,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`);

    // maintenances
    db.run(`CREATE TABLE IF NOT EXISTS maintenances (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vehicle_id INTEGER,
      type TEXT,
      date TEXT,
      km_or_hours INTEGER,
      cost REAL,
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
    );`);

    // create admin if not exists
    db.get('SELECT id FROM users WHERE email = ?', [ADMIN_EMAIL], async (err, row) => {
      if (err) return console.error('DB error', err.message);
      if (!row) {
        const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
        db.run('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)',
          ['Admin', ADMIN_EMAIL, hash, 'admin'], function (err2) {
            if (err2) console.error('Error creating admin', err2.message);
            else console.log('Admin created:', ADMIN_EMAIL);
          });
      } else {
        console.log('Admin already exists:', ADMIN_EMAIL);
      }
    });
  });
}
ensureSchemaAndAdmin();


// --- AUTH ROUTES ---
app.post('/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email e password richieste' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)', [name || '', email, hash, role || 'tech'], function (err) {
      if (err) {
        if (err.message && err.message.includes('UNIQUE')) {
          return res.status(400).json({ message: 'Email già registrata' });
        }
        console.error(err);
        return res.status(500).json({ message: 'Errore registrazione' });
      }
      res.json({ message: 'Utente creato', userId: this.lastID });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Errore server' });
  }
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email e password richieste' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ message: 'Errore DB' });
    if (!row) return res.status(400).json({ message: 'Utente non trovato' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(400).json({ message: 'Password errata' });
    const token = jwt.sign({ id: row.id, email: row.email, role: row.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ message: 'Login effettuato', token, user: { id: row.id, name: row.name, email: row.email, role: row.role } });
  });
});

// middleware autenticazione
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ message: 'No token' });
  const token = h.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Token invalido' });
  }
}

// --- API: vehicles ---
app.get('/api/vehicles', authMiddleware, (req, res) => {
  db.all('SELECT * FROM vehicles ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    res.json(rows);
  });
});

app.post('/api/vehicles', authMiddleware, (req, res) => {
  const { name, chassis_number, plate, engine_serial, km_or_hours, notes } = req.body;
  db.run('INSERT INTO vehicles (name,chassis_number,plate,engine_serial,km_or_hours,notes) VALUES (?,?,?,?,?,?)',
    [name, chassis_number, plate, engine_serial, km_or_hours || 0, notes], function (err) {
      if (err) return res.status(500).json({ message: 'DB error' });
      db.get('SELECT * FROM vehicles WHERE id = ?', [this.lastID], (e, row) => {
        if (e) return res.status(500).json({ message: 'DB error' });
        res.json(row);
      });
    });
});

// --- API: maintenances ---
app.get('/api/maintenances', authMiddleware, (req, res) => {
  const sql = `SELECT m.*, v.name as vehicle_name FROM maintenances m LEFT JOIN vehicles v ON v.id = m.vehicle_id ORDER BY m.date DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    res.json(rows);
  });
});

app.post('/api/maintenances', authMiddleware, (req, res) => {
  const { vehicle_id, type, date, km_or_hours, cost, notes } = req.body;
  db.run('INSERT INTO maintenances (vehicle_id,type,date,km_or_hours,cost,notes) VALUES (?,?,?,?,?,?)',
    [vehicle_id, type, date, km_or_hours || 0, cost || 0, notes], function (err) {
      if (err) return res.status(500).json({ message: 'DB error' });
      db.get('SELECT m.*, v.name as vehicle_name FROM maintenances m LEFT JOIN vehicles v ON v.id = m.vehicle_id WHERE m.id = ?', [this.lastID], (e, row) => {
        if (e) return res.status(500).json({ message: 'DB error' });
        res.json(row);
      });
    });
});

// simple health
app.get('/', (req, res) => res.send('Backend OK'));

// start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Server listening on', PORT));
