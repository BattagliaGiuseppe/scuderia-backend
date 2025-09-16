const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const DB_PATH = process.env.DB_PATH || "./db/scuderia.db";
const JWT_SECRET = process.env.JWT_SECRET || "secret";

const db = new sqlite3.Database(DB_PATH);

// --- Setup database tables if not exist ---
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS vehicles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model TEXT,
    chassis TEXT,
    plate TEXT,
    race_number TEXT,
    year INTEGER,
    status TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    model TEXT,
    serial TEXT UNIQUE,
    vehicle_id INTEGER,
    status TEXT,
    FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS maintenances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER,
    component_id INTEGER,
    type TEXT,
    date TEXT,
    km INTEGER,
    cost REAL,
    notes TEXT,
    FOREIGN KEY(vehicle_id) REFERENCES vehicles(id),
    FOREIGN KEY(component_id) REFERENCES components(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS expiring_parts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER,
    part_name TEXT,
    expiration_date TEXT,
    alert INTEGER,
    FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
  )`);
});

// --- Auth routes ---
app.post("/api/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users(username, password, role) VALUES(?,?,?)`, [username, hash, role], function(err){
    if(err) return res.status(400).json({ error: err.message });
    res.json({ id: this.lastID, username, role });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if(err || !user) return res.status(400).json({ error: "Utente non trovato" });
    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.status(401).json({ error: "Password errata" });
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ token, username: user.username, role: user.role });
  });
});

// --- CRUD veicoli ---
app.get("/api/vehicles", (req, res) => {
  db.all(`SELECT * FROM vehicles`, [], (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/api/vehicles", (req, res) => {
  const { model, chassis, plate, race_number, year, status } = req.body;
  db.run(`INSERT INTO vehicles(model,chassis,plate,race_number,year,status) VALUES(?,?,?,?,?,?)`,
    [model, chassis, plate, race_number, year, status], function(err){
      if(err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// --- CRUD componenti ---
app.get("/api/components", (req, res) => {
  db.all(`SELECT * FROM components`, [], (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/api/components", (req, res) => {
  const { type, model, serial, vehicle_id, status } = req.body;
  db.run(`INSERT INTO components(type,model,serial,vehicle_id,status) VALUES(?,?,?,?,?)`,
    [type, model, serial, vehicle_id, status], function(err){
      if(err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// --- CRUD manutenzioni ---
app.get("/api/maintenances", (req,res) => {
  db.all(`SELECT * FROM maintenances`, [], (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/api/maintenances", (req,res) => {
  const { vehicle_id, component_id, type, date, km, cost, notes } = req.body;
  db.run(`INSERT INTO maintenances(vehicle_id,component_id,type,date,km,cost,notes) VALUES(?,?,?,?,?,?,?)`,
    [vehicle_id, component_id, type, date, km, cost, notes], function(err){
      if(err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// --- Parti a scadenza ---
app.get("/api/expiring_parts", (req,res) => {
  db.all(`SELECT * FROM expiring_parts`, [], (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/api/expiring_parts", (req,res) => {
  const { vehicle_id, part_name, expiration_date, alert } = req.body;
  db.run(`INSERT INTO expiring_parts(vehicle_id,part_name,expiration_date,alert) VALUES(?,?,?,?)`,
    [vehicle_id, part_name, expiration_date, alert], function(err){
      if(err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));



