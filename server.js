const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const upload = multer({ dest: 'uploads/' });

app.use(express.json());
app.use(express.static('public'));

// SQLite DB
const db = new sqlite3.Database('database.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    username TEXT UNIQUE,
    login TEXT UNIQUE,
    password TEXT,
    avatar TEXT,
    isAdmin INTEGER DEFAULT 0,
    subscription TEXT DEFAULT 'none'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    text TEXT,
    media TEXT,
    likes INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromId INTEGER,
    toId INTEGER,
    text TEXT,
    time DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // создаём админа admin/admin
  db.get(`SELECT * FROM users WHERE login = 'admin'`, (err, row) => {
    if (!row) {
      bcrypt.hash('admin', 10, (err, hash) => {
        db.run(`INSERT INTO users (name, username, login, password, isAdmin) VALUES (?,?,?,?,?)`,
          ['Admin', 'admin', 'admin', hash, 1]);
      });
    }
  });
});

// JWT
const SECRET = 'shift_super_secret_key_change_me';
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch { res.status(401).json({ error: 'invalid token' }); }
}

// Регистрация
app.post('/api/register', (req, res) => {
  const { name, username, login, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    db.run(`INSERT INTO users (name, username, login, password) VALUES (?,?,?,?)`,
      [name, username, login, hash], function(err) {
        if (err) return res.status(400).json({ error: 'login or username taken' });
        const token = jwt.sign({ id: this.lastID, login }, SECRET);
        res.json({ token });
      });
  });
});

// Логин
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], (err, user) => {
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ error: 'invalid credentials' });
      const token = jwt.sign({ id: user.id, login, isAdmin: user.isAdmin }, SECRET);
      res.json({ token, user: { id: user.id, name: user.name, username: user.username, isAdmin: user.isAdmin } });
    });
  });
});

// Лента
app.get('/api/feed', auth, (req, res) => {
  db.all(`SELECT p.*, u.name, u.username FROM posts p JOIN users u ON p.userId = u.id ORDER BY p.id DESC LIMIT 30`, (err, rows) => {
    res.json(rows);
  });
});

// Создать пост
app.post('/api/posts', auth, upload.single('media'), (req, res) => {
  let mediaUrl = req.file ? `/uploads/${req.file.filename}` : '';
  db.run(`INSERT INTO posts (userId, text, media) VALUES (?,?,?)`, [req.user.id, req.body.text, mediaUrl], function(err) {
    if (err) return res.status(500).json({ error: err });
    res.json({ id: this.lastID });
  });
});

// Контакты для чата
app.get('/api/contacts', auth, (req, res) => {
  db.all(`
    SELECT DISTINCT u.id, u.name, u.username FROM users u
    WHERE u.id IN (SELECT fromId FROM messages WHERE toId=?) OR u.id IN (SELECT toId FROM messages WHERE fromId=?)
  `, [req.user.id, req.user.id], (err, rows) => {
    res.json(rows);
  });
});

// История сообщений
app.get('/api/messages/:userId', auth, (req, res) => {
  db.all(`SELECT * FROM messages WHERE (fromId=? AND toId=?) OR (fromId=? AND toId=?) ORDER BY time`,
    [req.user.id, req.params.userId, req.params.userId, req.user.id], (err, rows) => {
      res.json(rows);
    });
});

// Socket.IO чаты
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('auth'));
  try {
    socket.user = jwt.verify(token, SECRET);
    next();
  } catch { next(new Error('auth')); }
});
io.on('connection', (socket) => {
  socket.join(`user_${socket.user.id}`);
  socket.on('private_message', (data) => {
    db.run(`INSERT INTO messages (fromId, toId, text) VALUES (?,?,?)`, [socket.user.id, data.to, data.text]);
    io.to(`user_${data.to}`).emit('private_message', { from: socket.user.id, text: data.text, time: new Date() });
  });
});

// Админка – поиск пользователей
app.get('/__admin__/users', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'forbidden' });
  const { q } = req.query;
  db.all(`SELECT id, name, username, subscription FROM users WHERE name LIKE ? OR username LIKE ?`, [`%${q}%`, `%${q}%`], (err, rows) => {
    res.json(rows);
  });
});

// Админка – выдать подписку
app.post('/__admin__/subscription', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403);
  const { userId, plan } = req.body;
  db.run(`UPDATE users SET subscription = ? WHERE id = ?`, [plan, userId]);
  res.json({ ok: true });
});

// Раздача статики
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

server.listen(5000, () => console.log('Shift server running on http://localhost:5000'));
