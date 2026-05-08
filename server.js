const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const cloudinary = require('cloudinary').v2;

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json());
app.use(express.static('public'));

// Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ----- БАЗА ДАННЫХ -----
const db = new sqlite3.Database('database.sqlite');
db.serialize(() => {
  // Пользователи
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, username TEXT UNIQUE, login TEXT UNIQUE,
    password TEXT, avatar TEXT, isAdmin INTEGER DEFAULT 0,
    isVerified INTEGER DEFAULT 0,
    isBanned INTEGER DEFAULT 0,
    banReason TEXT,
    subscription TEXT DEFAULT 'none',
    subscriptionExpires DATETIME,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Посты
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER, text TEXT, media TEXT,
    likes TEXT DEFAULT '[]'
  )`);
  // Личные сообщения
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromId INTEGER, toId INTEGER, text TEXT, time DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Группы
  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, avatar TEXT, type TEXT DEFAULT 'open',
    ownerId INTEGER, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    groupId INTEGER, userId INTEGER, role TEXT DEFAULT 'member',
    PRIMARY KEY (groupId, userId)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    groupId INTEGER, userId INTEGER, text TEXT, media TEXT, time DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS group_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    groupId INTEGER, userId INTEGER, status TEXT DEFAULT 'pending',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Заявки на верификацию
  db.run(`CREATE TABLE IF NOT EXISTS verification_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER, reason TEXT, videoUrl TEXT, status TEXT DEFAULT 'pending',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Заявки в поддержку
  db.run(`CREATE TABLE IF NOT EXISTS support_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER, subject TEXT, message TEXT, files TEXT, status TEXT DEFAULT 'pending',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // Логи админов
  db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adminId INTEGER, action TEXT, targetId INTEGER, details TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Создать админа по умолчанию, если нет
  db.get(`SELECT * FROM users WHERE login = 'admin'`, (err, row) => {
    if (!row) {
      bcrypt.hash('admin', 10, (err, hash) => {
        db.run(`INSERT INTO users (name, username, login, password, isAdmin) VALUES (?,?,?,?,?)`,
          ['Admin', 'admin', 'admin', hash, 1]);
      });
    }
  });
});

// ----- JWT -----
const SECRET = process.env.JWT_SECRET || 'shift_super_secret_change_in_production';
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch { res.status(401).json({ error: 'invalid token' }); }
}

// ----- Регистрация / логин / профиль -----
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

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], (err, user) => {
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    if (user.isBanned) return res.status(403).json({ error: 'Account banned: ' + user.banReason });
    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ error: 'invalid credentials' });
      const token = jwt.sign({ id: user.id, login, isAdmin: user.isAdmin }, SECRET);
      res.json({ token, user: { id: user.id, name: user.name, username: user.username, isAdmin: user.isAdmin, avatar: user.avatar, isVerified: user.isVerified } });
    });
  });
});

app.get('/api/me', auth, (req, res) => {
  db.get(`SELECT id, name, username, avatar, isAdmin, isVerified FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: err });
    res.json(user);
  });
});

// ----- Лента, посты, лайки -----
app.get('/api/feed', auth, (req, res) => {
  db.all(`SELECT p.*, u.name, u.username, u.avatar FROM posts p JOIN users u ON p.userId = u.id ORDER BY p.id DESC LIMIT 50`, (err, rows) => {
    if (err) return res.status(500).json({ error: err });
    rows.forEach(p => { p.likes = JSON.parse(p.likes || '[]'); });
    res.json(rows);
  });
});

app.post('/api/posts', auth, upload.single('media'), async (req, res) => {
  try {
    let mediaUrl = '';
    if (req.file) {
      const b64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
      const uploadRes = await cloudinary.uploader.upload(b64, { folder: 'shift_posts' });
      mediaUrl = uploadRes.secure_url;
    }
    db.run(`INSERT INTO posts (userId, text, media) VALUES (?,?,?)`,
      [req.user.id, req.body.text, mediaUrl],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, mediaUrl });
      });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;
  db.get(`SELECT likes FROM posts WHERE id = ?`, [postId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'post not found' });
    let likes = JSON.parse(row.likes || '[]');
    const index = likes.indexOf(userId);
    if (index === -1) likes.push(userId);
    else likes.splice(index, 1);
    db.run(`UPDATE posts SET likes = ? WHERE id = ?`, [JSON.stringify(likes), postId], (err) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ likes: likes.length, liked: index === -1 });
    });
  });
});

// ----- Личные сообщения -----
app.get('/api/contacts', auth, (req, res) => {
  db.all(`
    SELECT DISTINCT u.id, u.name, u.username, u.avatar FROM users u
    WHERE u.id IN (SELECT fromId FROM messages WHERE toId=?)
       OR u.id IN (SELECT toId FROM messages WHERE fromId=?)
  `, [req.user.id, req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.get('/api/messages/:userId', auth, (req, res) => {
  db.all(`SELECT * FROM messages WHERE (fromId=? AND toId=?) OR (fromId=? AND toId=?) ORDER BY time`,
    [req.user.id, req.params.userId, req.params.userId, req.user.id], (err, rows) => {
      res.json(rows);
    });
});

// ----- Группы -----
app.get('/api/groups', auth, (req, res) => {
  db.all(`
    SELECT g.*, gm.role FROM groups g
    JOIN group_members gm ON g.id = gm.groupId
    WHERE gm.userId = ?
  `, [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/groups', auth, upload.single('avatar'), async (req, res) => {
  try {
    let avatarUrl = '';
    if (req.file) {
      const b64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
      const uploadRes = await cloudinary.uploader.upload(b64, { folder: 'group_avatars' });
      avatarUrl = uploadRes.secure_url;
    }
    const { name, type } = req.body;
    db.run(`INSERT INTO groups (name, avatar, type, ownerId) VALUES (?,?,?,?)`,
      [name, avatarUrl, type || 'open', req.user.id],
      function(err) {
        if (err) return res.status(500).json({ error: err });
        const groupId = this.lastID;
        db.run(`INSERT INTO group_members (groupId, userId, role) VALUES (?,?,?)`, [groupId, req.user.id, 'admin']);
        res.json({ id: groupId, name, avatar: avatarUrl });
      });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/groups/:id/messages', auth, (req, res) => {
  db.all(`
    SELECT gm.*, u.name, u.username, u.avatar FROM group_messages gm
    JOIN users u ON gm.userId = u.id
    WHERE gm.groupId = ? ORDER BY gm.time ASC
  `, [req.params.id], (err, rows) => {
    res.json(rows);
  });
});

// ----- SOCKET.IO -----
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
    const { to, text } = data;
    db.run(`INSERT INTO messages (fromId, toId, text) VALUES (?,?,?)`, [socket.user.id, to, text]);
    io.to(`user_${to}`).emit('private_message', { from: socket.user.id, text, time: new Date() });
  });
  socket.on('join_group', (groupId) => socket.join(`group_${groupId}`));
  socket.on('group_message', (data) => {
    const { groupId, text } = data;
    db.run(`INSERT INTO group_messages (groupId, userId, text) VALUES (?,?,?)`, [groupId, socket.user.id, text]);
    io.to(`group_${groupId}`).emit('group_message', { userId: socket.user.id, text, time: new Date(), name: socket.user.name });
  });
});

// ========== ПОЛНАЯ АДМИН-ПАНЕЛЬ (скрытая) ==========
const adminAuth = async (req, res, next) => {
  const user = await new Promise((resolve) => {
    db.get(`SELECT isAdmin FROM users WHERE id = ?`, [req.user.id], (err, row) => resolve(row));
  });
  if (!user || !user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// 1. Поиск пользователя (по имени, username, логину) с похожими
app.get('/__admin__/users', auth, adminAuth, (req, res) => {
  const { q } = req.query;
  db.all(`
    SELECT id, name, username, login, subscription, isVerified, isBanned, createdAt 
    FROM users 
    WHERE name LIKE ? OR username LIKE ? OR login LIKE ?
    LIMIT 30
  `, [`%${q}%`, `%${q}%`, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: err });
    res.json(rows);
  });
});

// 2. Выдача подписки (на время или навсегда)
app.post('/__admin__/subscription', auth, adminAuth, (req, res) => {
  const { userId, plan, durationDays } = req.body;
  let expires = null;
  if (durationDays && durationDays > 0) {
    expires = new Date(Date.now() + durationDays * 86400000).toISOString();
  }
  db.run(`UPDATE users SET subscription = ?, subscriptionExpires = ? WHERE id = ?`, [plan, expires, userId], (err) => {
    if (err) return res.status(500).json({ error: err });
    // Логируем действие
    db.run(`INSERT INTO admin_logs (adminId, action, targetId, details) VALUES (?,?,?,?)`,
      [req.user.id, 'subscription', userId, `plan:${plan}, days:${durationDays || 'forever'}`]);
    res.json({ ok: true });
  });
});

// 3. Блокировка / разблокировка (наблюдатель или бан)
app.post('/__admin__/ban', auth, adminAuth, (req, res) => {
  const { userId, banType, durationHours, reason } = req.body; // banType: 'observer' или 'full'
  let banFlag = 1;
  let banReason = reason || (banType === 'observer' ? 'Наблюдатель (только чтение)' : 'Полная блокировка');
  db.run(`UPDATE users SET isBanned = ?, banReason = ? WHERE id = ?`, [banFlag, banReason, userId], (err) => {
    if (err) return res.status(500).json({ error: err });
    // Кикнуть через socket, если пользователь онлайн
    const sockets = [...io.sockets.sockets.values()];
    for (const s of sockets) {
      if (s.user && s.user.id === userId) {
        s.disconnect(true);
      }
    }
    db.run(`INSERT INTO admin_logs (adminId, action, targetId, details) VALUES (?,?,?,?)`,
      [req.user.id, 'ban', userId, `${banType}: ${reason}`]);
    res.json({ ok: true });
  });
});

// 4. Разблокировка
app.post('/__admin__/unban', auth, adminAuth, (req, res) => {
  const { userId } = req.body;
  db.run(`UPDATE users SET isBanned = 0, banReason = NULL WHERE id = ?`, [userId], (err) => {
    if (err) return res.status(500).json({ error: err });
    db.run(`INSERT INTO admin_logs (adminId, action, targetId, details) VALUES (?,?,?,?)`,
      [req.user.id, 'unban', userId, '']);
    res.json({ ok: true });
  });
});

// 5. Кик с сервера (разрыв соединения)
app.post('/__admin__/kick', auth, adminAuth, (req, res) => {
  const { userId } = req.body;
  const sockets = [...io.sockets.sockets.values()];
  let kicked = false;
  for (const s of sockets) {
    if (s.user && s.user.id === userId) {
      s.disconnect(true);
      kicked = true;
    }
  }
  db.run(`INSERT INTO admin_logs (adminId, action, targetId, details) VALUES (?,?,?,?)`,
    [req.user.id, 'kick', userId, kicked ? 'success' : 'offline']);
  res.json({ kicked });
});

// 6. Выдача верификации (галочка)
app.post('/__admin__/verify', auth, adminAuth, (req, res) => {
  const { userId } = req.body;
  db.run(`UPDATE users SET isVerified = 1 WHERE id = ?`, [userId], (err) => {
    if (err) return res.status(500).json({ error: err });
    db.run(`UPDATE verification_requests SET status = 'approved' WHERE userId = ? AND status = 'pending'`, [userId]);
    db.run(`INSERT INTO admin_logs (adminId, action, targetId, details) VALUES (?,?,?,?)`,
      [req.user.id, 'verify', userId, 'verified']);
    res.json({ ok: true });
  });
});

// 7. Просмотр заявок на верификацию (админ)
app.get('/__admin__/verification-requests', auth, adminAuth, (req, res) => {
  db.all(`
    SELECT vr.*, u.name, u.username, u.login FROM verification_requests vr
    JOIN users u ON vr.userId = u.id
    WHERE vr.status = 'pending' ORDER BY vr.createdAt DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: err });
    res.json(rows);
  });
});

// 8. Просмотр заявок в службу поддержки
app.get('/__admin__/support-requests', auth, adminAuth, (req, res) => {
  db.all(`
    SELECT sr.*, u.name, u.username FROM support_requests sr
    JOIN users u ON sr.userId = u.id
    ORDER BY sr.createdAt DESC
  `, (err, rows) => {
    res.json(rows);
  });
});

// 9. Общая статистика
app.get('/__admin__/stats', auth, adminAuth, async (req, res) => {
  const totalUsers = await new Promise((resolve) => db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => resolve(row?.c || 0)));
  const online = io.sockets.sockets.size;
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const messagesToday = await new Promise((resolve) => db.get(`SELECT COUNT(*) as c FROM messages WHERE time >= ?`, [todayStart.toISOString()], (err, row) => resolve(row?.c || 0)));
  const totalUploadsMB = await new Promise((resolve) => db.get(`SELECT SUM(LENGTH(media)) as s FROM posts WHERE media != ''`, (err, row) => resolve(Math.round((row?.s || 0) / 1024 / 1024))));
  const serverLoad = process.cpuUsage ? process.cpuUsage().user / 1000000 : 0;
  res.json({
    totalUsers,
    online,
    messagesToday,
    uploadsMB: totalUploadsMB,
    serverLoad: serverLoad.toFixed(2)
  });
});

// 10. Создать заявку в поддержку (для пользователей)
app.post('/api/support', auth, (req, res) => {
  const { subject, message, files } = req.body;
  db.run(`INSERT INTO support_requests (userId, subject, message, files) VALUES (?,?,?,?)`,
    [req.user.id, subject, message, files || ''], (err) => {
      if (err) return res.status(500).json({ error: err });
      res.json({ ok: true });
    });
});

// 11. Запрос на верификацию от пользователя (с проверкой >1% подписчиков)
app.post('/api/verify-request', auth, async (req, res) => {
  const { reason, videoBase64 } = req.body;
  const userId = req.user.id;
  // Подсчет общего числа пользователей и подписчиков
  const totalUsers = await new Promise((resolve) => db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => resolve(row?.c || 1)));
  const subscribers = await new Promise((resolve) => db.get(`SELECT COUNT(*) as c FROM follows WHERE followedId = ?`, [userId], (err, row) => resolve(row?.c || 0)));
  const percent = (subscribers / totalUsers) * 100;
  if (percent < 1) {
    return res.status(403).json({ error: `Нужно >1% подписчиков от всех пользователей. Сейчас ${percent.toFixed(2)}%` });
  }
  let videoUrl = '';
  if (videoBase64) {
    try {
      const uploadRes = await cloudinary.uploader.upload(videoBase64, { resource_type: 'video', folder: 'verification_videos' });
      videoUrl = uploadRes.secure_url;
    } catch(e) { console.error(e); }
  }
  db.run(`INSERT INTO verification_requests (userId, reason, videoUrl) VALUES (?,?,?)`, [userId, reason, videoUrl], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ ok: true });
  });
});

// ---- Подписки (follow) для процента верификации ----
app.post('/api/follow/:id', auth, (req, res) => {
  const targetId = req.params.id;
  if (targetId == req.user.id) return res.status(400).json({ error: 'Нельзя подписаться на себя' });
  db.run(`INSERT OR IGNORE INTO follows (followerId, followedId) VALUES (?,?)`, [req.user.id, targetId], (err) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ ok: true });
  });
});

// Статика и SPA
app.use(express.static('public'));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Shift server on port ${PORT}`));
