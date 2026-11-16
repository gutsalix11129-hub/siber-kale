require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { z } = require('zod');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL tanımlı değil. Neon bağlantı dizesini Render ortam değişkenlerine ekle.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 10
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('public','private')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS room_members (
      room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','moderator','member')),
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(room_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS room_messages (
      id SERIAL PRIMARY KEY,
      room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS room_invites (
      id SERIAL PRIMARY KEY,
      room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      code TEXT NOT NULL UNIQUE,
      created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ,
      max_uses INTEGER,
      uses INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"]
    }
  }
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  store: new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz');
  next();
}

const registerSchema = z.object({
  email: z.string().email().max(254).transform(v => v.toLowerCase()),
  password: z.string().min(10).max(200)
});

const postSchema = z.object({
  title: z.string().min(5).max(120),
  body: z.string().min(20).max(10000)
});

const roomSchema = z.object({
  name: z.string().min(3).max(80),
  slug: z.string().min(3).max(40).regex(/^[a-z0-9-]+$/),
  description: z.string().max(500).default(''),
  visibility: z.enum(['public', 'private'])
});

async function getRoomMembership(roomId, userId) {
  if (!userId) return null;
  const { rows } = await pool.query(
    'SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2',
    [roomId, userId]
  );
  return rows[0] || null;
}

async function requireRoomAccess(req, res, next) {
  try {
    const { rows } = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.id]);
    const room = rows[0];
    if (!room) return res.status(404).send('Oda bulunamadı.');

    const membership = await getRoomMembership(room.id, req.session.user?.id);
    if (room.visibility === 'private' && !membership) {
      return res.status(403).send('Bu oda davet ile katılınabilir.');
    }

    req.room = room;
    req.roomMembership = membership;
    next();
  } catch (err) {
    next(err);
  }
}

app.get('/', async (req, res, next) => {
  try {
    const { rows: posts } = await pool.query(`
      SELECT p.*, u.email
      FROM posts p
      JOIN users u ON u.id = p.user_id
      WHERE p.status = 'approved'
      ORDER BY p.created_at DESC
      LIMIT 100
    `);
    res.render('index', { title: 'Onaylı Paylaşımlar', posts });
  } catch (err) {
    next(err);
  }
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Kayıt' });
});

app.post('/register', authLimiter, async (req, res, next) => {
  try {
    const data = registerSchema.parse(req.body);
    const hash = await bcrypt.hash(data.password, 12);

    await pool.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)',
      [data.email, hash, 'user']
    );

    res.redirect('/login');
  } catch (err) {
    if (err?.code === '23505') return res.status(400).send('Bu e-posta zaten kayıtlı.');
    if (err?.name === 'ZodError') return res.status(400).send('Geçersiz kayıt: ' + err.issues[0].message);
    next(err);
  }
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Giriş' });
});

app.post('/login', authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').toLowerCase();
    const password = String(req.body.password || '');

    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) return res.status(400).send('E-posta veya şifre hatalı.');

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).send('E-posta veya şifre hatalı.');

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: user.id, email: user.email, role: user.role };
      res.redirect('/');
    });
  } catch (err) {
    next(err);
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/posts/new', requireAuth, (req, res) => {
  res.render('new-post', { title: 'Yeni Paylaşım' });
});

app.post('/posts/new', requireAuth, async (req, res, next) => {
  try {
    const data = postSchema.parse(req.body);
    await pool.query(
      'INSERT INTO posts (user_id, title, body, status) VALUES ($1, $2, $3, $4)',
      [req.session.user.id, data.title, data.body, 'pending']
    );
    res.send('Paylaşım moderasyon için gönderildi. Onaylandıktan sonra yayınlanır.');
  } catch (err) {
    if (err?.name === 'ZodError') return res.status(400).send('Geçersiz paylaşım: ' + err.issues[0].message);
    next(err);
  }
});

app.post('/posts/:id/report', requireAuth, async (req, res, next) => {
  try {
    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (reason.length < 3) return res.status(400).send('Şikayet nedeni gerekli.');

    const { rows } = await pool.query(
      "SELECT id FROM posts WHERE id = $1 AND status = 'approved'",
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).send('Paylaşım bulunamadı.');

    await pool.query(
      'INSERT INTO reports (post_id, user_id, reason) VALUES ($1, $2, $3)',
      [rows[0].id, req.session.user.id, reason]
    );
    res.redirect('/');
  } catch (err) {
    if (err?.code === '23505') return res.status(400).send('Bu paylaşımı zaten şikayet ettiniz.');
    next(err);
  }
});

app.get('/admin', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const { rows: pending } = await pool.query(`
      SELECT p.*, u.email
      FROM posts p
      JOIN users u ON u.id = p.user_id
      WHERE p.status = 'pending'
      ORDER BY p.created_at ASC
    `);

    const { rows: reports } = await pool.query(`
      SELECT r.*, p.title
      FROM reports r
      JOIN posts p ON p.id = r.post_id
      ORDER BY r.created_at DESC
      LIMIT 100
    `);

    res.render('admin', { title: 'Moderasyon', pending, reports });
  } catch (err) {
    next(err);
  }
});

app.post('/admin/posts/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  await pool.query("UPDATE posts SET status = 'approved' WHERE id = $1", [req.params.id]);
  res.redirect('/admin');
});

app.post('/admin/posts/:id/reject', requireAuth, requireAdmin, async (req, res) => {
  await pool.query("UPDATE posts SET status = 'rejected' WHERE id = $1", [req.params.id]);
  res.redirect('/admin');
});

app.get('/rooms', requireAuth, async (req, res, next) => {
  try {
    const { rows: myRooms } = await pool.query(`
      SELECT r.* FROM rooms r
      JOIN room_members m ON m.room_id = r.id
      WHERE m.user_id = $1
      ORDER BY r.created_at DESC
    `, [req.session.user.id]);

    const { rows: publicRooms } = await pool.query(`
      SELECT r.* FROM rooms r
      WHERE r.visibility = 'public'
        AND r.id NOT IN (SELECT room_id FROM room_members WHERE user_id = $1)
      ORDER BY r.created_at DESC
      LIMIT 50
    `, [req.session.user.id]);

    res.render('rooms', { title: 'Odalar', myRooms, publicRooms });
  } catch (err) {
    next(err);
  }
});

app.get('/rooms/new', requireAuth, (req, res) => {
  res.render('new-room', { title: 'Yeni Oda' });
});

app.post('/rooms', requireAuth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const data = roomSchema.parse(req.body);
    await client.query('BEGIN');

    const { rows } = await client.query(
      'INSERT INTO rooms (owner_id, name, slug, description, visibility) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [req.session.user.id, data.name, data.slug, data.description, data.visibility]
    );

    await client.query(
      "INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'owner')",
      [rows[0].id, req.session.user.id]
    );

    await client.query('COMMIT');
    res.redirect('/rooms/' + rows[0].id);
  } catch (err) {
    await client.query('ROLLBACK');
    if (err?.code === '23505') return res.status(400).send('Bu slug zaten kullanılıyor.');
    if (err?.name === 'ZodError') return res.status(400).send('Geçersiz oda: ' + err.issues[0].message);
    next(err);
  } finally {
    client.release();
  }
});

app.get('/rooms/:id', requireAuth, requireRoomAccess, async (req, res, next) => {
  try {
    const { rows: messages } = await pool.query(`
      SELECT m.*, u.email FROM room_messages m
      JOIN users u ON u.id = m.user_id
      WHERE m.room_id = $1
      ORDER BY m.created_at ASC
      LIMIT 500
    `, [req.room.id]);

    res.render('room', {
      title: req.room.name,
      room: req.room,
      messages,
      isMember: !!req.roomMembership,
      inviteCode: req.query.invite || null
    });
  } catch (err) {
    next(err);
  }
});

app.post('/rooms/:id/messages', requireAuth, requireRoomAccess, async (req, res) => {
  if (!req.roomMembership) return res.status(403).send('Odaya üye değilsiniz.');
  const body = String(req.body.body || '').trim();
  if (body.length < 1 || body.length > 2000) return res.status(400).send('Mesaj 1-2000 karakter olmalı.');

  await pool.query(
    'INSERT INTO room_messages (room_id, user_id, body) VALUES ($1, $2, $3)',
    [req.room.id, req.session.user.id, body]
  );
  res.redirect('/rooms/' + req.room.id);
});

app.post('/rooms/:id/join', requireAuth, requireRoomAccess, async (req, res) => {
  if (req.room.visibility !== 'public') return res.status(400).send('Bu oda davet ile katılınabilir.');
  await pool.query(
    "INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING",
    [req.room.id, req.session.user.id]
  );
  res.redirect('/rooms/' + req.room.id);
});

app.post('/rooms/:id/invite', requireAuth, requireRoomAccess, async (req, res) => {
  const m = req.roomMembership;
  if (!m || (m.role !== 'owner' && m.role !== 'moderator')) {
    return res.status(403).send('Yetkisiz.');
  }

  const code = crypto.randomBytes(16).toString('base64url');
  await pool.query(
    'INSERT INTO room_invites (room_id, code, created_by) VALUES ($1, $2, $3)',
    [req.room.id, code, req.session.user.id]
  );
  res.redirect('/rooms/' + req.room.id + '?invite=' + code);
});

app.get('/join/:code', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM room_invites WHERE code = $1', [req.params.code]);
    const inv = rows[0];
    if (!inv) return res.status(404).send('Davet geçersiz.');
    if (inv.expires_at && new Date(inv.expires_at) < new Date()) return res.status(400).send('Davet süresi dolmuş.');
    if (inv.max_uses && inv.uses >= inv.max_uses) return res.status(400).send('Davet kullanım limiti aşılmış.');

    const membership = await getRoomMembership(inv.room_id, req.session.user.id);
    if (!membership) {
      await pool.query('BEGIN');
      try {
        await pool.query(
          "INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'member')",
          [inv.room_id, req.session.user.id]
        );
        await pool.query('UPDATE room_invites SET uses = uses + 1 WHERE id = $1', [inv.id]);
        await pool.query('COMMIT');
      } catch (e) {
        await pool.query('ROLLBACK');
        throw e;
      }
    }
    res.redirect('/rooms/' + inv.room_id);
  } catch (err) {
    next(err);
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).send('Sayfa bulunamadı.'));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(isProd ? 'Sunucu hatası.' : String(err));
});

async function seedAdmin() {
  const email = process.env.ADMIN_EMAIL?.toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;

  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (rows[0]) return;

  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin')",
    [email, hash]
  );
  console.log('Admin oluşturuldu:', email);
}

initDb()
  .then(seedAdmin)
  .then(() => {
    app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Başlatma hatası:', err);
    process.exit(1);
  });