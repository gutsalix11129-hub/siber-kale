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
    CREATE TABLE IF NOT EXISTS post_likes (
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(post_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS post_comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
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

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"] } } }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

app.use((req, res, next) => { res.locals.user = req.session.user || null; next(); });

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz'); next(); }

// ANA SAYFA (Beğeni ve Yorumlarla Birlikte)
app.get('/', async (req, res, next) => {
  try {
    const { rows: posts } = await pool.query(`
      SELECT p.*, u.email,
      (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as like_count,
      (SELECT COUNT(*) FROM post_comments pc WHERE pc.post_id = p.id) as comment_count
      FROM posts p JOIN users u ON u.id = p.user_id
      WHERE p.status = 'approved' ORDER BY p.created_at DESC LIMIT 100
    `);

    for (let post of posts) {
      const likes = await pool.query('SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2', [post.id, req.session.user?.id]);
      post.has_liked = likes.rows.length > 0;
      const comments = await pool.query(`
        SELECT c.*, u.email FROM post_comments c 
        JOIN users u ON u.id = c.user_id WHERE c.post_id = $1 ORDER BY c.created_at ASC
      `, [post.id]);
      post.comments = comments.rows;
    }
    res.render('index', { title: 'Siber Akış', posts });
  } catch (err) { next(err); }
});

// BEĞENİ ROTASI
app.post('/posts/:id/like', requireAuth, async (req, res) => {
  const check = await pool.query('SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  if (check.rows.length > 0) {
    await pool.query('DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  } else {
    await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1, $2)', [req.params.id, req.session.user.id]);
  }
  res.redirect('/');
});

// YORUM ROTASI
app.post('/posts/:id/comment', requireAuth, async (req, res) => {
  const body = String(req.body.body || '').trim();
  if (body.length > 0) {
    await pool.query('INSERT INTO post_comments (post_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, body]);
  }
  res.redirect('/');
});

// KAYIT & GİRİŞ
app.get('/register', (req, res) => res.render('register', { title: 'Kayıt' }));
app.post('/register', async (req, res, next) => {
  try {
    const email = req.body.email.toLowerCase();
    const hash = await bcrypt.hash(req.body.password, 12);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hash]);
    res.redirect('/login');
  } catch (err) { res.status(400).send('Bu e-posta zaten kayıtlı olabilir veya şifre kısa.'); }
});

app.get('/login', (req, res) => res.render('login', { title: 'Giriş' }));
app.post('/login', async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email.toLowerCase()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) return res.status(400).send('Hatalı giriş.');
    req.session.regenerate((err) => {
      req.session.user = { id: user.id, email: user.email, role: user.role };
      res.redirect('/');
    });
  } catch (err) { next(err); }
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// DİĞER ROTALAR (Paylaşım, Admin, Odalar - Önceki kodla aynı)
app.get('/posts/new', requireAuth, (req, res) => res.render('new-post', { title: 'Yeni Paylaşım' }));
app.post('/posts/new', requireAuth, async (req, res) => {
  if(req.body.title.length < 5 || req.body.body.length < 20) return res.send("Çok kısa!");
  await pool.query('INSERT INTO posts (user_id, title, body, status) VALUES ($1, $2, $3, $4)', [req.session.user.id, req.body.title, req.body.body, 'pending']);
  res.send('Paylaşım onaya gönderildi. <a href="/">Geri dön</a>');
});

app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const pending = await pool.query(`SELECT p.*, u.email FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'pending' ORDER BY p.created_at ASC`);
  const reports = await pool.query(`SELECT r.*, p.title FROM reports r JOIN posts p ON p.id = r.post_id ORDER BY r.created_at DESC LIMIT 100`);
  res.render('admin', { title: 'Admin', pending: pending.rows, reports: reports.rows });
});
app.post('/admin/posts/:id/approve', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'approved' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });
app.post('/admin/posts/:id/reject', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'rejected' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });

app.get('/rooms', requireAuth, async (req, res) => {
  const my = await pool.query(`SELECT r.* FROM rooms r JOIN room_members m ON m.room_id = r.id WHERE m.user_id = $1`, [req.session.user.id]);
  const pub = await pool.query(`SELECT * FROM rooms WHERE visibility = 'public' AND id NOT IN (SELECT room_id FROM room_members WHERE user_id = $1)`, [req.session.user.id]);
  res.render('rooms', { title: 'Odalar', myRooms: my.rows, publicRooms: pub.rows });
});
app.get('/rooms/new', requireAuth, (req, res) => res.render('new-room', { title: 'Yeni Oda' }));
app.post('/rooms', requireAuth, async (req, res) => {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('INSERT INTO rooms (owner_id, name, slug, visibility) VALUES ($1, $2, $3, $4) RETURNING id', [req.session.user.id, req.body.name, req.body.slug, req.body.visibility]);
    await c.query("INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, 'owner')", [r.rows[0].id, req.session.user.id]);
    await c.query('COMMIT');
    res.redirect('/rooms/' + r.rows[0].id);
  } catch(e) { await c.query('ROLLBACK'); res.send('Hata: Slug kullanımda olabilir.'); } finally { c.release(); }
});
app.get('/rooms/:id', requireAuth, async (req, res) => {
  const room = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.id]);
  if (!room.rows[0]) return res.send('Oda yok');
  const member = await pool.query('SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  if (room.rows[0].visibility === 'private' && member.rows.length === 0) return res.send('Gizli oda.');
  const msgs = await pool.query('SELECT m.*, u.email FROM room_messages m JOIN users u ON u.id = m.user_id WHERE room_id = $1 ORDER BY m.created_at ASC', [req.params.id]);
  res.render('room', { title: room.rows[0].name, room: room.rows[0], messages: msgs.rows, isMember: member.rows.length > 0, inviteCode: req.query.invite });
});
app.post('/rooms/:id/join', requireAuth, async (req, res) => { await pool.query("INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [req.params.id, req.session.user.id]); res.redirect('/rooms/' + req.params.id); });
app.post('/rooms/:id/messages', requireAuth, async (req, res) => { if(req.body.body) await pool.query('INSERT INTO room_messages (room_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, req.body.body]); res.redirect('/rooms/' + req.params.id); });
app.post('/rooms/:id/invite', requireAuth, async (req, res) => { const code = crypto.randomBytes(8).toString('hex'); await pool.query('INSERT INTO room_invites (room_id, code, created_by) VALUES ($1, $2, $3)', [req.params.id, code, req.session.user.id]); res.redirect('/rooms/' + req.params.id + '?invite=' + code); });
app.get('/join/:code', requireAuth, async (req, res) => { const inv = await pool.query('SELECT * FROM room_invites WHERE code = $1', [req.params.code]); if(inv.rows[0]) { await pool.query("INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [inv.rows[0].room_id, req.session.user.id]); res.redirect('/rooms/' + inv.rows[0].room_id); } else { res.send('Geçersiz kod.'); } });

app.get('/health', (req, res) => res.json({ ok: true }));
app.use((err, req, res, next) => { console.error(err); res.status(500).send('Sunucu Hatası'); });

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL) return;
  const check = await pool.query('SELECT id FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
  if (check.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query("INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin')", [process.env.ADMIN_EMAIL, hash]);
  }
}
initDb().then(seedAdmin).then(() => app.listen(PORT, () => console.log('Çalışıyor')));