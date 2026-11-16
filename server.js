require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { marked } = require('marked');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 10
});

function getRank(points) {
  if (points >= 1000) return '👑 Elite Hacker';
  if (points >= 500) return '🔥 Uzman';
  if (points >= 100) return '💻 Geliştirici';
  return '🌱 Çaylak';
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS points INTEGER DEFAULT 0;

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title TEXT, body TEXT, category TEXT DEFAULT 'Genel Sohbet', status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE posts ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'Genel Sohbet';

    CREATE TABLE IF NOT EXISTS post_likes (post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(post_id, user_id));
    CREATE TABLE IF NOT EXISTS post_comments (id SERIAL PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS rooms (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE, name TEXT, slug TEXT UNIQUE, visibility TEXT DEFAULT 'private', created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS room_members (room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, role TEXT DEFAULT 'member', PRIMARY KEY(room_id, user_id));
    CREATE TABLE IF NOT EXISTS room_messages (id SERIAL PRIMARY KEY, room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
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

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.getRank = getRank;
  res.locals.parseMarkdown = (text) => marked.parse(text || '');
  next();
});

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz'); next(); }

// ANA SAYFA (Kategorilere Göre)
app.get('/', async (req, res, next) => {
  try {
    const { rows: posts } = await pool.query(`
      SELECT p.*, u.username, u.points,
      (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as like_count,
      (SELECT COUNT(*) FROM post_comments pc WHERE pc.post_id = p.id) as comment_count
      FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'approved' ORDER BY p.created_at DESC
    `);

    for (let post of posts) {
      const likes = await pool.query('SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2', [post.id, req.session.user?.id]);
      post.has_liked = likes.rows.length > 0;
      const comments = await pool.query(`SELECT c.*, u.username FROM post_comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = $1 ORDER BY c.created_at ASC`, [post.id]);
      post.comments = comments.rows;
    }
    res.render('index', { title: 'Forum', posts });
  } catch (err) { next(err); }
});

// BEĞENİ & YORUM
app.post('/posts/:id/like', requireAuth, async (req, res) => {
  const check = await pool.query('SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  const postOwner = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
  if (check.rows.length > 0) {
    await pool.query('DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
    await pool.query('UPDATE users SET points = points - 2 WHERE id = $1', [postOwner.rows[0].user_id]);
  } else {
    await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1, $2)', [req.params.id, req.session.user.id]);
    await pool.query('UPDATE users SET points = points + 2 WHERE id = $1', [postOwner.rows[0].user_id]);
  }
  res.redirect('/');
});

app.post('/posts/:id/comment', requireAuth, async (req, res) => {
  if (req.body.body) {
    await pool.query('INSERT INTO post_comments (post_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, req.body.body]);
    await pool.query('UPDATE users SET points = points + 1 WHERE id = $1', [req.session.user.id]);
  }
  res.redirect('/');
});

// KAYIT, GİRİŞ, ÇIKIŞ
app.get('/register', (req, res) => res.render('register', { title: 'Kayıt' }));
app.post('/register', async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 12);
    await pool.query('INSERT INTO users (email, username, password_hash, points) VALUES ($1, $2, $3, 10)', [req.body.email.toLowerCase(), req.body.username, hash]);
    res.redirect('/login');
  } catch (err) { res.status(400).send('E-posta veya kullanıcı adı zaten alınmış.'); }
});

app.get('/login', (req, res) => res.render('login', { title: 'Giriş' }));
app.post('/login', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email.toLowerCase()]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) return res.status(400).send('Hatalı giriş.');
  req.session.regenerate(() => {
    req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role, points: user.points };
    res.redirect('/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// PAYLAŞIM YAPMA
app.get('/posts/new', requireAuth, (req, res) => res.render('new-post', { title: 'Yeni Konu' }));
app.post('/posts/new', requireAuth, async (req, res) => {
  await pool.query('INSERT INTO posts (user_id, title, body, category, status) VALUES ($1, $2, $3, $4, $5)', [req.session.user.id, req.body.title, req.body.body, req.body.category, 'pending']);
  res.send('Konu onaya gönderildi. <a href="/">Geri dön</a>');
});

// ADMIN
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const pending = await pool.query(`SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'pending' ORDER BY p.created_at ASC`);
  res.render('admin', { title: 'Admin', pending: pending.rows });
});
app.post('/admin/posts/:id/approve', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'approved' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });
app.post('/admin/posts/:id/reject', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'rejected' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });

// ODALAR
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
    await c.query('COMMIT'); res.redirect('/rooms/' + r.rows[0].id);
  } catch(e) { await c.query('ROLLBACK'); res.send('Hata'); } finally { c.release(); }
});
app.get('/rooms/:id', requireAuth, async (req, res) => {
  const room = await pool.query('SELECT * FROM rooms WHERE id = $1', [req.params.id]);
  const member = await pool.query('SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  if (room.rows[0]?.visibility === 'private' && member.rows.length === 0) return res.send('Gizli oda.');
  const msgs = await pool.query('SELECT m.*, u.username FROM room_messages m JOIN users u ON u.id = m.user_id WHERE room_id = $1 ORDER BY m.created_at ASC', [req.params.id]);
  res.render('room', { title: room.rows[0].name, room: room.rows[0], messages: msgs.rows, isMember: member.rows.length > 0, inviteCode: req.query.invite });
});
app.post('/rooms/:id/join', requireAuth, async (req, res) => { await pool.query("INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [req.params.id, req.session.user.id]); res.redirect('/rooms/' + req.params.id); });
app.post('/rooms/:id/messages', requireAuth, async (req, res) => { if(req.body.body) await pool.query('INSERT INTO room_messages (room_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, req.body.body]); res.redirect('/rooms/' + req.params.id); });
app.post('/rooms/:id/invite', requireAuth, async (req, res) => { const code = crypto.randomBytes(8).toString('hex'); await pool.query('INSERT INTO room_invites (room_id, code, created_by) VALUES ($1, $2, $3)', [req.params.id, code, req.session.user.id]); res.redirect('/rooms/' + req.params.id + '?invite=' + code); });
app.get('/join/:code', requireAuth, async (req, res) => { const inv = await pool.query('SELECT * FROM room_invites WHERE code = $1', [req.params.code]); if(inv.rows[0]) { await pool.query("INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", [inv.rows[0].room_id, req.session.user.id]); res.redirect('/rooms/' + inv.rows[0].room_id); } else { res.send('Geçersiz kod.'); } });

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL) return;
  const check = await pool.query('SELECT id FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
  if (check.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query("INSERT INTO users (email, username, password_hash, role, points) VALUES ($1, 'Kurucu', $2, 'admin', 9999)", [process.env.ADMIN_EMAIL, hash]);
  }
}
initDb().then(seedAdmin).then(() => app.listen(PORT, () => console.log('NullSec Aktif')));