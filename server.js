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
  if (points >= 1000) return { name: 'Elite Hacker', color: 'text-red-500', icon: 'fa-crown' };
  if (points >= 500) return { name: 'Uzman', color: 'text-yellow-500', icon: 'fa-fire' };
  if (points >= 100) return { name: 'Geliştirici', color: 'text-blue-400', icon: 'fa-code' };
  return { name: 'Çaylak', color: 'text-green-400', icon: 'fa-seedling' };
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT NOW());
    ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS points INTEGER DEFAULT 0;

    CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, name TEXT UNIQUE, description TEXT, icon TEXT);
    INSERT INTO categories (name, description, icon) VALUES 
      ('Siber Güvenlik', 'Genel güvenlik haberleri ve tartışmaları', 'fa-shield-alt'),
      ('Zafiyetler', 'CVE analizleri ve zafiyet tartışmaları', 'fa-bug'),
      ('CTF Çözümleri', 'Capture The Flag soruları ve çözümleri', 'fa-flag'),
      ('Kodlama & Araçlar', 'Yazılım, scriptler ve araç geliştirme', 'fa-code')
    ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS posts (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title TEXT, body TEXT, category TEXT DEFAULT 'Siber Güvenlik', status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS post_likes (post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(post_id, user_id));
    CREATE TABLE IF NOT EXISTS post_comments (id SERIAL PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
    
    CREATE TABLE IF NOT EXISTS shoutbox (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, message TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
  `);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

app.use(async (req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.getRank = getRank;
  res.locals.parseMarkdown = (text) => marked.parse(text || '');
  // Her sayfada kategorileri ve istatistikleri göster
  const cats = await pool.query('SELECT * FROM categories');
  const stats = await pool.query('SELECT (SELECT COUNT(*) FROM users) as users, (SELECT COUNT(*) FROM posts WHERE status = \'approved\') as posts');
  const shout = await pool.query('SELECT s.*, u.username FROM shoutbox s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC LIMIT 15');
  res.locals.categories = cats.rows;
  res.locals.stats = stats.rows[0];
  res.locals.shoutbox = shout.rows.reverse();
  next();
});

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz İşlem'); next(); }

// ANA SAYFA (Kategoriye Göre Filtreleme)
app.get('/', async (req, res, next) => {
  try {
    const catFilter = req.query.cat || 'Tümü';
    let query = `
      SELECT p.*, u.username, u.points,
      (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id) as like_count,
      (SELECT COUNT(*) FROM post_comments pc WHERE pc.post_id = p.id) as comment_count
      FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'approved'
    `;
    let params = [];
    if (catFilter !== 'Tümü') {
      query += ` AND p.category = $1`;
      params.push(catFilter);
    }
    query += ` ORDER BY p.created_at DESC`;

    const { rows: posts } = await pool.query(query, params);

    for (let post of posts) {
      const likes = await pool.query('SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2', [post.id, req.session.user?.id]);
      post.has_liked = likes.rows.length > 0;
      const comments = await pool.query(`SELECT c.*, u.username FROM post_comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = $1 ORDER BY c.created_at ASC`, [post.id]);
      post.comments = comments.rows;
    }
    res.render('index', { title: 'Forum', posts, activeCat: catFilter });
  } catch (err) { next(err); }
});

// SHOUTBOX MESAJ GÖNDERME
app.post('/shoutbox', requireAuth, async (req, res) => {
  if (req.body.message) {
    await pool.query('INSERT INTO shoutbox (user_id, message) VALUES ($1, $2)', [req.session.user.id, req.body.message]);
  }
  res.redirect('/');
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

// KAYIT & GİRİŞ
app.get('/register', (req, res) => res.render('register', { title: 'Kayıt', error: null }));
app.post('/register', async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 12);
    await pool.query('INSERT INTO users (email, username, password_hash, points) VALUES ($1, $2, $3, 10)', [req.body.email.toLowerCase(), req.body.username, hash]);
    res.redirect('/login');
  } catch (err) { res.render('register', { title: 'Kayıt', error: 'Bu e-posta veya kullanıcı adı zaten alınmış.' }); }
});

app.get('/login', (req, res) => res.render('login', { title: 'Giriş', error: null }));
app.post('/login', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email.toLowerCase()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) return res.render('login', { title: 'Giriş', error: 'E-posta veya şifre hatalı!' });
    req.session.regenerate(() => {
      req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role, points: user.points };
      res.redirect('/');
    });
  } catch (err) { res.render('login', { title: 'Giriş', error: 'Sistemsel hata.' }); }
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// PAYLAŞIM YAPMA
app.get('/posts/new', requireAuth, (req, res) => res.render('new-post', { title: 'Yeni Konu' }));
app.post('/posts/new', requireAuth, async (req, res) => {
  await pool.query('INSERT INTO posts (user_id, title, body, category, status) VALUES ($1, $2, $3, $4, $5)', [req.session.user.id, req.body.title, req.body.body, req.body.category, 'pending']);
  res.redirect('/');
});

// ADMIN
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const pending = await pool.query(`SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.status = 'pending' ORDER BY p.created_at ASC`);
  res.render('admin', { title: 'Admin', pending: pending.rows });
});
app.post('/admin/posts/:id/approve', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'approved' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });
app.post('/admin/posts/:id/reject', requireAuth, requireAdmin, async (req, res) => { await pool.query("UPDATE posts SET status = 'rejected' WHERE id = $1", [req.params.id]); res.redirect('/admin'); });

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL) return;
  const check = await pool.query('SELECT id FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
  if (check.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query("INSERT INTO users (email, username, password_hash, role, points) VALUES ($1, 'Kurucu', $2, 'admin', 9999)", [process.env.ADMIN_EMAIL, hash]);
  }
}
initDb().then(seedAdmin).then(() => app.listen(PORT, () => console.log('NullSec Aktif')));