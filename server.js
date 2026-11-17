require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { marked } = require('marked');
const expressLayouts = require('express-ejs-layouts');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 10
});

const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

function getRank(points) {
  if (points >= 1000) return { name: 'Elite Hacker', color: 'text-danger', icon: 'fa-crown' };
  if (points >= 500) return { name: 'Uzman', color: 'text-yellow-500', icon: 'fa-fire' };
  if (points >= 100) return { name: 'Geliştirici', color: 'text-accent', icon: 'fa-code' };
  return { name: 'Çaylak', color: 'text-primary', icon: 'fa-seedling' };
}

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', is_banned BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
      DO $$ BEGIN BEGIN ALTER TABLE users ADD COLUMN username TEXT; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'var'; END; BEGIN ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'var'; END; END $$;

      CREATE TABLE IF NOT EXISTS forums (id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT, icon TEXT DEFAULT 'fa-comments', sort_order INTEGER DEFAULT 0);
      INSERT INTO forums (name, description, icon, sort_order) VALUES
        ('Siber Güvenlik', 'Genel güvenlik haberleri ve tartışmaları', 'fa-shield-alt', 1),
        ('Zafiyetler', 'CVE analizleri ve sızma testleri', 'fa-bug', 2),
        ('Yapay Zeka & Teknoloji', 'AI araçları ve yazılım geliştirme', 'fa-robot', 3),
        ('CTF Çözümleri', 'Capture The Flag soruları ve çözümleri', 'fa-flag', 4)
      ON CONFLICT DO NOTHING;

      CREATE TABLE IF NOT EXISTS posts (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, forum_id INTEGER REFERENCES forums(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT NOT NULL, prefix TEXT, is_pinned BOOLEAN DEFAULT FALSE, is_locked BOOLEAN DEFAULT FALSE, views INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS post_replies (id SERIAL PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS post_reactions (post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(post_id, user_id));
      CREATE TABLE IF NOT EXISTS user_profiles (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, signature TEXT);
      CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type TEXT, message TEXT, link TEXT, is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE, receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT, is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS shoutbox (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, message TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS online_sessions (session_id TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, last_activity TIMESTAMPTZ DEFAULT NOW());
    `);
  } catch (err) { console.error("DB Init Error:", err); }
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
  
  try {
    const forums = await pool.query('SELECT * FROM forums ORDER BY sort_order');
    const stats = await pool.query(`SELECT (SELECT COUNT(*) FROM users) as users, (SELECT COUNT(*) FROM posts) as posts, (SELECT COUNT(*) FROM post_replies) as replies`);
    const shout = await pool.query('SELECT s.*, u.username FROM shoutbox s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC LIMIT 15');
    const online = await pool.query(`SELECT DISTINCT u.id, u.username FROM online_sessions os JOIN users u ON u.id = os.user_id WHERE os.last_activity > NOW() - INTERVAL '5 minutes'`);
    
    res.locals.forums = forums.rows;
    res.locals.stats = stats.rows[0];
    res.locals.shoutbox = shout.rows.reverse();
    res.locals.onlineUsers = online.rows;

    if (req.session.user) {
      const notifs = await pool.query('SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE', [req.session.user.id]);
      const pms = await pool.query('SELECT COUNT(*) FROM messages WHERE receiver_id = $1 AND is_read = FALSE', [req.session.user.id]);
      res.locals.unreadNotifs = parseInt(notifs.rows[0].count);
      res.locals.unreadPMs = parseInt(pms.rows[0].count);
      await pool.query(`INSERT INTO online_sessions (session_id, user_id, last_activity) VALUES ($1, $2, NOW()) ON CONFLICT (session_id) DO UPDATE SET last_activity = NOW()`, [req.sessionID, req.session.user.id]);
    } else {
      res.locals.unreadNotifs = 0; res.locals.unreadPMs = 0;
    }
  } catch (err) { console.error("Global Err:", err); }
  next();
});

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz'); next(); }

// YAPAY ZEKA CHAT API
app.post('/api/ai-chat', async (req, res) => {
  if (!openai) return res.json({ reply: "Sistem hatası: OPENAI_API_KEY eksik. Lütfen Render'da ekleyin." });
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: "Sen NullSec adında, siber güvenlik uzmanı bir yapay zeka asistanısın. Kullanıcılara hacker temalı, havalı ama yasal sınırlar içinde cevaplar veriyorsun. Kısa ve net konuş." },
        { role: "user", content: req.body.message }
      ],
      max_tokens: 300
    });
    res.json({ reply: completion.choices[0].message.content });
  } catch (err) { res.json({ reply: "Sistem hatası! OpenAI bağlantısı başarısız." }); }
});

// ANA SAYFA
app.get('/', async (req, res, next) => {
  try {
    const forumsWithStats = [];
    for (const forum of res.locals.forums) {
      const threadCount = await pool.query('SELECT COUNT(*) FROM posts WHERE forum_id = $1', [forum.id]);
      const replyCount = await pool.query(`SELECT COUNT(*) FROM post_replies pr JOIN posts p ON p.id = pr.post_id WHERE p.forum_id = $1`, [forum.id]);
      const lastPost = await pool.query(`SELECT p.id, p.title, p.created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.forum_id = $1 ORDER BY p.created_at DESC LIMIT 1`, [forum.id]);
      forumsWithStats.push({ ...forum, threadCount: parseInt(threadCount.rows[0].count), replyCount: parseInt(replyCount.rows[0].count), lastPost: lastPost.rows[0] || null });
    }
    const latestThreads = await pool.query(`SELECT p.id, p.title, u.username FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 5`);
    res.render('index', { title: 'Forum', forums: forumsWithStats, latestThreads: latestThreads.rows });
  } catch (err) { next(err); }
});

// FORUM İÇİ
app.get('/forum/:id', async (req, res, next) => {
  try {
    const forum = await pool.query('SELECT * FROM forums WHERE id = $1', [req.params.id]);
    const threads = await pool.query(`
      SELECT p.*, u.username, (SELECT COUNT(*) FROM post_replies pr WHERE pr.post_id = p.id) as reply_count
      FROM posts p JOIN users u ON u.id = p.user_id WHERE p.forum_id = $1 ORDER BY p.is_pinned DESC, p.created_at DESC`, [req.params.id]);
    res.render('forum', { title: forum.rows[0].name, forum: forum.rows[0], threads: threads.rows });
  } catch (err) { next(err); }
});

// KONU İÇİ
app.get('/thread/:id', async (req, res, next) => {
  try {
    await pool.query('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]);
    const thread = await pool.query(`SELECT p.*, u.username, f.name as forum_name FROM posts p JOIN users u ON u.id = p.user_id JOIN forums f ON f.id = p.forum_id WHERE p.id = $1`, [req.params.id]);
    if (!thread.rows[0]) return res.status(404).send('Konu yok');
    const replies = await pool.query(`SELECT pr.*, u.username, u.role, up.signature FROM post_replies pr JOIN users u ON u.id = pr.user_id LEFT JOIN user_profiles up ON up.user_id = u.id WHERE pr.post_id = $1 ORDER BY pr.created_at ASC`, [req.params.id]);
    res.render('thread', { title: thread.rows[0].title, thread: thread.rows[0], replies: replies.rows });
  } catch (err) { next(err); }
});

// YANIT YAZMA
app.post('/thread/:id/reply', requireAuth, async (req, res) => {
  if (req.body.body) {
    await pool.query('INSERT INTO post_replies (post_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, req.body.body]);
    const owner = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
    if(owner.rows[0].user_id !== req.session.user.id) {
      await pool.query('INSERT INTO notifications (user_id, type, message, link) VALUES ($1, $2, $3, $4)', [owner.rows[0].user_id, 'reply', `${req.session.user.username} konuna yanıt yazdı.`, `/thread/${req.params.id}`]);
    }
  }
  res.redirect('/thread/' + req.params.id);
});

// YENİ KONU
app.get('/new-thread', requireAuth, (req, res) => res.render('new-thread', { title: 'Yeni Konu' }));
app.post('/new-thread', requireAuth, async (req, res) => {
  const result = await pool.query('INSERT INTO posts (user_id, forum_id, title, body, prefix) VALUES ($1, $2, $3, $4, $5) RETURNING id', [req.session.user.id, req.body.forum_id, req.body.title, req.body.body, req.body.prefix || null]);
  res.redirect('/thread/' + result.rows[0].id);
});

// GİRİŞ & KAYIT
app.get('/register', (req, res) => res.render('register', { title: 'Kayıt', error: null }));
app.post('/register', async (req, res) => {
  try {
    const check = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', [req.body.email.toLowerCase(), req.body.username]);
    if (check.rows.length > 0) return res.render('register', { title: 'Kayıt', error: 'E-posta veya Kullanıcı adı alınmış.' });
    const hash = await bcrypt.hash(req.body.password, 12);
    const result = await pool.query('INSERT INTO users (email, username, password_hash, points) VALUES ($1, $2, $3, 10) RETURNING id', [req.body.email.toLowerCase(), req.body.username, hash]);
    await pool.query('INSERT INTO user_profiles (user_id) VALUES ($1)', [result.rows[0].id]);
    res.redirect('/login');
  } catch (err) { res.render('register', { title: 'Kayıt', error: 'Hata oluştu.' }); }
});

app.get('/login', (req, res) => res.render('login', { title: 'Giriş', error: null }));
app.post('/login', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email.toLowerCase()]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) return res.render('login', { title: 'Giriş', error: 'Hatalı giriş!' });
  req.session.regenerate(() => {
    req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role, points: user.points };
    res.redirect('/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// SHOUTBOX
app.post('/shoutbox', requireAuth, async (req, res) => {
  if (req.body.message) await pool.query('INSERT INTO shoutbox (user_id, message) VALUES ($1, $2)', [req.session.user.id, req.body.message]);
  res.redirect('/');
});

// ADMIN PANELİ
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const users = await pool.query('SELECT id, username, email, role, is_banned FROM users ORDER BY id DESC');
  const threads = await pool.query('SELECT p.id, p.title, p.is_pinned, p.is_locked, u.username FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 50');
  res.render('admin', { title: 'Admin Paneli', users: users.rows, threads: threads.rows });
});
app.post('/admin/thread/:id/pin', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE posts SET is_pinned = NOT is_pinned WHERE id = $1', [req.params.id]); res.redirect('/admin'); });
app.post('/admin/thread/:id/lock', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE posts SET is_locked = NOT is_locked WHERE id = $1', [req.params.id]); res.redirect('/admin'); });
app.post('/admin/user/:id/ban', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE users SET is_banned = NOT is_banned WHERE id = $1 AND role != \'admin\'', [req.params.id]); res.redirect('/admin'); });

initDb().then(async () => {
  try {
    if (process.env.ADMIN_EMAIL) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin123!', 12);
      const check = await pool.query('SELECT id FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
      if (check.rows.length > 0) { await pool.query("UPDATE users SET role = 'admin', password_hash = $1 WHERE email = $2", [hash, process.env.ADMIN_EMAIL]); } 
      else { await pool.query("INSERT INTO users (email, username, password_hash, role, points) VALUES ($1, 'Kurucu', $2, 'admin', 9999)", [process.env.ADMIN_EMAIL, hash]); }
    }
  } catch (e) { console.error(e); }
  app.listen(PORT, () => console.log('NullSec Sistem Aktif'));
});