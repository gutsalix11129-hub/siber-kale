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
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'user', is_banned BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
      DO $$ BEGIN BEGIN ALTER TABLE users ADD COLUMN username TEXT; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'var'; END; BEGIN ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'var'; END; END $$;

      CREATE TABLE IF NOT EXISTS forums (id SERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT, icon TEXT DEFAULT 'fa-comments', sort_order INTEGER DEFAULT 0);
      
      CREATE TABLE IF NOT EXISTS posts (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, forum_id INTEGER REFERENCES forums(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT NOT NULL, prefix TEXT, status TEXT DEFAULT 'approved', is_pinned BOOLEAN DEFAULT FALSE, is_locked BOOLEAN DEFAULT FALSE, views INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW());
      
      CREATE TABLE IF NOT EXISTS post_replies (id SERIAL PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
      
      CREATE TABLE IF NOT EXISTS post_reactions (post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(post_id, user_id));

      CREATE TABLE IF NOT EXISTS user_profiles (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, bio TEXT, signature TEXT);
      
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

// GLOBAL DEĞİŞKENLER VE BİLDİRİM KONTROLÜ
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
  } catch (err) { console.error("Global Middleware Err:", err); }
  next();
});

function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Yetkisiz'); next(); }

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
    const latestThreads = await pool.query(`SELECT p.id, p.title, u.username, p.created_at FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 5`);
    res.render('index', { title: 'Forum', forums: forumsWithStats, latestThreads: latestThreads.rows });
  } catch (err) { next(err); }
});

// FORUM İÇİ
app.get('/forum/:id', async (req, res, next) => {
  try {
    const forum = await pool.query('SELECT * FROM forums WHERE id = $1', [req.params.id]);
    if (!forum.rows[0]) return res.status(404).send('Forum bulunamadı');
    const threads = await pool.query(`
      SELECT p.*, u.username, u.points, (SELECT COUNT(*) FROM post_replies pr WHERE pr.post_id = p.id) as reply_count, (SELECT COUNT(*) FROM post_reactions pr WHERE pr.post_id = p.id) as like_count
      FROM posts p JOIN users u ON u.id = p.user_id WHERE p.forum_id = $1 ORDER BY p.is_pinned DESC, p.created_at DESC`, [req.params.id]);
    res.render('forum', { title: forum.rows[0].name, forum: forum.rows[0], threads: threads.rows });
  } catch (err) { next(err); }
});

// KONU DETAY
app.get('/thread/:id', async (req, res, next) => {
  try {
    await pool.query('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]);
    const thread = await pool.query(`SELECT p.*, u.username, u.points, f.name as forum_name FROM posts p JOIN users u ON u.id = p.user_id JOIN forums f ON f.id = p.forum_id WHERE p.id = $1`, [req.params.id]);
    if (!thread.rows[0]) return res.status(404).send('Konu yok');
    const replies = await pool.query(`SELECT pr.*, u.username, u.points, up.signature FROM post_replies pr JOIN users u ON u.id = pr.user_id LEFT JOIN user_profiles up ON up.user_id = u.id WHERE pr.post_id = $1 ORDER BY pr.created_at ASC`, [req.params.id]);
    const likes = await pool.query('SELECT COUNT(*) FROM post_reactions WHERE post_id = $1', [req.params.id]);
    const hasLiked = await pool.query('SELECT 1 FROM post_reactions WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user?.id]);
    
    res.render('thread', { title: thread.rows[0].title, thread: thread.rows[0], replies: replies.rows, likeCount: parseInt(likes.rows[0].count), hasLiked: hasLiked.rows.length > 0 });
  } catch (err) { next(err); }
});

// YANIT YAZMA (BİLDİRİM TETİKLER)
app.post('/thread/:id/reply', requireAuth, async (req, res) => {
  if (req.body.body) {
    await pool.query('INSERT INTO post_replies (post_id, user_id, body) VALUES ($1, $2, $3)', [req.params.id, req.session.user.id, req.body.body]);
    await pool.query('UPDATE users SET points = points + 1 WHERE id = $1', [req.session.user.id]);
    const owner = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
    if(owner.rows[0].user_id !== req.session.user.id) {
      await pool.query('INSERT INTO notifications (user_id, type, message, link) VALUES ($1, $2, $3, $4)', [owner.rows[0].user_id, 'reply', `${req.session.user.username} konuna yanıt yazdı.`, `/thread/${req.params.id}`]);
    }
  }
  res.redirect('/thread/' + req.params.id);
});

// BEĞENİ
app.post('/thread/:id/like', requireAuth, async (req, res) => {
  const check = await pool.query('SELECT 1 FROM post_reactions WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
  const owner = await pool.query('SELECT user_id FROM posts WHERE id = $1', [req.params.id]);
  if (check.rows.length > 0) {
    await pool.query('DELETE FROM post_reactions WHERE post_id = $1 AND user_id = $2', [req.params.id, req.session.user.id]);
    await pool.query('UPDATE users SET points = points - 2 WHERE id = $1', [owner.rows[0].user_id]);
  } else {
    await pool.query('INSERT INTO post_reactions (post_id, user_id) VALUES ($1, $2)', [req.params.id, req.session.user.id]);
    await pool.query('UPDATE users SET points = points + 2 WHERE id = $1', [owner.rows[0].user_id]);
    if(owner.rows[0].user_id !== req.session.user.id) {
      await pool.query('INSERT INTO notifications (user_id, type, message, link) VALUES ($1, $2, $3, $4)', [owner.rows[0].user_id, 'like', `${req.session.user.username} konunu beğendi.`, `/thread/${req.params.id}`]);
    }
  }
  res.redirect('/thread/' + req.params.id);
});

// YENİ KONU
app.get('/new-thread', requireAuth, (req, res) => res.render('new-thread', { title: 'Yeni Konu' }));
app.post('/new-thread', requireAuth, async (req, res) => {
  const result = await pool.query('INSERT INTO posts (user_id, forum_id, title, body, prefix, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [req.session.user.id, req.body.forum_id, req.body.title, req.body.body, req.body.prefix || null, 'approved']);
  res.redirect('/thread/' + result.rows[0].id);
});

// ARAMA MOTORU
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  let threads = [], users = [];
  if(q) {
    const tRes = await pool.query('SELECT p.id, p.title, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.title ILIKE $1 LIMIT 20', [`%${q}%`]);
    const uRes = await pool.query('SELECT username FROM users WHERE username ILIKE $1 LIMIT 20', [`%${q}%`]);
    threads = tRes.rows; users = uRes.rows;
  }
  res.render('search', { title: 'Arama', q, threads, users });
});

// PROFİL VE AYARLAR
app.get('/profile/:username', async (req, res) => {
  const user = await pool.query('SELECT * FROM users WHERE username = $1', [req.params.username]);
  if (!user.rows[0]) return res.status(404).send('Kullanıcı yok');
  const profile = await pool.query('SELECT * FROM user_profiles WHERE user_id = $1', [user.rows[0].id]);
  const threads = await pool.query('SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10', [user.rows[0].id]);
  res.render('profile', { title: user.rows[0].username, profileUser: user.rows[0], profile: profile.rows[0] || {}, threads: threads.rows });
});

app.get('/settings', requireAuth, async (req, res) => {
  const profile = await pool.query('SELECT * FROM user_profiles WHERE user_id = $1', [req.session.user.id]);
  res.render('settings', { title: 'Ayarlar', profile: profile.rows[0] || {} });
});
app.post('/settings', requireAuth, async (req, res) => {
  await pool.query(`INSERT INTO user_profiles (user_id, bio, signature) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET bio = $2, signature = $3`, [req.session.user.id, req.body.bio, req.body.signature]);
  res.redirect('/settings');
});

// ÖZEL MESAJLAR (PM)
app.get('/messages', requireAuth, async (req, res) => {
  const msgs = await pool.query(`SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.receiver_id = $1 ORDER BY m.created_at DESC`, [req.session.user.id]);
  res.render('messages', { title: 'Gelen Kutusu', messages: msgs.rows });
});
app.get('/messages/new/:username', requireAuth, async (req, res) => {
  const target = await pool.query('SELECT id, username FROM users WHERE username = $1', [req.params.username]);
  if(!target.rows[0]) return res.send('Kullanıcı yok');
  res.render('new-message', { title: 'Mesaj Gönder', target: target.rows[0] });
});
app.post('/messages/new/:username', requireAuth, async (req, res) => {
  const target = await pool.query('SELECT id FROM users WHERE username = $1', [req.params.username]);
  if(target.rows[0]) await pool.query('INSERT INTO messages (sender_id, receiver_id, body) VALUES ($1, $2, $3)', [req.session.user.id, target.rows[0].id, req.body.body]);
  res.redirect('/messages');
});

// BİLDİRİMLER
app.get('/notifications', requireAuth, async (req, res) => {
  const notifs = await pool.query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC', [req.session.user.id]);
  await pool.query('UPDATE notifications SET is_read = TRUE WHERE user_id = $1', [req.session.user.id]);
  res.render('notifications', { title: 'Bildirimler', notifications: notifs.rows });
});

// SHOUTBOX & AUTH
app.post('/shoutbox', requireAuth, async (req, res) => {
  if (req.body.message) await pool.query('INSERT INTO shoutbox (user_id, message) VALUES ($1, $2)', [req.session.user.id, req.body.message]);
  res.redirect('/');
});

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
  if (user.is_banned) return res.render('login', { title: 'Giriş', error: 'Hesabınız askıya alınmış.' });
  req.session.regenerate(() => {
    req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role, points: user.points };
    res.redirect('/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// ADMIN PANELİ VE İŞLEMLERİ
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const users = await pool.query('SELECT id, username, email, role, is_banned FROM users ORDER BY id DESC');
  const threads = await pool.query('SELECT p.id, p.title, p.is_pinned, p.is_locked, u.username FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 50');
  res.render('admin', { title: 'Admin Paneli', users: users.rows, threads: threads.rows });
});
app.post('/admin/thread/:id/pin', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE posts SET is_pinned = NOT is_pinned WHERE id = $1', [req.params.id]); res.redirect('/admin'); });
app.post('/admin/thread/:id/lock', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE posts SET is_locked = NOT is_locked WHERE id = $1', [req.params.id]); res.redirect('/admin'); });
app.post('/admin/user/:id/ban', requireAuth, requireAdmin, async (req, res) => { await pool.query('UPDATE users SET is_banned = NOT is_banned WHERE id = $1 AND role != \'admin\'', [req.params.id]); res.redirect('/admin'); });

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL) return;
  const check = await pool.query('SELECT id FROM users WHERE email = $1', [process.env.ADMIN_EMAIL]);
  if (check.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    const result = await pool.query("INSERT INTO users (email, username, password_hash, role, points) VALUES ($1, 'Kurucu', $2, 'admin', 9999) RETURNING id", [process.env.ADMIN_EMAIL, hash]);
    await pool.query('INSERT INTO user_profiles (user_id) VALUES ($1)', [result.rows[0].id]);
  }
}

initDb().then(seedAdmin).then(() => app.listen(PORT, () => console.log('NullSec Dev Aktif')));