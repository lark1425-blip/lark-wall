require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "люси_знает_всё"; // СМЕНИ НА СВОЙ КЛЮЧ!

// === ПОДКЛЮЧЕНИЕ К БАЗЕ ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// === ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ ===
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        last_seen BIGINT NOT NULL,
        visits INTEGER DEFAULT 1
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        user_name TEXT NOT NULL,
        text TEXT NOT NULL,
        answer TEXT,
        deleted INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL,
        answered_at BIGINT
      );
    `);

    console.log("База данных готова");
  } catch (err) {
    console.error("Ошибка базы данных:", err);
  }
}

initDB();

// === MIDDLEWARE ===
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || "lark_secret_key_2026",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

// === УТИЛИТЫ ===
function now() { return Date.now(); }

// === АВТОРИЗАЦИЯ ===
app.post("/api/register", async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.json({ ok: false, error: "заполни все поля" });
    if (name.length < 2 || name.length > 20) return res.json({ ok: false, error: "имя от 2 до 20 символов" });
    if (password.length < 3) return res.json({ ok: false, error: "пароль минимум 3 символа" });

    const existing = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (existing.rows.length > 0) return res.json({ ok: false, error: "это имя уже занято" });

    const hash = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, password, created_at, last_seen, visits) VALUES ($1, $2, $3, $4, 1) RETURNING id",
      [name, hash, now(), now()]
    );

    req.session.userId = result.rows[0].id;
    req.session.userName = name;

    res.json({ ok: true, name });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "ошибка сервера" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.json({ ok: false, error: "заполни все поля" });

    const userRes = await pool.query("SELECT * FROM users WHERE name = $1", [name]);
    if (userRes.rows.length === 0) return res.json({ ok: false, error: "неверное имя или пароль" });

    const user = userRes.rows[0];
    if (!bcrypt.compareSync(password, user.password)) return res.json({ ok: false, error: "неверное имя или пароль" });

    await pool.query("UPDATE users SET last_seen = $1, visits = visits + 1 WHERE id = $2", [now(), user.id]);

    req.session.userId = user.id;
    req.session.userName = user.name;

    res.json({ ok: true, name: user.name });
  } catch (err) {
    console.error(err);
    res.json({ ok: false, error: "ошибка сервера" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  if (req.session.userId) {
    res.json({ ok: true, name: req.session.userName, id: req.session.userId });
  } else {
    res.json({ ok: false });
  }
});

// === СООБЩЕНИЯ (ЛИЧНЫЕ) ===
app.get("/api/my-messages", async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, error: "нужно войти" });

  const result = await pool.query(`
    SELECT id, text, answer, deleted, created_at, answered_at
    FROM messages
    WHERE user_id = $1
    ORDER BY created_at DESC
  `, [req.session.userId]);

  res.json({ ok: true, messages: result.rows });
});

app.post("/api/messages", async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, error: "нужно войти" });

  const { text } = req.body;
  if (!text || text.trim().length === 0) return res.json({ ok: false, error: "напиши что-нибудь" });
  if (text.length > 500) return res.json({ ok: false, error: "слишком длинное сообщение" });

  await pool.query(`
    INSERT INTO messages (user_id, user_name, text, created_at)
    VALUES ($1, $2, $3, $4)
  `, [req.session.userId, req.session.userName, text.trim(), now()]);

  res.json({ ok: true });
});

// === АДМИНКА ===
app.post("/api/admin/login", (req, res) => {
  const { key } = req.body;
  if (key === ADMIN_KEY) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  res.json({ ok: false, error: "неверный ключ" });
});

app.get("/api/admin/messages", async (req, res) => {
  if (!req.session.isAdmin) return res.json({ ok: false, error: "доступ запрещён" });

  const result = await pool.query(`
    SELECT 
      m.id, m.user_id, m.user_name, m.text, m.answer, m.deleted,
      m.created_at, m.answered_at,
      u.created_at as user_created, u.last_seen, u.visits
    FROM messages m
    JOIN users u ON m.user_id = u.id
    ORDER BY m.created_at DESC
  `);

  res.json({ ok: true, messages: result.rows });
});

app.get("/api/admin/users", async (req, res) => {
  if (!req.session.isAdmin) return res.json({ ok: false, error: "доступ запрещён" });

  const result = await pool.query(`
    SELECT 
      u.id, u.name, u.created_at, u.last_seen, u.visits,
      COUNT(m.id) as message_count
    FROM users u
    LEFT JOIN messages m ON m.user_id = u.id
    GROUP BY u.id
    ORDER BY u.last_seen DESC
  `);

  res.json({ ok: true, users: result.rows });
});

app.get("/api/admin/user/:id", async (req, res) => {
  if (!req.session.isAdmin) return res.json({ ok: false, error: "доступ запрещён" });

  const userId = parseInt(req.params.id);
  const userRes = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  if (userRes.rows.length === 0) return res.json({ ok: false, error: "пользователь не найден" });

  const msgRes = await pool.query(`
    SELECT id, text, answer, deleted, created_at, answered_at
    FROM messages
    WHERE user_id = $1
    ORDER BY created_at DESC
  `, [userId]);

  res.json({ ok: true, user: userRes.rows[0], messages: msgRes.rows });
});

app.post("/api/admin/answer", async (req, res) => {
  if (!req.session.isAdmin) return res.json({ ok: false, error: "доступ запрещён" });

  const { id, answer } = req.body;
  if (answer && answer.trim()) {
    await pool.query("UPDATE messages SET answer = $1, answered_at = $2 WHERE id = $3", [answer.trim(), now(), id]);
  } else {
    await pool.query("UPDATE messages SET answer = NULL, answered_at = NULL WHERE id = $1", [id]);
  }

  res.json({ ok: true });
});

app.post("/api/admin/delete", async (req, res) => {
  if (!req.session.isAdmin) return res.json({ ok: false, error: "доступ запрещён" });

  const { id, deleted } = req.body;
  await pool.query("UPDATE messages SET deleted = $1 WHERE id = $2", [deleted ? 1 : 0, id]);

  res.json({ ok: true });
});

// === ЗАПУСК ===
app.listen(PORT, () => {
  console.log(`Люси слушает на порту ${PORT}`);
  console.log(`Админ-ключ: ${ADMIN_KEY}`);
});