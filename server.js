'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const { calculateRisk, symptomWeights } = require('./lib/risk');

const app = express();
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: production && !process.env.DATABASE_URL.includes('localhost') ? { rejectUnauthorized: false } : false,
  max: 10,
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Повторите через 15 минут.' },
});

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) reject(error);
      else resolve(`${salt}:${key.toString('hex')}`);
    });
  });
}

async function verifyPassword(password, stored) {
  const [salt, expectedHex] = String(stored).split(':');
  if (!salt || !expectedHex) return false;
  const actual = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(stored));
}

function createCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function smtpTransport() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendVerificationCode(email, code) {
  const transport = smtpTransport();
  if (!transport) {
    if (production) throw new Error('SMTP is not configured');
    console.log(`[development] Verification code for ${email}: ${code}`);
    return false;
  }
  await transport.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Код подтверждения MeningoCheck/Ai',
    text: `Ваш код подтверждения: ${code}. Код действует 10 минут.`,
  });
  return true;
}

async function issueCode(userId, email) {
  const code = createCode();
  await pool.query('DELETE FROM verification_codes WHERE user_id = $1', [userId]);
  await pool.query(
    `INSERT INTO verification_codes (user_id, code_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`,
    [userId, hashToken(code)],
  );
  await sendVerificationCode(email, code);
  return production ? undefined : code;
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '30 days')`,
    [userId, hashToken(token)],
  );
  return token;
}

async function requireAuth(req, res, next) {
  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Требуется вход.' });
    const result = await pool.query(
      `SELECT u.id, u.name, u.email
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.verified_at IS NOT NULL`,
      [hashToken(token)],
    );
    if (!result.rowCount) return res.status(401).json({ error: 'Сессия истекла. Войдите снова.' });
    req.auth = { token, user: result.rows[0] };
    next();
  } catch (error) {
    next(error);
  }
}

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    if (name.length < 2 || name.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Укажите имя, корректный email и пароль от 8 до 128 символов.' });
    }
    const passwordHash = await hashPassword(password);
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE
       SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, updated_at = NOW()
       WHERE users.verified_at IS NULL
       RETURNING id, verified_at`,
      [name, email, passwordHash],
    );
    if (!result.rowCount || result.rows[0].verified_at) {
      return res.status(409).json({ error: 'Пользователь с таким email уже зарегистрирован.' });
    }
    const devCode = await issueCode(result.rows[0].id, email);
    res.status(201).json({ email, devCode });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/resend', authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const result = await pool.query('SELECT id FROM users WHERE email = $1 AND verified_at IS NULL', [email]);
    if (result.rowCount) await issueCode(result.rows[0].id, email);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/verify', authLimiter, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const email = normalizeEmail(req.body.email);
    const codeHash = hashToken(String(req.body.code || '').trim());
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT u.id, u.name, u.email, v.id AS code_id
       FROM users u JOIN verification_codes v ON v.user_id = u.id
       WHERE u.email = $1 AND u.verified_at IS NULL AND v.code_hash = $2
         AND v.expires_at > NOW() AND v.attempts < 5
       FOR UPDATE`,
      [email, codeHash],
    );
    if (!result.rowCount) {
      await client.query(
        `UPDATE verification_codes SET attempts = attempts + 1
         WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
        [email],
      );
      await client.query('COMMIT');
      return res.status(400).json({ error: 'Неверный или истёкший код.' });
    }
    const user = result.rows[0];
    await client.query('UPDATE users SET verified_at = NOW(), updated_at = NOW() WHERE id = $1', [user.id]);
    await client.query('DELETE FROM verification_codes WHERE user_id = $1', [user.id]);
    await client.query('COMMIT');
    const token = await createSession(user.id);
    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (error) {
    await client.query('ROLLBACK');
    next(error);
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const result = await pool.query(
      'SELECT id, name, email, password_hash, verified_at FROM users WHERE email = $1',
      [email],
    );
    const user = result.rows[0];
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }
    if (!user.verified_at) return res.status(403).json({ error: 'Сначала подтвердите email.' });
    const token = await createSession(user.id);
    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (error) {
    next(error);
  }
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.auth.user }));

app.post('/api/auth/logout', requireAuth, async (req, res, next) => {
  try {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(req.auth.token)]);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/assessments', requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, risk_percent AS "pct", emergency, created_at AS "createdAt"
       FROM assessments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.auth.user.id],
    );
    res.json({ assessments: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/assessments', requireAuth, async (req, res, next) => {
  try {
    const age = Number(req.body.age);
    const duration = Number(req.body.duration);
    const gender = String(req.body.gender || '');
    const selected = Array.isArray(req.body.symptoms) ? [...new Set(req.body.symptoms)] : [];
    const other = String(req.body.other || '').trim().slice(0, 1000);
    if (!Number.isInteger(age) || age < 0 || age > 120 || !Number.isInteger(duration) || duration < 0 || duration > 365 || !['female', 'male', 'other'].includes(gender)) {
      return res.status(400).json({ error: 'Проверьте возраст, пол и длительность симптомов.' });
    }
    if (selected.some((id) => !(id in symptomWeights))) {
      return res.status(400).json({ error: 'Передан неизвестный симптом.' });
    }
    const { pct, emergency } = calculateRisk(selected);
    const result = await pool.query(
      `INSERT INTO assessments (user_id, age, gender, duration_days, symptoms, other_symptoms, risk_percent, emergency)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, risk_percent AS "pct", emergency, created_at AS "createdAt"`,
      [req.auth.user.id, age, gender, duration, selected, other, pct, emergency],
    );
    res.status(201).json({ assessment: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*splat', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((error, _req, res, _next) => {
  console.error(error);
  const smtpMissing = error.message === 'SMTP is not configured';
  res.status(smtpMissing ? 503 : 500).json({
    error: smtpMissing ? 'Отправка почты пока не настроена.' : 'Внутренняя ошибка сервера.',
  });
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      verified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS verification_codes (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash CHAR(64) NOT NULL,
      attempts SMALLINT NOT NULL DEFAULT 0,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash CHAR(64) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS assessments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      age SMALLINT NOT NULL,
      gender VARCHAR(10) NOT NULL,
      duration_days SMALLINT NOT NULL,
      symptoms TEXT[] NOT NULL DEFAULT '{}',
      other_symptoms TEXT NOT NULL DEFAULT '',
      risk_percent SMALLINT NOT NULL,
      emergency BOOLEAN NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS assessments_user_created_idx ON assessments(user_id, created_at DESC);
  `);
  await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");
  await pool.query("DELETE FROM verification_codes WHERE expires_at <= NOW()");
}

initDatabase()
  .then(() => app.listen(port, '0.0.0.0', () => console.log(`MeningoCheck/Ai listening on ${port}`)))
  .catch((error) => {
    console.error('Database initialization failed', error);
    process.exit(1);
  });
