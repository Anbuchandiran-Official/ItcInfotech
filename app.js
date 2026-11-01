const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const argon2 = require('argon2');
const helmet = require('helmet');
const Redis = require('ioredis');
const { rateLimit } = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
const passwordHashOptions = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
const dummyHashPromise = argon2.hash(crypto.randomBytes(32), passwordHashOptions);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProduction ? { rejectUnauthorized: false } : undefined });
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: true }) : null;
const secret = process.env.SESSION_SECRET;
const encryptionKey = process.env.TOTP_ENCRYPTION_KEY;

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Start PostgreSQL and set DATABASE_URL.');
if (!secret || secret.length < 32) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters.');
if (!encryptionKey || encryptionKey.length < 32) throw new Error('Set TOTP_ENCRYPTION_KEY to a random value of at least 32 characters.');
if (isProduction && !redis) throw new Error('REDIS_URL is required in production for shared rate limits.');

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '12kb', strict: true }));
app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: isProduction ? '1h' : 0 }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'itc.sid', secret, resave: false, saveUninitialized: false, rolling: true,
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 1000 * 60 * 30 }
}));

function rateStore(prefix) {
  if (!redis) return undefined;
  return new RedisStore({ prefix, sendCommand: (...args) => redis.call(...args) });
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, store: rateStore('rl:login:'), message: { error: 'Too many attempts. Wait a while and try again.' } });
const recoveryLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false, store: rateStore('rl:recovery:'), message: { error: 'Too many recovery requests. Try again later.' } });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false, store: rateStore('rl:signup:'), message: { error: 'Too many sign-up attempts. Try again later.' } });

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = value => String(value || '').trim().toLowerCase();
const safeEqual = (a, b) => { const aa = Buffer.from(a); const bb = Buffer.from(b); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); };

async function setupDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS password_resets (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS password_resets_user_id_idx ON password_resets(user_id)');
}

app.get('/api/csrf', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
  res.set('Cache-Control', 'no-store').json({ csrfToken: req.session.csrfToken });
});
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.get('x-csrf-token');
  if (!token || !req.session.csrfToken || !safeEqual(token, req.session.csrfToken)) return res.status(403).json({ error: 'Your session expired. Refresh and try again.' });
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.userId || req.session.mfaPending) return res.status(401).json({ error: 'Complete sign-in to continue.' });
  next();
}
function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 256) return 'Use a password between 12 and 256 characters.';
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) return 'Include a lowercase letter, uppercase letter, and number.';
  return null;
}
function encryptSecret(value) {
  const key = crypto.createHash('sha256').update(encryptionKey).digest(); const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map(x => x.toString('base64url')).join('.');
}
function decryptSecret(value) {
  const [iv, tag, body] = value.split('.').map(x => Buffer.from(x, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(encryptionKey).digest(), iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes) {
  let bits = 0, value = 0, output = '';
  for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { output += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) output += B32[(value << (5 - bits)) & 31];
  return output;
}
function base32Decode(input) {
  let bits = 0, value = 0; const out = [];
  for (const ch of input.toUpperCase().replace(/=+$/,'')) { const n = B32.indexOf(ch); if (n < 0) throw new Error('Invalid authenticator secret'); value = (value << 5) | n; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function totp(secretValue, time = Date.now()) {
  const counter = Math.floor(time / 30000); const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secretValue)).update(msg).digest(); const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}
function verifyTotp(secretValue, code) {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  for (const delta of [-30000, 0, 30000]) if (safeEqual(totp(secretValue, Date.now() + delta), String(code))) return true;
  return false;
}
function genericAuthError(res) { return res.status(401).json({ error: 'Email or password is incorrect.' }); }

app.post('/api/register', signupLimiter, asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email); const password = req.body.password;
  const problem = validatePassword(password);
  if (!emailPattern.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (problem) return res.status(400).json({ error: problem });
  const hash = await argon2.hash(password, passwordHashOptions);
  try {
    const result = await pool.query('INSERT INTO app_users(email, password_hash) VALUES($1,$2) RETURNING id,email', [email, hash]);
    await loginSession(req, result.rows[0]);
    res.status(201).json({ user: { email: result.rows[0].email, mfaEnabled: false } });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'An account with that email already exists. Sign in instead.' });
    throw error;
  }
}));

async function loginSession(req, user) {
  await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
  req.session.userId = user.id;
  req.session.userEmail = user.email;
  req.session.mfaPending = Boolean(user.totp_secret_enc);
  req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
}

app.post('/api/login', loginLimiter, asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email); const result = await pool.query('SELECT id,email,password_hash,totp_secret_enc FROM app_users WHERE email=$1', [email]);
  const user = result.rows[0];
  const hash = user?.password_hash || await dummyHashPromise;
  let ok = false;
  try { ok = await argon2.verify(hash, String(req.body.password || '')); } catch {}
  if (!user || !ok) {
    if (redis && emailPattern.test(email)) {
      const accountKey = `login-account:${crypto.createHash('sha256').update(`${email}:${req.ip}`).digest('hex')}`;
      const attempts = await redis.incr(accountKey);
      if (attempts === 1) await redis.expire(accountKey, 15 * 60);
      if (attempts >= 5) return res.status(429).json({ error: 'Too many attempts for this account. Try again later.' });
    }
    return genericAuthError(res);
  }
  if (redis) await redis.del(`login-account:${crypto.createHash('sha256').update(`${email}:${req.ip}`).digest('hex')}`);
  await loginSession(req, user);
  if (user.totp_secret_enc) return res.json({ mfaRequired: true });
  res.json({ user: { email: user.email, mfaEnabled: false } });
}));
app.post('/api/login/mfa', loginLimiter, asyncRoute(async (req, res) => {
  if (!req.session.mfaPending || !req.session.userId) return genericAuthError(res);
  const result = await pool.query('SELECT email,totp_secret_enc FROM app_users WHERE id=$1', [req.session.userId]);
  if (!result.rowCount || !verifyTotp(decryptSecret(result.rows[0].totp_secret_enc), req.body.code)) return genericAuthError(res);
  req.session.mfaPending = false;
  req.session.userEmail = result.rows[0].email;
  res.json({ user: { email: result.rows[0].email, mfaEnabled: true } });
}));

app.get('/api/me', (req, res) => {
  if (!req.session.userId || req.session.mfaPending) return res.json({ user: null });
  pool.query('SELECT email,totp_secret_enc,created_at FROM app_users WHERE id=$1', [req.session.userId]).then(result => {
    if (!result.rowCount) return res.json({ user: null });
    res.json({ user: { email: result.rows[0].email, mfaEnabled: Boolean(result.rows[0].totp_secret_enc), createdAt: result.rows[0].created_at } });
  }).catch(error => res.status(500).json({ error: 'Unable to load your account.' }));
});

app.post('/api/logout', requireAuth, asyncRoute(async (req, res) => {
  await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
  res.clearCookie('itc.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax' }).json({ ok: true });
}));

app.post('/api/mfa/setup', requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT email,totp_secret_enc FROM app_users WHERE id=$1', [req.session.userId]);
  if (result.rows[0].totp_secret_enc) return res.status(409).json({ error: 'Authenticator MFA is already enabled.' });
  const secretValue = base32Encode(crypto.randomBytes(20));
  req.session.pendingTotp = secretValue;
  const label = encodeURIComponent(`ITC Login:${result.rows[0].email}`);
  res.json({ secret: secretValue, otpauth: `otpauth://totp/${label}?secret=${secretValue}&issuer=ITC%20Secure%20Login&algorithm=SHA1&digits=6&period=30` });
}));
app.post('/api/mfa/enable', requireAuth, asyncRoute(async (req, res) => {
  const secretValue = req.session.pendingTotp;
  if (!secretValue || !verifyTotp(secretValue, req.body.code)) return res.status(400).json({ error: 'Code did not match. Try the current code in your authenticator.' });
  await pool.query('UPDATE app_users SET totp_secret_enc=$1 WHERE id=$2', [encryptSecret(secretValue), req.session.userId]);
  delete req.session.pendingTotp;
  res.json({ ok: true });
}));
app.post('/api/mfa/disable', requireAuth, asyncRoute(async (req, res) => {
  const result = await pool.query('SELECT totp_secret_enc FROM app_users WHERE id=$1', [req.session.userId]);
  if (!result.rowCount || !result.rows[0].totp_secret_enc || !verifyTotp(decryptSecret(result.rows[0].totp_secret_enc), req.body.code)) return res.status(400).json({ error: 'Authenticator code is incorrect.' });
  await pool.query('UPDATE app_users SET totp_secret_enc=NULL WHERE id=$1', [req.session.userId]);
  res.json({ ok: true });
}));

app.post('/api/forgot', recoveryLimiter, asyncRoute(async (req, res) => {
  const generic = { message: 'If an account exists for that email, password reset instructions will be sent.' };
  const email = normalizeEmail(req.body.email);
  if (!emailPattern.test(email)) return res.json(generic);
  if (!process.env.RESEND_API_KEY || !process.env.MAIL_FROM) return res.json(generic);
  const userResult = await pool.query('SELECT id,email FROM app_users WHERE email=$1', [email]);
  if (!userResult.rowCount) return res.json(generic);
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await pool.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL', [userResult.rows[0].id]);
  await pool.query('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL \'15 minutes\')', [userResult.rows[0].id, tokenHash]);
  const origin = process.env.APP_ORIGIN || `${req.protocol}://${req.get('host')}`;
  try {
    const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: process.env.MAIL_FROM, to: [email], subject: 'Reset your secure login password', text: `Use this one-time link within 15 minutes:\n\n${origin}/?reset=${encodeURIComponent(token)}\n\nIf you did not request this, ignore this email.` }) });
    if (!response.ok) throw new Error(`Email provider returned ${response.status}`);
  } catch (error) {
    await pool.query('UPDATE password_resets SET used_at=NOW() WHERE token_hash=$1', [tokenHash]);
    throw error;
  }
  res.json(generic);
}));
app.post('/api/reset', recoveryLimiter, asyncRoute(async (req, res) => {
  const token = String(req.body.token || ''); const password = req.body.password; const problem = validatePassword(password);
  if (problem) return res.status(400).json({ error: problem });
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return res.status(400).json({ error: 'This reset link is invalid or expired. Request a new one.' });
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const row = await client.query('SELECT id,user_id FROM password_resets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE', [hash]);
    if (!row.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'This reset link is invalid or expired. Request a new one.' }); }
    const passwordHash = await argon2.hash(password, passwordHashOptions);
    await client.query('UPDATE app_users SET password_hash=$1,password_changed_at=NOW() WHERE id=$2', [passwordHash, row.rows[0].user_id]);
    await client.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL', [row.rows[0].user_id]);
    await client.query('DELETE FROM user_sessions WHERE sess->>\'userId\'=$1', [String(row.rows[0].user_id)]);
    await client.query('COMMIT');
    res.json({ message: 'Password changed. Sign in with your new password.' });
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
}));

app.get('/healthz', asyncRoute(async (req, res) => {
  await pool.query('SELECT 1');
  if (redis) await redis.ping();
  res.json({ status: 'ok' });
}));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'A server error occurred. Please try again.' });
});

async function start() {
  await setupDatabase();
  if (redis) await redis.connect();
  app.listen(port, '0.0.0.0', () => console.log(`Secure login demo listening on port ${port}`));
}
start().catch(error => { console.error('Startup failed:', error.message); process.exit(1); });

process.on('SIGTERM', async () => { await pool.end(); if (redis) await redis.quit().catch(() => {}); process.exit(0); });
