const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue, Timestamp } = require('firebase-admin/firestore');
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
const sessionSecret = process.env.SESSION_SECRET;
const totpEncryptionKey = process.env.TOTP_ENCRYPTION_KEY;

if (!sessionSecret || sessionSecret.length < 32) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters.');
if (!totpEncryptionKey || totpEncryptionKey.length < 32) throw new Error('Set TOTP_ENCRYPTION_KEY to a random value of at least 32 characters.');
if (isProduction && !process.env.REDIS_URL) throw new Error('REDIS_URL is required in production for shared rate limits.');

function readServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64) {
    return JSON.parse(Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64, 'base64').toString('utf8'));
  }
  const credentialPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (credentialPath) return JSON.parse(fs.readFileSync(path.resolve(credentialPath), 'utf8').replace(/^\uFEFF/, ''));
  throw new Error('Set GOOGLE_APPLICATION_CREDENTIALS to a Firebase service-account JSON file path.');
}
const serviceAccount = readServiceAccount();
if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) throw new Error('Firebase service-account JSON is missing required fields.');
const firebaseApp = initializeApp({ credential: cert(serviceAccount), projectId: serviceAccount.project_id });
const db = getFirestore(firebaseApp);
const users = db.collection('appUsers');
const sessions = db.collection('appSessions');
const resets = db.collection('passwordResets');
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: true }) : null;

class FirestoreSessionStore extends session.Store {
  get(sid, callback) {
    sessions.doc(sid).get().then(async snapshot => {
      if (!snapshot.exists) return callback(null, null);
      const data = snapshot.data();
      if (!data.expiresAt || data.expiresAt.toMillis() <= Date.now()) {
        await snapshot.ref.delete();
        return callback(null, null);
      }
      callback(null, data.session);
    }).catch(callback);
  }
  set(sid, sessionData, callback = () => {}) {
    const expires = sessionData.cookie?.expires ? new Date(sessionData.cookie.expires) : new Date(Date.now() + 30 * 60 * 1000);
    sessions.doc(sid).set({
      session: sessionData,
      userId: sessionData.userId || null,
      expiresAt: Timestamp.fromDate(expires),
      updatedAt: FieldValue.serverTimestamp()
    }).then(() => callback(null)).catch(callback);
  }
  touch(sid, sessionData, callback = () => {}) { this.set(sid, sessionData, callback); }
  destroy(sid, callback = () => {}) { sessions.doc(sid).delete().then(() => callback(null)).catch(callback); }
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '12kb', strict: true }));
app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: isProduction ? '1h' : 0 }));
app.use(session({
  store: new FirestoreSessionStore(),
  name: 'itc.sid', secret: sessionSecret, resave: false, saveUninitialized: false, rolling: true,
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
const userIdFor = email => crypto.createHash('sha256').update(email).digest('hex');
const safeEqual = (a, b) => { const aa = Buffer.from(a); const bb = Buffer.from(b); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); };
const invalidReset = 'This reset link is invalid or expired. Request a new one.';

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 256) return 'Use a password between 12 and 256 characters.';
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) return 'Include a lowercase letter, uppercase letter, and number.';
  return null;
}
function encryptSecret(value) {
  const key = crypto.createHash('sha256').update(totpEncryptionKey).digest(); const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map(x => x.toString('base64url')).join('.');
}
function decryptSecret(value) {
  const [iv, tag, body] = value.split('.').map(x => Buffer.from(x, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(totpEncryptionKey).digest(), iv); decipher.setAuthTag(tag);
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
function isValidReset(snapshot, userData) {
  if (!snapshot.exists || !snapshot.data().expiresAt || snapshot.data().usedAt) return false;
  return snapshot.data().expiresAt.toMillis() > Date.now() && snapshot.data().passwordVersion === Number(userData.passwordVersion || 0);
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

const requireAuth = asyncRoute(async (req, res, next) => {
  if (!req.session.userId || req.session.mfaPending) return res.status(401).json({ error: 'Complete sign-in to continue.' });
  const user = await users.doc(req.session.userId).get();
  if (!user.exists || Number(user.data().sessionVersion || 0) !== Number(req.session.authVersion || 0)) {
    await new Promise(resolve => req.session.destroy(() => resolve()));
    return res.status(401).json({ error: 'Your session expired. Sign in again.' });
  }
  next();
});

app.post('/api/register', signupLimiter, asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email); const password = req.body.password; const issue = validatePassword(password);
  if (!emailPattern.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (issue) return res.status(400).json({ error: issue });
  const id = userIdFor(email); const ref = users.doc(id);
  const hash = await argon2.hash(password, passwordHashOptions);
  const user = { email, passwordHash: hash, totpSecretEnc: null, sessionVersion: 0, passwordVersion: 0, createdAt: FieldValue.serverTimestamp(), passwordChangedAt: FieldValue.serverTimestamp() };
  try { await ref.create(user); }
  catch (error) { if (error.code === 6 || error.code === 'already-exists') return res.status(409).json({ error: 'An account with that email already exists. Sign in instead.' }); throw error; }
  await loginSession(req, id, { email, sessionVersion: 0, totpSecretEnc: null });
  res.status(201).json({ user: { email, mfaEnabled: false } });
}));

async function loginSession(req, userId, user) {
  await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
  req.session.userId = userId;
  req.session.userEmail = user.email;
  req.session.authVersion = Number(user.sessionVersion || 0);
  req.session.mfaPending = Boolean(user.totpSecretEnc);
  req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
}

app.post('/api/login', loginLimiter, asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email); const validEmail = emailPattern.test(email) && email.length <= 254;
  const ref = validEmail ? users.doc(userIdFor(email)) : null;
  const snapshot = ref ? await ref.get() : null;
  const user = snapshot?.exists ? snapshot.data() : null;
  const hash = user?.passwordHash || await dummyHashPromise;
  let ok = false;
  try { ok = await argon2.verify(hash, String(req.body.password || '')); } catch {}
  if (!user || !ok) {
    if (redis && validEmail) {
      const accountKey = `login-account:${crypto.createHash('sha256').update(`${email}:${req.ip}`).digest('hex')}`;
      const attempts = await redis.incr(accountKey);
      if (attempts === 1) await redis.expire(accountKey, 15 * 60);
      if (attempts >= 5) return res.status(429).json({ error: 'Too many attempts for this account. Try again later.' });
    }
    return genericAuthError(res);
  }
  if (redis) await redis.del(`login-account:${crypto.createHash('sha256').update(`${email}:${req.ip}`).digest('hex')}`);
  await loginSession(req, ref.id, user);
  if (user.totpSecretEnc) return res.json({ mfaRequired: true });
  res.json({ user: { email: user.email, mfaEnabled: false } });
}));
app.post('/api/login/mfa', loginLimiter, asyncRoute(async (req, res) => {
  if (!req.session.mfaPending || !req.session.userId) return genericAuthError(res);
  const user = await users.doc(req.session.userId).get();
  if (!user.exists || Number(user.data().sessionVersion || 0) !== Number(req.session.authVersion || 0) || !verifyTotp(decryptSecret(user.data().totpSecretEnc), req.body.code)) return genericAuthError(res);
  req.session.mfaPending = false;
  req.session.userEmail = user.data().email;
  res.json({ user: { email: user.data().email, mfaEnabled: true } });
}));

app.get('/api/me', asyncRoute(async (req, res) => {
  if (!req.session.userId || req.session.mfaPending) return res.json({ user: null });
  const snapshot = await users.doc(req.session.userId).get();
  if (!snapshot.exists || Number(snapshot.data().sessionVersion || 0) !== Number(req.session.authVersion || 0)) return res.json({ user: null });
  const user = snapshot.data();
  res.json({ user: { email: user.email, mfaEnabled: Boolean(user.totpSecretEnc), createdAt: user.createdAt?.toDate?.() || null } });
}));

app.post('/api/logout', asyncRoute(async (req, res) => {
  await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
  res.clearCookie('itc.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax' }).json({ ok: true });
}));

app.post('/api/mfa/setup', requireAuth, asyncRoute(async (req, res) => {
  const ref = users.doc(req.session.userId); const user = (await ref.get()).data();
  if (user.totpSecretEnc) return res.status(409).json({ error: 'Authenticator MFA is already enabled.' });
  const secretValue = base32Encode(crypto.randomBytes(20)); req.session.pendingTotp = secretValue;
  const label = encodeURIComponent(`ITC Login:${user.email}`);
  res.json({ secret: secretValue, otpauth: `otpauth://totp/${label}?secret=${secretValue}&issuer=ITC%20Secure%20Login&algorithm=SHA1&digits=6&period=30` });
}));
app.post('/api/mfa/enable', requireAuth, asyncRoute(async (req, res) => {
  const secretValue = req.session.pendingTotp;
  if (!secretValue || !verifyTotp(secretValue, req.body.code)) return res.status(400).json({ error: 'Code did not match. Try the current code in your authenticator.' });
  await users.doc(req.session.userId).update({ totpSecretEnc: encryptSecret(secretValue) });
  delete req.session.pendingTotp;
  res.json({ ok: true });
}));
app.post('/api/mfa/disable', requireAuth, asyncRoute(async (req, res) => {
  const ref = users.doc(req.session.userId); const snapshot = await ref.get(); const user = snapshot.data();
  if (!user?.totpSecretEnc || !verifyTotp(decryptSecret(user.totpSecretEnc), req.body.code)) return res.status(400).json({ error: 'Authenticator code is incorrect.' });
  await ref.update({ totpSecretEnc: null });
  res.json({ ok: true });
}));

async function revokeUserSessions(userId) {
  while (true) {
    const batch = db.batch();
    const snapshot = await sessions.where('userId', '==', userId).limit(400).get();
    if (snapshot.empty) return;
    snapshot.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
    if (snapshot.size < 400) return;
  }
}
async function pruneExpiredSessions() {
  const snapshot = await sessions.where('expiresAt', '<=', Timestamp.now()).limit(400).get();
  if (snapshot.empty) return;
  const batch = db.batch(); snapshot.docs.forEach(doc => batch.delete(doc.ref)); await batch.commit();
}

app.post('/api/forgot', recoveryLimiter, asyncRoute(async (req, res) => {
  const generic = { message: 'If an account exists for that email, password reset instructions will be sent.' };
  const email = normalizeEmail(req.body.email);
  if (!emailPattern.test(email) || !process.env.RESEND_API_KEY || !process.env.MAIL_FROM) return res.json(generic);
  const id = userIdFor(email); const userRef = users.doc(id); const userSnapshot = await userRef.get();
  if (!userSnapshot.exists) return res.json(generic);
  const token = crypto.randomBytes(32).toString('base64url'); const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const user = userSnapshot.data();
  await resets.doc(tokenHash).create({ userId: id, passwordVersion: Number(user.passwordVersion || 0), expiresAt: Timestamp.fromMillis(Date.now() + 15 * 60 * 1000), usedAt: null, createdAt: FieldValue.serverTimestamp() });
  const origin = process.env.APP_ORIGIN || `${req.protocol}://${req.get('host')}`;
  try {
    const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: process.env.MAIL_FROM, to: [email], subject: 'Reset your secure login password', text: `Use this one-time link within 15 minutes:\n\n${origin}/?reset=${encodeURIComponent(token)}\n\nIf you did not request this, ignore this email.` }) });
    if (!response.ok) throw new Error(`Email provider returned ${response.status}`);
  } catch (error) { await resets.doc(tokenHash).update({ usedAt: Timestamp.now() }); throw error; }
  res.json(generic);
}));
app.post('/api/reset', recoveryLimiter, asyncRoute(async (req, res) => {
  const token = String(req.body.token || ''); const password = req.body.password; const issue = validatePassword(password);
  if (issue) return res.status(400).json({ error: issue });
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return res.status(400).json({ error: invalidReset });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex'); const resetRef = resets.doc(tokenHash); const reset = await resetRef.get();
  if (!reset.exists) return res.status(400).json({ error: invalidReset });
  const resetData = reset.data(); const userRef = users.doc(resetData.userId); const userSnapshot = await userRef.get();
  if (!userSnapshot.exists || !isValidReset(reset, userSnapshot.data())) return res.status(400).json({ error: invalidReset });
  const passwordHash = await argon2.hash(password, passwordHashOptions);
  const changed = await db.runTransaction(async transaction => {
    const currentReset = await transaction.get(resetRef); const currentUser = await transaction.get(userRef);
    if (!currentUser.exists || !isValidReset(currentReset, currentUser.data())) return false;
    transaction.update(userRef, { passwordHash, passwordChangedAt: FieldValue.serverTimestamp(), passwordVersion: FieldValue.increment(1), sessionVersion: FieldValue.increment(1) });
    transaction.update(resetRef, { usedAt: Timestamp.now() });
    return true;
  });
  if (!changed) return res.status(400).json({ error: invalidReset });
  await revokeUserSessions(resetData.userId);
  res.json({ message: 'Password changed. Sign in with your new password.' });
}));

app.get('/healthz', asyncRoute(async (req, res) => {
  await users.limit(1).get();
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
  await users.limit(1).get();
  if (redis) await redis.connect();
  const cleanupTimer = setInterval(() => pruneExpiredSessions().catch(error => console.error('Session cleanup failed:', error.message)), 60 * 60 * 1000);
  cleanupTimer.unref();
  app.listen(port, '0.0.0.0', () => console.log(`Secure login demo listening on port ${port}`));
}
start().catch(error => { console.error('Startup failed:', error.message); process.exit(1); });
process.on('SIGTERM', async () => { if (redis) await redis.quit().catch(() => {}); process.exit(0); });
