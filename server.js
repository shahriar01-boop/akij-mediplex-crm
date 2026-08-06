const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const SALT_LEN = 16;
const KEY_LEN = 64;
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Security headers ──
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'none';");
  next();
});

// ── Data layer ──
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readData(filename) {
  const fp = path.join(DATA_DIR, filename);
  try { if (fs.existsSync(fp)) return fs.readFileSync(fp, 'utf-8'); } catch (e) { console.error('read error', filename, e.message); }
  return null;
}

function writeData(filename, value) {
  const fp = path.join(DATA_DIR, filename);
  const tmp = fp + '.tmp.' + Date.now();
  try { fs.writeFileSync(tmp, value, 'utf-8'); fs.renameSync(tmp, fp); return true; }
  catch (e) { console.error('write error', filename, e.message); try { fs.unlinkSync(tmp); } catch (_) {} return false; }
}

function audit(action, detail) {
  const ts = new Date().toISOString();
  console.log(`[AUDIT ${ts}] ${action} — ${detail}`);
}

// ── Rate limiting ──
const rateLimitMap = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const entry = rateLimitMap.get(key) || { count: 0, reset: now + windowMs };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
  entry.count++;
  rateLimitMap.set(key, entry);
  return entry.count > max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitMap) { if (now > v.reset) rateLimitMap.delete(k); }
}, 60000);

// ── Password hashing ──
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(SALT_LEN).toString('hex');
  const hash = crypto.scryptSync(password, salt, KEY_LEN).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return password === stored; // legacy plaintext
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(password, salt, KEY_LEN).toString('hex') === hash;
}

// ── Session tokens ──
const sessions = new Map(); // token → { username, role, name, territory, expires }
function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function createSession(user) {
  const token = generateToken();
  sessions.set(token, { ...user, expires: Date.now() + TOKEN_EXPIRY_MS });
  return token;
}
function validateSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(token); return null; }
  return s;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) { if (now > s.expires) sessions.delete(k); }
}, 300000);

// ── Auth middleware ──
function authRequired(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  const session = validateSession(token);
  if (!session) return res.status(401).json({ error: 'Session expired or invalid' });
  req.session = session;
  next();
}

// ── Sanitize accounts (strip passwords) ──
function sanitizeAccounts(accts) {
  if (!accts) return null;
  const safe = JSON.parse(JSON.stringify(accts));
  if (safe.admin) { safe.admin = { ...safe.admin }; delete safe.admin.password; }
  safe.hpos = (safe.hpos || []).map(h => {
    const s = { ...h }; delete s.password; return s;
  });
  return safe;
}

function loadAccounts() {
  const raw = readData('accounts.json');
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

function saveAccounts(accts) {
  return writeData('accounts.json', JSON.stringify(accts));
}

// Migrate legacy plaintext passwords to hashed on startup
function migrateAccountsPasswords() {
  const accts = loadAccounts();
  if (!accts) return;
  let changed = false;
  if (accts.admin && accts.admin.password && !accts.admin.password.includes(':')) {
    accts.admin.password = hashPassword(accts.admin.password);
    changed = true;
  }
  if (accts.hpos) {
    for (const h of accts.hpos) {
      if (h.password && !h.password.includes(':')) {
        h.password = hashPassword(h.password);
        changed = true;
      }
    }
  }
  if (changed) { saveAccounts(accts); console.log('Migrated plaintext passwords to hashed'); }
}

// Run migration
migrateAccountsPasswords();

// ── API Routes ──

// POST /api/login
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (rateLimit(ip, 10, 60000)) return res.status(429).json({ error: 'Too many login attempts. Try again later.' });

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Invalid input' });
  if (username.length > 100 || password.length > 100) return res.status(400).json({ error: 'Invalid input' });

  const accts = loadAccounts();
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });

  if (accts.admin && accts.admin.username === username) {
    if (!verifyPassword(password, accts.admin.password)) {
      audit('LOGIN_FAIL', `admin:${username}`);
      return res.status(401).json({ error: 'Incorrect username or password' });
    }
    const token = createSession({ role: 'admin', name: 'Administrator', username, territory: 'All' });
    audit('LOGIN_OK', `admin`);
    return res.json({ token, user: { role: 'admin', name: 'Administrator', username, territory: 'All' } });
  }

  const hpo = (accts.hpos || []).find(h => h.username === username);
  if (!hpo) {
    audit('LOGIN_FAIL', `unknown:${username}`);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  if (!verifyPassword(password, hpo.password)) {
    audit('LOGIN_FAIL', `hpo:${username}`);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  const token = createSession({ role: 'hpo', name: hpo.name, username: hpo.username, territory: hpo.territory });
  audit('LOGIN_OK', `hpo:${username}`);
  return res.json({ token, user: { role: 'hpo', name: hpo.name, username: hpo.username, territory: hpo.territory } });
});

// POST /api/google-login
app.post('/api/google-login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (rateLimit(ip, 15, 60000)) return res.status(429).json({ error: 'Too many attempts' });

  const { email } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  if (email.length > 200) return res.status(400).json({ error: 'Invalid input' });

  const accts = loadAccounts();
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });

  const emailLower = email.toLowerCase();
  if (accts.admin && accts.admin.email && accts.admin.email.toLowerCase() === emailLower) {
    const token = createSession({ role: 'admin', name: 'Administrator', username: accts.admin.username, territory: 'All' });
    audit('GOOGLE_LOGIN', `admin:${email}`);
    return res.json({ token, user: { role: 'admin', name: 'Administrator', username: accts.admin.username, territory: 'All' } });
  }

  const hpo = (accts.hpos || []).find(h => h.email && h.email.toLowerCase() === emailLower);
  if (hpo) {
    const token = createSession({ role: 'hpo', name: hpo.name, username: hpo.username, territory: hpo.territory });
    audit('GOOGLE_LOGIN', `hpo:${email}`);
    return res.json({ token, user: { role: 'hpo', name: hpo.name, username: hpo.username, territory: hpo.territory } });
  }

  const displayName = email.split('@')[0].replace(/[^a-zA-Z]/g, ' ').replace(/\s+/g, ' ').trim() || email;
  const name = displayName.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  const token = createSession({ role: 'hpo', name, username: email, territory: 'Guest — ' + email });
  audit('GOOGLE_LOGIN', `guest:${email}`);
  return res.json({ token, user: { role: 'hpo', name, username: email, territory: 'Guest — ' + email } });
});

// POST /api/logout
app.post('/api/logout', authRequired, (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  sessions.delete(token);
  audit('LOGOUT', req.session.username);
  res.json({ success: true });
});

// GET endpoints — public reads (no auth for read access to data)
app.get('/api/doctors', (_req, res) => {
  const data = readData('doctors.json');
  res.json({ value: data || null });
});

app.get('/api/pharmacies', (_req, res) => {
  const data = readData('pharmacies.json');
  res.json({ value: data || null });
});

app.get('/api/accounts', (_req, res) => {
  const accts = loadAccounts();
  const safe = sanitizeAccounts(accts);
  res.json({ value: safe ? JSON.stringify(safe) : null });
});

app.get('/api/visitlogs', (_req, res) => {
  const data = readData('visitlogs.json');
  res.json({ value: data || null });
});

// PUT endpoints — require auth
app.put('/api/doctors', authRequired, (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  try { JSON.parse(value); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
  const ok = writeData('doctors.json', value);
  audit('WRITE', `${req.session.username} updated doctors`);
  res.json({ success: ok });
});

app.put('/api/pharmacies', authRequired, (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  try { JSON.parse(value); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
  const ok = writeData('pharmacies.json', value);
  audit('WRITE', `${req.session.username} updated pharmacies`);
  res.json({ success: ok });
});

app.put('/api/accounts', authRequired, (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  let accts;
  try { accts = JSON.parse(value); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
  // Re-hash any new/changed passwords
  if (accts.admin && accts.admin.password && !accts.admin.password.includes(':')) {
    accts.admin.password = hashPassword(accts.admin.password);
  }
  if (accts.hpos) {
    for (const h of accts.hpos) {
      if (h.password && !h.password.includes(':')) {
        h.password = hashPassword(h.password);
      }
    }
  }
  const ok = saveAccounts(accts);
  audit('WRITE', `${req.session.username} updated accounts`);
  res.json({ success: ok });
});

app.put('/api/visitlogs', authRequired, (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  try { JSON.parse(value); } catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
  const ok = writeData('visitlogs.json', value);
  audit('WRITE', `${req.session.username} updated visitlogs`);
  res.json({ success: ok });
});

// Admin-only: POST /api/hpo — create new HPO (admin only)
app.post('/api/hpo', authRequired, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, territory, email } = req.body;
  if (!name || typeof name !== 'string' || name.length > 100) return res.status(400).json({ error: 'Name required' });
  const username = name.toLowerCase().replace(/[^a-z]+/g, '.').replace(/^\.+|\.+$/g, '');
  const accts = loadAccounts();
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });
  if ((accts.hpos || []).some(h => h.username === username)) return res.status(409).json({ error: 'Username already exists' });

  const rawPw = crypto.randomBytes(5).toString('hex');
  const hashedPw = hashPassword(rawPw);
  accts.hpos = accts.hpos || [];
  accts.hpos.push({
    name, territory: territory || 'Unassigned', username, password: hashedPw,
    email: email || ''
  });
  saveAccounts(accts);
  audit('HPO_CREATE', `${req.session.username} created HPO: ${username}`);
  res.json({ success: true, hpo: { name, territory: territory || 'Unassigned', username, password: rawPw, email: email || '' } });
});

// Admin-only: DELETE /api/hpo/:index
app.delete('/api/hpo/:index', authRequired, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const idx = parseInt(req.params.index, 10);
  const accts = loadAccounts();
  if (!accts || !accts.hpos || idx < 0 || idx >= accts.hpos.length) return res.status(404).json({ error: 'HPO not found' });
  const removed = accts.hpos[idx];
  accts.hpos.splice(idx, 1);
  saveAccounts(accts);
  audit('HPO_REMOVE', `${req.session.username} removed HPO: ${removed.username}`);
  res.json({ success: true });
});

// POST /api/admin-email — set admin email (admin only)
app.post('/api/admin-email', authRequired, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { email } = req.body;
  const accts = loadAccounts();
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });
  accts.admin.email = (typeof email === 'string') ? email.trim() : '';
  saveAccounts(accts);
  res.json({ success: true });
});

// POST /api/reset — re-seed accounts with sample data (admin only)
app.post('/api/reset', authRequired, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const accts = {
    admin: { username: 'admin', password: hashPassword('uHoHKubDKpPK'), email: '' },
    hpos: [
      {name:"Tanvir Ahmed",   territory:"Mirpur",       username:"tanvir.ahmed",    password: hashPassword("nB7Kw4P7RB")},
      {name:"Sadia Rahman",   territory:"Dhanmondi",    username:"sadia.rahman",    password: hashPassword("kfMMvy5UG3")},
      {name:"Imran Kabir",    territory:"Uttara",       username:"imran.kabir",     password: hashPassword("sf8xq4DfZh")},
      {name:"Nusrat Jahan",   territory:"Gulshan",      username:"nusrat.jahan",    password: hashPassword("ECmu8kDL2v")},
      {name:"Mahfuzur Rahman",territory:"Mohammadpur",  username:"mahfuzur.rahman", password: hashPassword("DtTPuice9b")},
      {name:"Farhana Akter",  territory:"Banani",       username:"farhana.akter",   password: hashPassword("UYmxxtU6hQ")},
      {name:"Shakil Ahmed",   territory:"Bashundhara",  username:"shakil.ahmed",    password: hashPassword("7Lr5GyFhzU")},
      {name:"Ruma Begum",     territory:"Motijheel",    username:"ruma.begum",      password: hashPassword("e8Cvc2fLPR")},
      {name:"Kamrul Hasan",   territory:"Farmgate",     username:"kamrul.hasan",    password: hashPassword("MhraPmbYMp")},
      {name:"Taslima Khatun", territory:"Wari",         username:"taslima.khatun",  password: hashPassword("7m65WMdiqu")},
      {name:"Jubayer Islam",  territory:"Khilgaon",     username:"jubayer.islam",   password: hashPassword("CyzpPK3cNH")},
      {name:"Sharmin Sultana",territory:"Rampura",      username:"sharmin.sultana", password: hashPassword("dhLzG7uqvF")},
      {name:"Abdul Mannan",   territory:"Tejgaon",      username:"abdul.mannan",    password: hashPassword("uyYi4EiQNj")},
      {name:"Rima Akter",     territory:"Savar",        username:"rima.akter",      password: hashPassword("PENTxMbTaG")},
      {name:"Zahidul Islam",  territory:"Narayanganj",  username:"zahidul.islam",   password: hashPassword("bHXkGBBpnU")},
    ]
  };
  saveAccounts(accts);
  audit('RESET', 'Sample accounts restored by ' + req.session.username);
  res.json({ success: true, accounts: sanitizeAccounts(accts) });
});
// POST /api/change-password
app.post('/api/change-password', authRequired, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  if (newPassword.length > 100) return res.status(400).json({ error: 'Password too long' });

  const accts = loadAccounts();
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });

  if (req.session.role === 'admin') {
    if (!verifyPassword(currentPassword, accts.admin.password)) return res.status(401).json({ error: 'Current password is incorrect' });
    accts.admin.password = hashPassword(newPassword);
  } else {
    const hpo = (accts.hpos || []).find(h => h.username === req.session.username);
    if (!hpo || !verifyPassword(currentPassword, hpo.password)) return res.status(401).json({ error: 'Current password is incorrect' });
    hpo.password = hashPassword(newPassword);
  }
  saveAccounts(accts);
  audit('PASSWORD_CHANGE', req.session.username);
  res.json({ success: true });
});

// Catch-all → serve HTML
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'akij_mediplex_crm.html'));
});

app.listen(PORT, () => {
  console.log(`AKIJ Mediplex CRM running at http://localhost:${PORT}`);
});
