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

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'none';");
  next();
});

// ── Data layer ──
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(filename) {
  const fp = path.join(DATA_DIR, filename);
  try { if (fs.existsSync(fp)) return JSON.parse(fs.readFileSync(fp, 'utf-8')); } catch (e) { console.error('read error', filename, e.message); }
  return null;
}

function writeJSON(filename, data) {
  const fp = path.join(DATA_DIR, filename);
  const tmp = fp + '.tmp.' + Date.now();
  try { fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8'); fs.renameSync(tmp, fp); return true; }
  catch (e) { console.error('write error', filename, e.message); try { fs.unlinkSync(tmp); } catch (_) {} return false; }
}

function audit(action, detail) {
  console.log(`[AUDIT ${new Date().toISOString()}] ${action} — ${detail}`);
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
  return `${salt}:${crypto.scryptSync(password, salt, KEY_LEN).toString('hex')}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return password === stored;
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(password, salt, KEY_LEN).toString('hex') === hash;
}

// ── Sessions ──
const sessions = new Map();
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
  if (!session) return res.status(401).json({ error: 'Session expired' });
  req.session = session;
  next();
}

function roleRequired(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.session.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ── ID generators ──
const counters = {};
function nextId(prefix) {
  if (!counters[prefix]) counters[prefix] = 0;
  counters[prefix]++;
  return `${prefix}-${String(counters[prefix]).padStart(5, '0')}`;
}

// ── Seed data ──
// ── Seed accounts only (no demo data) ──
function initAccounts() {
  if (!readJSON('accounts.json')) {
    const accounts = {
      admin: { username: 'admin', password: hashPassword('admin123'), name: 'Super Admin', email: '' },
      users: [
        { username: 'sales.head', password: hashPassword('sales123'), role: 'sales_head', name: 'Rafiqul Islam', sbu: 'All', region: 'All', area: 'All', territory: 'All', email: '' },
        { username: 'nusrat.jahan', password: hashPassword('nusrat123'), role: 'so', name: 'Nusrat Jahan', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Gulshan', email: '' },
        { username: 'sadia.rahman', password: hashPassword('sadia123'), role: 'so', name: 'Sadia Rahman', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Dhanmondi', email: '' },
        { username: 'imran.kabir', password: hashPassword('imran123'), role: 'so', name: 'Imran Kabir', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Uttara', email: '' },
        { username: 'tanvir.ahmed', password: hashPassword('tanvir123'), role: 'so', name: 'Tanvir Ahmed', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Mirpur', email: '' },
        { username: 'farhana.akter', password: hashPassword('farhana123'), role: 'so', name: 'Farhana Akter', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Banani', email: '' },
        { username: 'shakil.ahmed', password: hashPassword('shakil123'), role: 'so', name: 'Shakil Ahmed', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Bashundhara', email: '' },
        { username: 'ruma.begum', password: hashPassword('ruma123'), role: 'so', name: 'Ruma Begum', sbu: 'Diagnostics', region: 'Dhaka', area: 'Dhaka South', territory: 'Motijheel', email: '' },
        { username: 'zahidul.islam', password: hashPassword('zahidul123'), role: 'so', name: 'Zahidul Islam', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka Outer', territory: 'Narayanganj', email: '' },
        { username: 'agent.01', password: hashPassword('agent123'), role: 'contact_center', name: 'Rasheda Begum', sbu: 'All', region: 'Dhaka', area: 'All', territory: 'All', email: '' },
        { username: 'auditor.01', password: hashPassword('audit123'), role: 'sales_excellence', name: 'Monir Hossain', sbu: 'All', region: 'All', area: 'All', territory: 'All', email: '' },
        { username: 'management', password: hashPassword('mgmt123'), role: 'management', name: 'Board View', sbu: 'All', region: 'All', area: 'All', territory: 'All', email: '' },
      ]
    };
    writeJSON('accounts.json', accounts);
  }
}
initAccounts();

// Wipe all data files except accounts on startup
const DATA_FILES = ['customers','leads','opportunities','visits','orders','complaints','contacts','activities','targets','callLogs','audits','competitors'];
for (const name of DATA_FILES) {
  writeJSON(`${name}.json`, []);
}

// ── Role hierarchy ──
const ROLE_HIERARCHY = {
  super_admin: ['All'],
  admin: ['All'],
  sales_head: ['dashboard', 'customers', 'leads', 'opportunities', 'visits', 'orders', 'reports'],
  rm: ['customers', 'visits', 'orders', 'reports'],
  am: ['customers', 'visits', 'orders'],
  tm: ['customers', 'visits', 'orders'],
  so: ['customers', 'leads', 'visits', 'orders'],
  contact_center: ['complaints', 'contact_center'],
  sales_excellence: ['sales_excellence', 'reports'],
  management: ['dashboard', 'reports'],
};

// ── Auth routes ──
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (rateLimit(ip, 10, 60000)) return res.status(429).json({ error: 'Too many attempts' });

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const accts = readJSON('accounts.json');
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });

  if (accts.admin && accts.admin.username === username) {
    if (!verifyPassword(password, accts.admin.password)) {
      audit('LOGIN_FAIL', `admin:${username}`);
      return res.status(401).json({ error: 'Incorrect username or password' });
    }
    const token = createSession({ role: 'super_admin', name: 'Super Admin', username, territory: 'All', region: 'All', area: 'All' });
    audit('LOGIN_OK', 'admin');
    return res.json({ token, user: { role: 'super_admin', name: 'Super Admin', username, territory: 'All', modules: ROLE_HIERARCHY.super_admin } });
  }

  const user = (accts.users || []).find(u => u.username === username);
  if (!user) {
    audit('LOGIN_FAIL', `unknown:${username}`);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  if (!verifyPassword(password, user.password)) {
    audit('LOGIN_FAIL', `${user.role}:${username}`);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  const token = createSession({ role: user.role, name: user.name, username: user.username, territory: user.territory, region: user.region, area: user.area, sbu: user.sbu });
  audit('LOGIN_OK', `${user.role}:${username}`);
  return res.json({ token, user: { role: user.role, name: user.name, username: user.username, territory: user.territory, region: user.region, area: user.area, sbu: user.sbu, modules: ROLE_HIERARCHY[user.role] || [] } });
});

app.post('/api/logout', authRequired, (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  sessions.delete(token);
  res.json({ success: true });
});

app.get('/api/session', authRequired, (req, res) => {
  res.json({ user: { role: req.session.role, name: req.session.name, username: req.session.username, territory: req.session.territory, region: req.session.region, area: req.session.area, sbu: req.session.sbu, modules: ROLE_HIERARCHY[req.session.role] || [] } });
});

// ── Dashboard stats ──
app.get('/api/dashboard/stats', authRequired, (req, res) => {
  const customers = readJSON('customers.json') || [];
  const leads = readJSON('leads.json') || [];
  const opportunities = readJSON('opportunities.json') || [];
  const orders = readJSON('orders.json') || [];
  const complaints = readJSON('complaints.json') || [];
  const visits = readJSON('visits.json') || [];

  const totalCustomers = customers.length;
  const activeCustomers = customers.filter(c => c.status === 'Active').length;
  const inactiveCustomers = customers.filter(c => c.status === 'Inactive').length;
  const newCustomersThisMonth = customers.filter(c => {
    const d = new Date(c.createdAt);
    const now = new Date();
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length;

  const totalLeads = leads.length;
  const openLeads = leads.filter(l => l.status === 'New' || l.status === 'Qualified').length;
  const convertedLeads = leads.filter(l => l.status === 'Converted').length;
  const lostLeads = leads.filter(l => l.status === 'Lost').length;

  const totalOpportunities = opportunities.length;
  const openOpportunities = opportunities.filter(o => o.stage !== 'Closed-Won' && o.stage !== 'Closed-Lost').length;
  const wonOpportunities = opportunities.filter(o => o.stage === 'Closed-Won').length;
  const pipelineValue = opportunities.reduce((sum, o) => o.stage !== 'Closed-Lost' ? sum + (o.expectedValue * o.probability / 100) : sum, 0);

  const totalOrders = orders.length;
  const pendingOrders = orders.filter(o => o.status === 'Pending').length;
  const totalSales = orders.filter(o => o.status === 'Delivered').reduce((sum, o) => sum + o.totalAmount, 0);
  const outstanding = orders.filter(o => o.status === 'Pending' || o.status === 'Approved' || o.status === 'Dispatched').reduce((sum, o) => sum + o.totalAmount, 0);

  const totalComplaints = complaints.length;
  const openComplaints = complaints.filter(c => c.status === 'Open' || c.status === 'In Progress').length;
  const resolvedComplaints = complaints.filter(c => c.status === 'Resolved' || c.status === 'Closed').length;
  const avgCsat = complaints.filter(c => c.csat).reduce((sum, c) => sum + c.csat, 0) / (complaints.filter(c => c.csat).length || 1);

  const totalVisits = visits.length;
  const visitsThisMonth = visits.filter(v => {
    const d = new Date(v.createdAt);
    const now = new Date();
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length;
  const followUpDue = leads.filter(l => l.status !== 'Converted' && l.status !== 'Lost' && l.followUpDate && new Date(l.followUpDate) <= new Date(Date.now() + 3 * 86400000)).length;

  const salespeople = [...new Set(customers.map(c => c.salesperson))];
  const targets = readJSON('targets.json') || [];
  const currentMonth = new Date().toISOString().slice(0, 7);
  const spPerformance = salespeople.map(sp => {
    const spCustomers = customers.filter(c => c.salesperson === sp);
    const spVisits = visits.filter(v => spCustomers.some(c => c.id === v.customerId));
    const spOrders = orders.filter(o => spCustomers.some(c => c.id === o.customerId) && o.status === 'Delivered');
    const achievedSales = spOrders.reduce((s, o) => s + o.totalAmount, 0);
    const spTarget = targets.find(t => t.salesperson === sp && t.month === currentMonth);
    const targetSales = spTarget ? spTarget.targetSales : 0;
    const targetVisits = spTarget ? spTarget.targetVisits : 0;
    const pctAchievement = targetSales > 0 ? Math.round((achievedSales / targetSales) * 100) : 0;

    let aiSuggestion = '';
    if (targetSales > 0) {
      if (pctAchievement >= 110) aiSuggestion = 'Top performer — recommend territory expansion or team leadership role.';
      else if (pctAchievement >= 90) aiSuggestion = 'On track — sustain current strategy, upsell existing customers.';
      else if (pctAchievement >= 70) aiSuggestion = 'Close to target — prioritize high-value leads and increase follow-up frequency.';
      else if (pctAchievement >= 50) aiSuggestion = 'Behind target — increase daily visits, re-engage dormant customers, request marketing support.';
      else aiSuggestion = 'Critical gap — schedule coaching session, review territory assignment, consider reallocation.';
    } else {
      aiSuggestion = 'No target set — assign targets from Admin Panel.';
    }

    return {
      name: sp,
      customers: spCustomers.length,
      visits: spVisits.length,
      targetVisits,
      achievedSales,
      targetSales,
      pctAchievement,
      aiSuggestion
    };
  }).sort((a, b) => b.pctAchievement - a.pctAchievement);

  res.json({
    customers: { total: totalCustomers, active: activeCustomers, inactive: inactiveCustomers, newThisMonth: newCustomersThisMonth },
    leads: { total: totalLeads, open: openLeads, converted: convertedLeads, lost: lostLeads, followUpDue },
    opportunities: { total: totalOpportunities, open: openOpportunities, won: wonOpportunities, pipelineValue },
    orders: { total: totalOrders, pending: pendingOrders, totalSales, outstanding },
    complaints: { total: totalComplaints, open: openComplaints, resolved: resolvedComplaints, avgCsat: +avgCsat.toFixed(1) },
    visits: { total: totalVisits, thisMonth: visitsThisMonth },
    spPerformance
  });
});

// ── Generic CRUD helper ──
function crudRoutes(entityName, routePath) {
  app.get(`/api/${routePath}`, authRequired, (req, res) => {
    const data = readJSON(`${entityName}.json`) || [];
    res.json(data);
  });

  app.post(`/api/${routePath}`, authRequired, (req, res) => {
    const data = readJSON(`${entityName}.json`) || [];
    const prefix = entityName === 'customers' ? 'CUS' : entityName === 'leads' ? 'LEAD' : entityName === 'opportunities' ? 'OPP' : entityName === 'visits' ? 'VIS' : entityName === 'orders' ? 'ORD' : entityName === 'complaints' ? 'CMP' : entityName === 'contacts' ? 'CONT' : entityName === 'callLogs' ? 'CALL' : entityName === 'audits' ? 'AUD' : entityName === 'competitors' ? 'COMP' : 'ACT';
    const newItem = { id: nextId(prefix), ...req.body, createdAt: new Date().toISOString().slice(0, 10), updatedAt: new Date().toISOString().slice(0, 10) };
    data.push(newItem);
    writeJSON(`${entityName}.json`, data);
    audit('CREATE', `${req.session.username} created ${entityName} ${newItem.id}`);
    res.json(newItem);
  });

  app.put(`/api/${routePath}/:id`, authRequired, (req, res) => {
    const data = readJSON(`${entityName}.json`) || [];
    const idx = data.findIndex(d => d.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    data[idx] = { ...data[idx], ...req.body, id: data[idx].id, updatedAt: new Date().toISOString().slice(0, 10) };
    writeJSON(`${entityName}.json`, data);
    audit('UPDATE', `${req.session.username} updated ${entityName} ${data[idx].id}`);
    res.json(data[idx]);
  });

  app.delete(`/api/${routePath}/:id`, authRequired, (req, res) => {
    const data = readJSON(`${entityName}.json`) || [];
    const idx = data.findIndex(d => d.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const removed = data.splice(idx, 1)[0];
    writeJSON(`${entityName}.json`, data);
    audit('DELETE', `${req.session.username} deleted ${entityName} ${removed.id}`);
    res.json({ success: true });
  });
}

crudRoutes('customers', 'customers');
crudRoutes('leads', 'leads');
crudRoutes('opportunities', 'opportunities');
crudRoutes('visits', 'visits');
crudRoutes('orders', 'orders');
crudRoutes('complaints', 'complaints');
crudRoutes('contacts', 'contacts');
crudRoutes('activities', 'activities');
crudRoutes('callLogs', 'callLogs');
crudRoutes('audits', 'audits');
crudRoutes('competitors', 'competitors');

// ── Customer 360 ──
app.get('/api/customer/:id/360', authRequired, (req, res) => {
  const customerId = req.params.id;
  const customers = readJSON('customers.json') || [];
  const customer = customers.find(c => c.id === customerId);
  if (!customer) return res.status(404).json({ error: 'Customer not found' });

  const contacts = (readJSON('contacts.json') || []).filter(c => c.customerId === customerId);
  const leads = (readJSON('leads.json') || []).filter(l => l.customerId === customerId);
  const opportunities = (readJSON('opportunities.json') || []).filter(o => o.customerId === customerId);
  const visits = (readJSON('visits.json') || []).filter(v => v.customerId === customerId);
  const orders = (readJSON('orders.json') || []).filter(o => o.customerId === customerId);
  const complaints = (readJSON('complaints.json') || []).filter(c => c.customerId === customerId);
  const activities = (readJSON('activities.json') || []).filter(a => a.customerId === customerId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({ customer, contacts, leads, opportunities, visits, orders, complaints, activities });
});

// ── Accounts management (admin only) ──
app.get('/api/accounts', authRequired, (req, res) => {
  const accts = readJSON('accounts.json');
  if (!accts) return res.json([]);
  const safe = { admin: { ...accts.admin, password: undefined }, users: (accts.users || []).map(u => ({ ...u, password: undefined })) };
  res.json(safe);
});

app.post('/api/accounts', authRequired, roleRequired('super_admin'), (req, res) => {
  const accts = readJSON('accounts.json');
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });
  const { username, password, role, name, sbu, region, area, territory, email } = req.body;
  if (!username || !password || !role || !name) return res.status(400).json({ error: 'Required fields missing' });
  if ((accts.users || []).some(u => u.username === username)) return res.status(409).json({ error: 'Username exists' });
  accts.users = accts.users || [];
  accts.users.push({ username, password: hashPassword(password), role, name, sbu: sbu || 'All', region: region || 'All', area: area || 'All', territory: territory || 'All', email: email || '' });
  writeJSON('accounts.json', accts);
  res.json({ success: true, user: { username, role, name } });
});

app.put('/api/accounts/:username', authRequired, roleRequired('super_admin', 'admin', 'sales_head'), (req, res) => {
  const accts = readJSON('accounts.json');
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });
  const idx = (accts.users || []).findIndex(u => u.username === req.params.username);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  accts.users[idx] = { ...accts.users[idx], ...req.body };
  if (req.body.password) accts.users[idx].password = hashPassword(req.body.password);
  writeJSON('accounts.json', accts);
  res.json({ success: true });
});

app.delete('/api/accounts/:username', authRequired, roleRequired('super_admin'), (req, res) => {
  const accts = readJSON('accounts.json');
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });
  accts.users = (accts.users || []).filter(u => u.username !== req.params.username);
  writeJSON('accounts.json', accts);
  res.json({ success: true });
});

app.post('/api/change-password', authRequired, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const accts = readJSON('accounts.json');
  if (!accts) return res.status(500).json({ error: 'Account store not initialized' });

  if (req.session.role === 'super_admin') {
    if (!verifyPassword(currentPassword, accts.admin.password)) return res.status(401).json({ error: 'Current password incorrect' });
    accts.admin.password = hashPassword(newPassword);
  } else {
    const user = (accts.users || []).find(u => u.username === req.session.username);
    if (!user || !verifyPassword(currentPassword, user.password)) return res.status(401).json({ error: 'Current password incorrect' });
    user.password = hashPassword(newPassword);
  }
  writeJSON('accounts.json', accts);
  res.json({ success: true });
});

// ── Catch-all → HTML ──
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`AKIJ CRM running at http://localhost:${PORT}`);
});
