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
function seedIfEmpty() {
  if (!readJSON('customers.json')) {
    const customers = [
      { id: 'CUS-00001', type: 'Individual', name: 'Dr. Abdur Rahman', category: 'Doctor', specialty: 'Cardiologist', phone: '01711234567', email: 'dr.rahman@email.com', address: 'House 12, Road 5, Gulshan-1', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Gulshan', salesperson: 'Nusrat Jahan', status: 'Active', createdAt: '2026-01-15', updatedAt: '2026-08-01' },
      { id: 'CUS-00002', type: 'Individual', name: 'Dr. Fatema Begum', category: 'Doctor', specialty: 'Gynecologist', phone: '01719876543', email: 'dr.fatema@email.com', address: '23 Dhanmondi R/A, Road 8', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Dhanmondi', salesperson: 'Sadia Rahman', status: 'Active', createdAt: '2026-02-10', updatedAt: '2026-07-28' },
      { id: 'CUS-00003', type: 'Individual', name: 'Dr. Kamal Hossain', category: 'Doctor', specialty: 'Neurologist', phone: '01715551234', email: 'dr.kamal@email.com', address: '45 Uttara Sector 7', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Uttara', salesperson: 'Imran Kabir', status: 'Active', createdAt: '2026-03-05', updatedAt: '2026-08-05' },
      { id: 'CUS-00004', type: 'Individual', name: 'Dr. Shirin Akhter', category: 'Doctor', specialty: 'Dermatologist', phone: '01717778899', email: null, address: 'Plot 8, Block B, Bashundhara R/A', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Bashundhara', salesperson: 'Shakil Ahmed', status: 'Active', createdAt: '2026-01-20', updatedAt: '2026-08-02' },
      { id: 'CUS-00005', type: 'Individual', name: 'Dr. Mahmudul Hasan', category: 'Doctor', specialty: 'Pediatrician', phone: '01716665544', email: null, address: '67 Mirpur Road, Mirpur-1', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Mirpur', salesperson: 'Tanvir Ahmed', status: 'Active', createdAt: '2026-04-12', updatedAt: '2026-07-30' },
      { id: 'CUS-00006', type: 'Business', name: 'MediCare Pharmacy', category: 'Pharmacy', specialty: null, phone: '01713334455', email: 'medicare@email.com', address: '12 Banani Road 11', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka North', territory: 'Banani', salesperson: 'Farhana Akter', status: 'Active', createdAt: '2026-02-01', updatedAt: '2026-08-06' },
      { id: 'CUS-00007', type: 'Business', name: 'HealthPlus Pharmacy', category: 'Pharmacy', specialty: null, phone: '01714445566', email: 'info@healthplus.com', address: '34 Mohammadpur Bus Stand', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Mohammadpur', salesperson: 'Mahfuzur Rahman', status: 'Active', createdAt: '2026-03-15', updatedAt: '2026-08-03' },
      { id: 'CUS-00008', type: 'Business', name: 'Popular Diagnostic Centre', category: 'Hospital', specialty: null, phone: '01712223344', email: 'admin@populardiagnostic.com', address: '56 Motijheel C/A', sbu: 'Diagnostics', region: 'Dhaka', area: 'Dhaka South', territory: 'Motijheel', salesperson: 'Ruma Begum', status: 'Active', createdAt: '2026-01-10', updatedAt: '2026-07-25' },
      { id: 'CUS-00009', type: 'Individual', name: 'Dr. Rezaul Karim', category: 'Doctor', specialty: 'Orthopedic', phone: '01718889900', email: null, address: '89 Farmgate, Tejgaon', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Farmgate', salesperson: 'Kamrul Hasan', status: 'Active', createdAt: '2026-05-20', updatedAt: '2026-08-04' },
      { id: 'CUS-00010', type: 'Business', name: 'Apon Pharmacy', category: 'Pharmacy', specialty: null, phone: '01719990011', email: 'apon@email.com', address: '22 Wari, Old Dhaka', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Wari', salesperson: 'Taslima Khatun', status: 'Active', createdAt: '2026-04-01', updatedAt: '2026-08-01' },
      { id: 'CUS-00011', type: 'Individual', name: 'Dr. Nasrin Sultana', category: 'Doctor', specialty: 'ENT', phone: '01711112233', email: 'dr.nasrin@email.com', address: '15 Khilgaon Rail Gate', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka East', territory: 'Khilgaon', salesperson: 'Jubayer Islam', status: 'Inactive', createdAt: '2026-02-28', updatedAt: '2026-07-15' },
      { id: 'CUS-00012', type: 'Business', name: 'Wellness Drug House', category: 'Distributor', specialty: null, phone: '01716667788', email: 'sales@wellness.com', address: '100 Tejgaon I/A', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka South', territory: 'Tejgaon', salesperson: 'Abdul Mannan', status: 'Active', createdAt: '2026-03-20', updatedAt: '2026-08-07' },
      { id: 'CUS-00013', type: 'Individual', name: 'Dr. Hasan Mahmud', category: 'Doctor', specialty: 'General Physician', phone: '01713335566', email: null, address: '78 Rampura Bazar', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka East', territory: 'Rampura', salesperson: 'Sharmin Sultana', status: 'Active', createdAt: '2026-06-01', updatedAt: '2026-08-08' },
      { id: 'CUS-00014', type: 'Business', name: 'Savar Health Clinic', category: 'Hospital', specialty: null, phone: '01714447788', email: 'savarclinic@email.com', address: 'Savar Bazar, Savar', sbu: 'Diagnostics', region: 'Dhaka', area: 'Dhaka Outer', territory: 'Savar', salesperson: 'Rima Akter', status: 'Active', createdAt: '2026-05-10', updatedAt: '2026-08-02' },
      { id: 'CUS-00015', type: 'Individual', name: 'Dr. Zahirul Islam', category: 'Doctor', specialty: 'Gastroenterologist', phone: '01715557788', email: null, address: '11 Narayanganj Bazar', sbu: 'Pharma', region: 'Dhaka', area: 'Dhaka Outer', territory: 'Narayanganj', salesperson: 'Zahidul Islam', status: 'Active', createdAt: '2026-04-25', updatedAt: '2026-08-05' },
    ];
    writeJSON('customers.json', customers);
    counters['CUS'] = 15;
  }

  if (!readJSON('leads.json')) {
    const leads = [
      { id: 'LEAD-00001', customerId: null, name: 'Dr. Anisur Rahman', source: 'Referral', product: 'Cardiology Range', status: 'New', assignedTo: 'Nusrat Jahan', notes: 'Referred by Dr. Abdur Rahman', lostReason: null, followUpDate: '2026-08-15', createdAt: '2026-08-01', updatedAt: '2026-08-01' },
      { id: 'LEAD-00002', customerId: null, name: 'Ibn Sina Hospital', source: 'Website', product: 'Full Diagnostic Line', status: 'Qualified', assignedTo: 'Imran Kabir', notes: 'Submitted inquiry via website', lostReason: null, followUpDate: '2026-08-12', createdAt: '2026-07-25', updatedAt: '2026-08-05' },
      { id: 'LEAD-00003', customerId: null, name: 'Dr. Selina Akhter', source: 'Walk-in', product: 'Gynecology Range', status: 'New', assignedTo: 'Sadia Rahman', notes: 'Visited office, requested samples', lostReason: null, followUpDate: '2026-08-14', createdAt: '2026-08-08', updatedAt: '2026-08-08' },
      { id: 'LEAD-00004', customerId: null, name: 'New Life Pharmacy', source: 'Cold Call', product: 'OTC Products', status: 'Lost', assignedTo: 'Farhana Akter', notes: 'Not interested at this time', lostReason: 'Competitor contract', followUpDate: '2026-09-01', createdAt: '2026-07-15', updatedAt: '2026-08-01' },
      { id: 'LEAD-00005', customerId: 'CUS-00001', name: 'Dr. Abdur Rahman (Expansion)', source: 'Existing Customer', product: 'Neurology Range', status: 'Converted', assignedTo: 'Nusrat Jahan', notes: 'Customer expanding product usage', lostReason: null, followUpDate: null, createdAt: '2026-06-20', updatedAt: '2026-08-09' },
    ];
    writeJSON('leads.json', leads);
    counters['LEAD'] = 5;
  }

  if (!readJSON('opportunities.json')) {
    const opportunities = [
      { id: 'OPP-00001', customerId: 'CUS-00001', name: 'Cardiology Supply Contract', product: 'Cardiology Range', expectedValue: 500000, probability: 70, stage: 'Proposal', closingDate: '2026-09-30', notes: 'Annual supply contract negotiation', createdAt: '2026-06-01', updatedAt: '2026-08-01' },
      { id: 'OPP-00002', customerId: 'CUS-00006', name: 'OTC Bulk Order', product: 'OTC Range', expectedValue: 300000, probability: 50, stage: 'Qualification', closingDate: '2026-08-30', notes: 'Pharmacy chain bulk purchase', createdAt: '2026-07-10', updatedAt: '2026-08-05' },
      { id: 'OPP-00003', customerId: 'CUS-00008', name: 'Diagnostic Equipment', product: 'Diagnostic Kits', expectedValue: 1200000, probability: 30, stage: 'Prospecting', closingDate: '2026-12-15', notes: 'New equipment procurement', createdAt: '2026-08-01', updatedAt: '2026-08-01' },
      { id: 'OPP-00004', customerId: 'CUS-00002', name: 'Gynecology Annual', product: 'Gynecology Range', expectedValue: 450000, probability: 85, stage: 'Negotiation', closingDate: '2026-09-15', notes: 'Final pricing discussion', createdAt: '2026-05-15', updatedAt: '2026-08-09' },
      { id: 'OPP-00005', customerId: 'CUS-00012', name: 'Distributor Expansion', product: 'Full Pharma Range', expectedValue: 800000, probability: 60, stage: 'Proposal', closingDate: '2026-10-01', notes: 'New territory distribution rights', createdAt: '2026-07-01', updatedAt: '2026-08-08' },
      { id: 'OPP-00006', customerId: 'CUS-00003', name: 'Neurology Trial', product: 'Neurology Range', expectedValue: 200000, probability: 90, stage: 'Closed-Won', closingDate: '2026-08-10', notes: 'Trial completed, order confirmed', createdAt: '2026-06-10', updatedAt: '2026-08-10' },
    ];
    writeJSON('opportunities.json', opportunities);
    counters['OPP'] = 6;
  }

  if (!readJSON('visits.json')) {
    const visits = [
      { id: 'VIS-00001', customerId: 'CUS-00001', type: 'Customer Visit', purpose: 'Product detailing - Cardiology', salesperson: 'Nusrat Jahan', checkIn: '2026-08-10T09:00:00', checkOut: '2026-08-10T09:45:00', location: { lat: 23.7925, lng: 90.4078 }, findings: 'Doctor showed interest in new cardiology range. Requested samples and pricing.', nextAction: 'Send samples and price list by Aug 12', photoUrl: null, createdAt: '2026-08-10T09:00:00' },
      { id: 'VIS-00002', customerId: 'CUS-00002', type: 'Customer Visit', purpose: 'Follow-up on prescription trends', salesperson: 'Sadia Rahman', checkIn: '2026-08-10T10:30:00', checkOut: '2026-08-10T11:00:00', location: { lat: 23.7450, lng: 90.3830 }, findings: 'Prescription volume increased 15% this month.', nextAction: 'Continue monthly follow-up', photoUrl: null, createdAt: '2026-08-10T10:30:00' },
      { id: 'VIS-00003', customerId: 'CUS-00006', type: 'Market Visit', purpose: 'Stock check and reorder', salesperson: 'Farhana Akter', checkIn: '2026-08-09T14:00:00', checkOut: '2026-08-09T14:30:00', location: { lat: 23.7944, lng: 90.4044 }, findings: 'Low stock on 3 SKUs. Pharmacy requested urgent restock.', nextAction: 'Process order immediately', photoUrl: null, createdAt: '2026-08-09T14:00:00' },
      { id: 'VIS-00004', customerId: 'CUS-00003', type: 'Planned Visit', purpose: 'New product launch presentation', salesperson: 'Imran Kabir', checkIn: '2026-08-09T11:00:00', checkOut: '2026-08-09T12:00:00', location: { lat: 23.8735, lng: 90.3938 }, findings: 'Doctor agreed to try new neurology product on 5 patients.', nextAction: 'Deliver trial packs on Aug 12', photoUrl: null, createdAt: '2026-08-09T11:00:00' },
      { id: 'VIS-00005', customerId: 'CUS-00001', type: 'Customer Visit', purpose: 'Sample delivery', salesperson: 'Nusrat Jahan', checkIn: '2026-08-08T16:00:00', checkOut: '2026-08-08T16:20:00', location: { lat: 23.7925, lng: 90.4078 }, findings: 'Samples delivered. Doctor will prescribe and provide feedback.', nextAction: 'Follow up in 2 weeks', photoUrl: null, createdAt: '2026-08-08T16:00:00' },
    ];
    writeJSON('visits.json', visits);
    counters['VIS'] = 5;
  }

  if (!readJSON('orders.json')) {
    const orders = [
      { id: 'ORD-00001', customerId: 'CUS-00006', items: [{ product: 'Paracetamol 500mg', quantity: 500, unitPrice: 150 }, { product: 'Omeprazole 20mg', quantity: 300, unitPrice: 200 }], totalAmount: 135000, status: 'Approved', approvedBy: 'Sales Head', dispatchedAt: null, deliveredAt: null, createdAt: '2026-08-09', updatedAt: '2026-08-10' },
      { id: 'ORD-00002', customerId: 'CUS-00007', items: [{ product: 'Amoxicillin 500mg', quantity: 200, unitPrice: 180 }, { product: 'Ciprofloxacin 500mg', quantity: 150, unitPrice: 250 }], totalAmount: 73500, status: 'Pending', approvedBy: null, dispatchedAt: null, deliveredAt: null, createdAt: '2026-08-10', updatedAt: '2026-08-10' },
      { id: 'ORD-00003', customerId: 'CUS-00008', items: [{ product: 'Diagnostic Kit A', quantity: 10, unitPrice: 8500 }], totalAmount: 85000, status: 'Dispatched', approvedBy: 'Sales Head', dispatchedAt: '2026-08-10', deliveredAt: null, createdAt: '2026-08-08', updatedAt: '2026-08-10' },
      { id: 'ORD-00004', customerId: 'CUS-00012', items: [{ product: 'Pharma Bundle A', quantity: 50, unitPrice: 2000 }], totalAmount: 100000, status: 'Delivered', approvedBy: 'Sales Head', dispatchedAt: '2026-08-05', deliveredAt: '2026-08-08', createdAt: '2026-08-03', updatedAt: '2026-08-09' },
      { id: 'ORD-00005', customerId: 'CUS-00010', items: [{ product: 'Cough Syrup', quantity: 100, unitPrice: 85 }, { product: 'Antihistamine', quantity: 80, unitPrice: 95 }], totalAmount: 16100, status: 'Pending', approvedBy: null, dispatchedAt: null, deliveredAt: null, createdAt: '2026-08-10', updatedAt: '2026-08-10' },
    ];
    writeJSON('orders.json', orders);
    counters['ORD'] = 5;
  }

  if (!readJSON('complaints.json')) {
    const complaints = [
      { id: 'CMP-00001', customerId: 'CUS-00010', category: 'Product Quality', description: 'Cough syrup bottles arrived with damaged seals', priority: 'High', status: 'Open', assignedTo: 'Quality Team', sla: '2026-08-13', resolution: null, resolvedAt: null, customerConfirmed: false, csat: null, createdAt: '2026-08-10' },
      { id: 'CMP-00002', customerId: 'CUS-00006', category: 'Delivery', description: 'Last order was 2 days late', priority: 'Medium', status: 'In Progress', assignedTo: 'Logistics', sla: '2026-08-15', resolution: null, resolvedAt: null, customerConfirmed: false, csat: null, createdAt: '2026-08-08' },
      { id: 'CMP-00003', customerId: 'CUS-00002', category: 'Billing', description: 'Invoice amount mismatch - charged extra 500 BDT', priority: 'Medium', status: 'Resolved', assignedTo: 'Accounts', sla: '2026-08-10', resolution: 'Credit note issued for 500 BDT', resolvedAt: '2026-08-09', customerConfirmed: true, csat: 4, createdAt: '2026-08-07' },
      { id: 'CMP-00004', customerId: 'CUS-00001', category: 'Product Quality', description: 'Tablet coating inconsistent in latest batch', priority: 'Low', status: 'Open', assignedTo: null, sla: '2026-08-20', resolution: null, resolvedAt: null, customerConfirmed: false, csat: null, createdAt: '2026-08-09' },
    ];
    writeJSON('complaints.json', complaints);
    counters['CMP'] = 4;
  }

  if (!readJSON('contacts.json')) {
    const contacts = [
      { id: 'CONT-00001', customerId: 'CUS-00001', name: 'Dr. Abdur Rahman', designation: 'Chief Cardiologist', phone: '01711234567', email: 'dr.rahman@email.com', isPrimary: true },
      { id: 'CONT-00002', customerId: 'CUS-00006', name: 'Mr. Karim', designation: 'Owner', phone: '01713334455', email: 'karim@email.com', isPrimary: true },
      { id: 'CONT-00003', customerId: 'CUS-00008', name: 'Ms. Anika', designation: 'Admin Manager', phone: '01712223345', email: 'anika@populardiagnostic.com', isPrimary: true },
      { id: 'CONT-00004', customerId: 'CUS-00012', name: 'Mr. Habibur', designation: 'Operations Head', phone: '01716667789', email: 'habibur@wellness.com', isPrimary: true },
    ];
    writeJSON('contacts.json', contacts);
    counters['CONT'] = 4;
  }

  if (!readJSON('activities.json')) {
    const activities = [
      { id: 'ACT-00001', customerId: 'CUS-00001', type: 'visit', description: 'Product detailing - Cardiology', performedBy: 'Nusrat Jahan', createdAt: '2026-08-10T09:00:00' },
      { id: 'ACT-00002', customerId: 'CUS-00001', type: 'order', description: 'Order ORD-00004 delivered', performedBy: 'Logistics', createdAt: '2026-08-08T10:00:00' },
      { id: 'ACT-00003', customerId: 'CUS-00001', type: 'complaint', description: 'Complaint CMP-00004 filed', performedBy: 'System', createdAt: '2026-08-09T14:00:00' },
      { id: 'ACT-00004', customerId: 'CUS-00006', type: 'visit', description: 'Stock check and reorder', performedBy: 'Farhana Akter', createdAt: '2026-08-09T14:00:00' },
      { id: 'ACT-00005', customerId: 'CUS-00006', type: 'order', description: 'Order ORD-00001 placed', performedBy: 'Farhana Akter', createdAt: '2026-08-09T14:30:00' },
      { id: 'ACT-00006', customerId: 'CUS-00002', type: 'complaint', description: 'Complaint CMP-00003 resolved', performedBy: 'Accounts', createdAt: '2026-08-09T16:00:00' },
    ];
    writeJSON('activities.json', activities);
    counters['ACT'] = 6;
  }

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
seedIfEmpty();

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
  const spPerformance = salespeople.map(sp => {
    const spCustomers = customers.filter(c => c.salesperson === sp);
    const spVisits = visits.filter(v => spCustomers.some(c => c.id === v.customerId));
    const spOrders = orders.filter(o => spCustomers.some(c => c.id === o.customerId) && o.status === 'Delivered');
    return {
      name: sp,
      customers: spCustomers.length,
      visits: spVisits.length,
      sales: spOrders.reduce((s, o) => s + o.totalAmount, 0)
    };
  }).sort((a, b) => b.sales - a.sales);

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
    const prefix = entityName === 'customers' ? 'CUS' : entityName === 'leads' ? 'LEAD' : entityName === 'opportunities' ? 'OPP' : entityName === 'visits' ? 'VIS' : entityName === 'orders' ? 'ORD' : entityName === 'complaints' ? 'CMP' : entityName === 'contacts' ? 'CONT' : 'ACT';
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

app.put('/api/accounts/:username', authRequired, roleRequired('super_admin'), (req, res) => {
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
