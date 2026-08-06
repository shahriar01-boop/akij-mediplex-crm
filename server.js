const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readData(filename) {
  const filepath = path.join(DATA_DIR, filename);
  try {
    if (fs.existsSync(filepath)) {
      return fs.readFileSync(filepath, 'utf-8');
    }
  } catch (e) {
    console.error('read error', filename, e.message);
  }
  return null;
}

function writeData(filename, value) {
  const filepath = path.join(DATA_DIR, filename);
  const tmp = filepath + '.tmp.' + Date.now();
  try {
    fs.writeFileSync(tmp, value, 'utf-8');
    fs.renameSync(tmp, filepath);
    return true;
  } catch (e) {
    console.error('write error', filename, e.message);
    try { fs.unlinkSync(tmp); } catch (_) {}
    return false;
  }
}

app.get('/api/doctors', (_req, res) => {
  const data = readData('doctors.json');
  res.json({ value: data || null });
});

app.put('/api/doctors', (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  const ok = writeData('doctors.json', value);
  res.json({ success: ok });
});

app.get('/api/pharmacies', (_req, res) => {
  const data = readData('pharmacies.json');
  res.json({ value: data || null });
});

app.put('/api/pharmacies', (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  const ok = writeData('pharmacies.json', value);
  res.json({ success: ok });
});

app.get('/api/accounts', (_req, res) => {
  const data = readData('accounts.json');
  res.json({ value: data || null });
});

app.put('/api/accounts', (req, res) => {
  const { value } = req.body;
  if (typeof value !== 'string') return res.status(400).json({ error: 'value required' });
  const ok = writeData('accounts.json', value);
  res.json({ success: ok });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'akij_mediplex_crm.html'));
});

app.listen(PORT, () => {
  console.log(`AKIJ Mediplex CRM running at http://localhost:${PORT}`);
});
