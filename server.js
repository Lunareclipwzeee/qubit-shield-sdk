'use strict';
const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const { QubitShield } = require('./src/sdk/index');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => console.log(`${req.method} ${req.path} -> ${res.statusCode} (${Date.now()-start}ms)`));
  next();
});

// In-memory store
const companies = new Map();
const usageLog  = [];

function generateKey() {
  return 'qs_live_' + crypto.randomBytes(16).toString('hex');
}

function getCompanyByKey(key) { return companies.get(key) || null; }
function getCompanyByEmail(email) {
  for (const c of companies.values()) if (c.email === email) return c;
  return null;
}
function logUsage(key, action, ms) {
  usageLog.push({ api_key: key, action, ms, created_at: new Date().toISOString() });
}
function getStats(key) {
  const all = usageLog.filter(u => u.api_key === key);
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  return {
    totalEncryptions: all.length,
    thisMonth: all.filter(u => new Date(u.created_at) >= monthStart).length,
    byAction: [],
    recentActivity: all.slice(-10).reverse()
  };
}
function isPilotActive(company) {
  return new Date(company.pilot_end) > new Date();
}
function daysLeft(company) {
  return Math.max(0, Math.ceil((new Date(company.pilot_end) - new Date()) / (1000*60*60*24)));
}

// AUTH
function authenticate(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token || !token.startsWith('qs_')) return res.status(401).json({ ok: false, error: 'Unauthorized — use: Authorization: Bearer qs_live_your_key' });
  const company = getCompanyByKey(token);
  if (!company) return res.status(401).json({ ok: false, error: 'API key not found — sign up at qubit-shield.onrender.com/signup' });
  if (!isPilotActive(company)) return res.status(402).json({ ok: false, error: 'Pilot expired — upgrade at qubit-shield.onrender.com/signup' });
  try { req.qs = new QubitShield({ apiKey: token }); } catch(e) { return res.status(401).json({ ok: false, error: 'Invalid API key' }); }
  req.company = company;
  next();
}

// PAGES
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// PLATFORM API
app.post('/platform/signup', (req, res) => {
  try {
    const { name, email, company, role } = req.body;
    if (!name || !email || !company) return res.status(400).json({ ok: false, error: 'name, email, and company are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, error: 'Invalid email address' });
    if (getCompanyByEmail(email)) return res.status(409).json({ ok: false, error: 'Email already registered' });
    const apiKey   = generateKey();
    const pilotEnd = new Date(Date.now() + 30*24*60*60*1000).toISOString();
    const record   = { name, email, company, role: role||'CTO', api_key: apiKey, plan: 'pilot', status: 'active', pilot_end: pilotEnd, created_at: new Date().toISOString() };
    companies.set(apiKey, record);
    logUsage(apiKey, 'signup', 0);
    res.status(201).json({ ok: true, message: 'Welcome to QUBIT Shield. Your 30-day pilot starts now.', apiKey, plan: 'pilot', pilotDays: 30, pilotEnd, dashboard: '/dashboard?key='+apiKey });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.get('/platform/dashboard', (req, res) => {
  const apiKey = req.query.key || (req.headers['authorization']||'').replace('Bearer ','').trim();
  if (!apiKey) return res.status(401).json({ ok: false, error: 'API key required' });
  const company = getCompanyByKey(apiKey);
  if (!company) return res.status(404).json({ ok: false, error: 'API key not found' });
  const usage = getStats(apiKey);
  const dl    = daysLeft(company);
  res.json({
    ok: true,
    account: { name: company.name, email: company.email, company: company.company, apiKey: company.api_key, plan: company.plan, status: isPilotActive(company)?'active':'expired', pilotDaysRemaining: dl, pilotEnd: company.pilot_end, memberSince: company.created_at },
    usage,
    billing: { currentPlan: company.plan, estimatedBill: 0, currency: 'INR', nextBillingDate: company.pilot_end }
  });
});

// QUBIT API
app.get('/', (req, res) => res.json({ name: 'QUBIT Shield API', version: '1.0.0', company: 'LUNARECLIPSE', signup: '/signup', dashboard: '/dashboard', endpoints: { health: 'GET /v1/health', encrypt: 'POST /v1/encrypt', decrypt: 'POST /v1/decrypt', detect: 'POST /v1/detect', sign: 'POST /v1/sign', verify: 'POST /v1/verify' } }));

app.get('/v1/health', (req, res) => res.json({ ok: true, status: 'operational', version: '1.0.0', engine: 'QubitShield-v1', algorithms: ['QKD-BB84','AES-256-GCM','STEANE-7-QEC'], timestamp: new Date().toISOString(), uptime: Math.floor(process.uptime()), totalCompanies: companies.size }));

app.post('/v1/encrypt', authenticate, async (req, res) => {
  const start = Date.now();
  try {
    const { payload } = req.body;
    if (!payload) return res.status(400).json({ ok: false, error: 'payload is required' });
    const result = await req.qs.encrypt(typeof payload==='string'?payload:JSON.stringify(payload));
    logUsage(req.company.api_key, 'encrypt', Date.now()-start);
    res.json({ ok: true, sessionId: result.sessionId, envelope: result.envelope, algorithm: result.envelope.algorithm, encoding: result.envelope.encoding, timeMs: result.envelope.timeMs });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/v1/decrypt', authenticate, async (req, res) => {
  const start = Date.now();
  try {
    const { envelope } = req.body;
    if (!envelope) return res.status(400).json({ ok: false, error: 'envelope is required' });
    const result = await req.qs.decrypt(envelope);
    logUsage(req.company.api_key, 'decrypt', Date.now()-start);
    res.json({ ok: true, text: result.text, sessionId: result.sessionId, errorsFound: result.errorsFound });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/v1/detect', authenticate, async (req, res) => {
  const start = Date.now();
  try {
    const { envelope } = req.body;
    if (!envelope) return res.status(400).json({ ok: false, error: 'envelope is required' });
    const result = await req.qs.detect(envelope);
    logUsage(req.company.api_key, 'detect', Date.now()-start);
    res.json({ ok: true, tampered: result.tampered, score: result.score, reason: result.reason });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/v1/sign', authenticate, (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ ok: false, error: 'data is required' });
    logUsage(req.company.api_key, 'sign', 0);
    res.json({ ok: true, ...req.qs.sign(data) });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.post('/v1/verify', authenticate, (req, res) => {
  try {
    const { data, signature } = req.body;
    if (!data||!signature) return res.status(400).json({ ok: false, error: 'data and signature are required' });
    logUsage(req.company.api_key, 'verify', 0);
    res.json({ ok: true, ...req.qs.verify(data, signature) });
  } catch(err) { res.status(400).json({ ok: false, error: err.message }); }
});

app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   QUBIT SHIELD PLATFORM — OPERATIONAL    ║');
  console.log('║   LUNARECLIPSE · v1.0.0                  ║');
  console.log(`║   http://localhost:${PORT}                  ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;
