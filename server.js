'use strict';

const express = require('express');
const crypto  = require('crypto');
const { QubitShield } = require('./src/sdk/index');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => console.log(`${req.method} ${req.path} → ${res.statusCode} (${Date.now()-start}ms)`));
  next();
});

function authenticate(req, res, next) {
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  if (!token || !token.startsWith('qs_')) return res.status(401).json({ ok:false, error:'Unauthorized — use: Authorization: Bearer qs_live_your_key' });
  try { req.qs = new QubitShield({ apiKey: token }); next(); }
  catch(err) { return res.status(401).json({ ok:false, error:'Invalid API key' }); }
}

function handleError(res, err) {
  console.error('API Error:', err.message);
  return res.status(400).json({ ok:false, error:err.message });
}

app.get('/', (req, res) => {
  res.json({ name:'QUBIT Shield API', version:'1.0.0', company:'LUNARECLIPSE',
    description:'Quantum-inspired enterprise security infrastructure',
    endpoints:{ health:'GET /v1/health', encrypt:'POST /v1/encrypt', decrypt:'POST /v1/decrypt', detect:'POST /v1/detect', sign:'POST /v1/sign', verify:'POST /v1/verify' }
  });
});

app.get('/v1/health', (req, res) => {
  res.json({ ok:true, status:'operational', version:'1.0.0', engine:'QubitShield-v1',
    algorithms:['QKD-BB84','AES-256-GCM','STEANE-7-QEC','HMAC-SHA256'],
    timestamp:new Date().toISOString(), uptime:Math.floor(process.uptime()) });
});

app.post('/v1/encrypt', authenticate, async (req, res) => {
  try {
    const { payload } = req.body;
    if (!payload) return res.status(400).json({ ok:false, error:'payload is required' });
    const result = await req.qs.encrypt(typeof payload==='string' ? payload : JSON.stringify(payload));
    res.json({ ok:true, sessionId:result.sessionId, envelope:result.envelope, algorithm:result.envelope.algorithm, encoding:result.envelope.encoding, timeMs:result.envelope.timeMs });
  } catch(err) { handleError(res, err); }
});

app.post('/v1/decrypt', authenticate, async (req, res) => {
  try {
    const { envelope } = req.body;
    if (!envelope) return res.status(400).json({ ok:false, error:'envelope is required' });
    const result = await req.qs.decrypt(envelope);
    res.json({ ok:true, text:result.text, sessionId:result.sessionId, errorsFound:result.errorsFound });
  } catch(err) { handleError(res, err); }
});

app.post('/v1/detect', authenticate, async (req, res) => {
  try {
    const { envelope } = req.body;
    if (!envelope) return res.status(400).json({ ok:false, error:'envelope is required' });
    const result = await req.qs.detect(envelope);
    res.json({ ok:true, tampered:result.tampered, score:result.score, reason:result.reason, syndromeMatch:result.syndromeMatch, signatureValid:result.signatureValid });
  } catch(err) { handleError(res, err); }
});

app.post('/v1/sign', authenticate, (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ ok:false, error:'data is required' });
    res.json({ ok:true, ...req.qs.sign(data) });
  } catch(err) { handleError(res, err); }
});

app.post('/v1/verify', authenticate, (req, res) => {
  try {
    const { data, signature } = req.body;
    if (!data||!signature) return res.status(400).json({ ok:false, error:'data and signature are required' });
    res.json({ ok:true, ...req.qs.verify(data, signature) });
  } catch(err) { handleError(res, err); }
});

app.use((req, res) => res.status(404).json({ ok:false, error:'Endpoint not found' }));

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║     QUBIT SHIELD API — OPERATIONAL       ║');
  console.log('║     LUNARECLIPSE · v1.0.0                ║');
  console.log(`║     http://localhost:${PORT}                ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;
