/**
 * TruConfirm QRDI — Mock Backend Server
 * json-server + custom scan execution simulator
 * Run: node server.js   (default port 3001)
 */

const jsonServer = require('json-server');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');

const PORT    = process.env.PORT || 3001;
const DB_PATH = path.join(__dirname, 'db.json');

const server   = jsonServer.create();
const router   = jsonServer.router(DB_PATH);
const middlewares = jsonServer.defaults({ noCors: true });

// ── CORS (allow the frontend on any localhost port) ──
server.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'] }));
server.use(middlewares);
server.use(jsonServer.bodyParser);

// ── helpers ──────────────────────────────────────────────────────────────────
function readDb()       { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
function writeDb(data)  { fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2)); }
function uid(prefix)    { return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2,6); }
function ts()           { return new Date().toISOString().slice(0,16).replace('T',' '); }

// ── SIMULATE QRDI DIALOG EXECUTION ───────────────────────────────────────────
//
// For Option-4 (mock backend) we don't actually make HTTP / TCP calls.
// Instead we pattern-match on the detection_type + dialog to produce
// a realistic-looking finding: status, result text, evidence, debug log.
//
function simulateExecution(sig, host) {
  const detType = sig.detection_type || 'http dialog';
  const title   = sig.title || 'Custom QRDI Check';
  const dialog  = sig.dialog || [];
  const debug_level = sig.debug_level || 0;

  const debugLines = [];
  if (debug_level >= 100) debugLines.push(`[100] Detection started: ${title}`);

  let status   = 'NOT VULNERABLE';
  let result   = '';
  let evidence = '';
  let errors   = '';

  try {
    if (detType === 'http dialog') {
      const getTx      = dialog.find(t => t.transaction === 'http get' || t.transaction === 'http post');
      const processTx  = dialog.find(t => t.transaction === 'process');
      const reportTx   = dialog.find(t => t.transaction === 'report');
      const obj        = getTx ? getTx.object : '/';
      const pattern    = processTx ? processTx.match : '';

      if (debug_level >= 200) debugLines.push(`[200] TX1 ${getTx?.transaction || 'http get'} ${obj} -> HTTP 200 (simulated)`);

      // Simulate a match ~60% of the time for demo variety
      const matched = Math.random() > 0.4;

      if (matched) {
        if (debug_level >= 200) debugLines.push(`[200] TX2 process ${processTx?.mode || 'regexp'} MATCH FOUND`);
        status   = 'VULNERABLE';

        if (typeof reportTx?.result === 'string') {
          result = reportTx.result;
        } else if (reportTx?.result?.concat) {
          result = `${title} detected on ${host}`;
        } else if (reportTx?.result?.system === 'body') {
          result = `Response body captured from ${host}`;
        } else {
          result = `${title} confirmed on ${host}`;
        }

        evidence = `GET ${obj} HTTP/1.1\nHost: ${host}\n\nHTTP/1.1 200 OK\nServer: Apache/2.4.51\nContent-Type: text/html\n\n<html>...matched pattern: ${pattern}...</html>`;
      } else {
        if (debug_level >= 200) debugLines.push(`[200] TX2 process ${processTx?.mode || 'regexp'} NO MATCH`);
        evidence = `GET ${obj} HTTP/1.1\nHost: ${host}\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>...no match for pattern: ${pattern}...</html>`;
      }
    } else {
      // TCP dialog
      const sendTx    = dialog.find(t => t.transaction === 'send');
      const receiveTx = dialog.find(t => t.transaction === 'receive');
      const pattern   = receiveTx ? receiveTx.match : '.+';

      if (debug_level >= 200) debugLines.push(`[200] TX1 send -> ok (simulated)`);

      const matched = Math.random() > 0.35;
      if (matched) {
        if (debug_level >= 200) debugLines.push(`[200] TX2 receive ${receiveTx?.mode || 'regexp'} MATCH FOUND`);
        status   = 'VULNERABLE';
        result   = `TCP service response captured from ${host}`;
        evidence = `SENT: ${typeof sendTx?.data === 'string' ? sendTx.data : '[binary packet]'}\nRECV: Service banner / response captured\nPattern matched: ${pattern}`;
      } else {
        if (debug_level >= 200) debugLines.push(`[200] TX2 receive NO MATCH or TIMEOUT`);
        evidence = `No matching TCP response received from ${host}`;
      }
    }
  } catch (e) {
    status = 'ERROR';
    errors = `RESULT_ERRORS: Execution error — ${e.message}`;
    if (debug_level >= 100) debugLines.push(`[100] Detection ended: ERROR`);
  }

  if (debug_level >= 100) debugLines.push(`[100] Detection ended: ${status}`);

  return { status, result, evidence, debug: debugLines.join('\n'), errors };
}

// ── MOCK ASSET POOLS (per profile) ───────────────────────────────────────────
const ASSET_POOLS = {
  sp1: ['10.0.1.44','10.0.1.45','10.0.1.46','10.0.1.47','10.0.1.48','10.0.1.49'],
  sp2: ['10.0.2.10','10.0.2.11','10.0.2.12'],
  sp3: ['10.0.3.20','10.0.3.21','10.0.3.22','10.0.3.23'],
};

// ── POST /api/scan/run ────────────────────────────────────────────────────────
// Body: { profileId: "sp1", qids: [410001, 410003] }
// Returns: { scanId, status, findings[] }
server.post('/api/scan/run', (req, res) => {
  const { profileId, qids } = req.body || {};
  if (!profileId) return res.status(400).json({ error: 'profileId required' });

  const db       = readDb();
  const profile  = db.profiles.find(p => p.id === profileId);
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  const qidsToRun = qids || profile.attachedQids || [];
  const hosts     = ASSET_POOLS[profileId] || ['10.0.0.1'];
  const scanId    = uid('sc');
  const startedAt = ts();

  const newFindings = [];
  let vulnerableCount = 0, errorCount = 0;

  qidsToRun.forEach(qid => {
    const sig = db.signatures.find(s => s.qid === qid);
    if (!sig) return;

    const enabled = profile.perScanEnabled?.[String(qid)];
    if (enabled === false) return;  // per-scan disabled

    hosts.forEach(host => {
      const sim = simulateExecution(sig.definition || sig, host);
      const finding = {
        id:          uid('f'),
        qid,
        title:       sig.title,
        profileId,
        profileName: profile.name,
        status:      sim.status,
        result:      sim.result,
        evidence:    sim.evidence,
        debug:       sim.debug,
        errors:      sim.errors,
        host,
        ts:          ts(),
        scanId
      };
      newFindings.push(finding);
      if (sim.status === 'VULNERABLE') vulnerableCount++;
      if (sim.status === 'ERROR')      errorCount++;
    });
  });

  const completedAt = ts();
  const scanRecord = {
    id: scanId, profileId,
    profileName: profile.name,
    startedAt, completedAt,
    status: errorCount > 0 ? 'COMPLETED_WITH_ERRORS' : 'COMPLETED',
    totalHosts: hosts.length,
    vulnerable: vulnerableCount,
    notVulnerable: newFindings.filter(f => f.status === 'NOT VULNERABLE').length,
    errors: errorCount,
    qidsRun: qidsToRun
  };

  // Persist to db.json
  db.findings.push(...newFindings);
  db.scans.push(scanRecord);

  // Telemetry event
  db.telemetry.push({
    id: uid('t'), event: 'scan_executed',
    scanId, profileId,
    ts: ts(), user: 'maghosh'
  });

  writeDb(db);
  // Reload router so GET /findings returns fresh data
  router.db.read();

  res.json({ scanId, status: scanRecord.status, findings: newFindings, scan: scanRecord });
});

// ── POST /api/telemetry ───────────────────────────────────────────────────────
// Body: { event, qid?, title?, scanId?, profileId? }
server.post('/api/telemetry', (req, res) => {
  const db = readDb();
  const entry = { id: uid('t'), ts: ts(), user: 'maghosh', ...req.body };
  db.telemetry.push(entry);
  writeDb(db);
  router.db.read();
  res.status(201).json(entry);
});

// ── GET /api/stats ────────────────────────────────────────────────────────────
server.get('/api/stats', (req, res) => {
  const db = readDb();
  const active   = db.signatures.filter(s => s.status === 'Active').length;
  const total    = db.signatures.length;
  const vulns    = db.findings.filter(f => f.status === 'VULNERABLE').length;
  const scans    = db.scans.length;
  const luaLibs  = db.lua_libs.length;
  const pending  = db.signatures.filter(s => s.status === 'Draft' || s.status === 'Pending').length;

  // Telemetry summary
  const aiInvocations  = db.telemetry.filter(t => t.event === 'ai_generation_invoked').length;
  const valPassed      = db.telemetry.filter(t => t.event === 'validation_passed').length;
  const sigCreated     = db.telemetry.filter(t => t.event === 'signature_created').length;
  const scansExecuted  = db.telemetry.filter(t => t.event === 'scan_executed').length;

  res.json({ total, active, pending, luaLibs, vulns, scans, aiInvocations, valPassed, sigCreated, scansExecuted });
});

// ── Serve the frontend on / (optional convenience) ───────────────────────────
const FRONTEND = path.join(__dirname, '..');
server.use(require('express').static(FRONTEND));

// ── Mount json-server router at /api ─────────────────────────────────────────
server.use('/api', router);

// ── Start ─────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n✅  TruConfirm QRDI mock backend running`);
  console.log(`   API  → http://localhost:${PORT}/api`);
  console.log(`   App  → http://localhost:${PORT}\n`);
  console.log('   Endpoints:');
  console.log('   GET    /api/signatures         — list all QRDI signatures');
  console.log('   POST   /api/signatures         — create a new signature');
  console.log('   PUT    /api/signatures/:id     — update a signature');
  console.log('   DELETE /api/signatures/:id     — delete a signature');
  console.log('   GET    /api/profiles           — list scan profiles');
  console.log('   GET    /api/findings           — list all findings');
  console.log('   GET    /api/findings?profileId=sp1  — filter by profile');
  console.log('   GET    /api/findings?qid=410001     — filter by QID');
  console.log('   POST   /api/scan/run           — execute a mock scan');
  console.log('   GET    /api/stats              — dashboard KPIs + telemetry summary');
  console.log('   POST   /api/telemetry          — log a user event');
  console.log('   GET    /api/scans              — scan run history\n');
});
