// ─────────────────────────────────────────────
//  DATA
// ─────────────────────────────────────────────
const CVE_DATA = [
  { id:'CVE-2026-1281', type:'cve', title:'CVE-2026-1281', sub:'CVE-2026-1281: ...', sev:'Critical', score:9.5, cvss:9.8, expl:'Actively Exploited', tc:true, hosts:109, jobs:9, actors:1, patch:0, riskFactors:['internet','service','auth','privesc'], ciseKev:true },
  { id:'CVE-2025-1546', type:'cve', title:'CVE-2025-1546', sub:'CVE-2025-1546: ...', sev:'Medium', score:4.2, cvss:8.8, expl:'POC Exploit', tc:true, hosts:0, jobs:0, actors:0, patch:22, riskFactors:['internet','service','auth'], ciseKev:false },
  { id:'CVE-2026-2374', type:'cve', title:'CVE-2026-2374', sub:'CVE-2026-2374: ...', sev:'Critical', score:9.5, cvss:9.8, expl:'Actively Exploited', tc:true, hosts:0, jobs:0, actors:0, patch:0, riskFactors:['internet','service','auth','privesc'], ciseKev:true },
  { id:'CVE-2025-0891', type:'cve', title:'CVE-2025-0891', sub:'CVE-2025-0891: ...', sev:'High', score:7.2, cvss:7.8, expl:'Easy Exploit', tc:false, hosts:42, jobs:3, actors:0, patch:5, riskFactors:['internet','service'], ciseKev:false },
  { id:'CVE-2024-9912', type:'cve', title:'CVE-2024-9912', sub:'CVE-2024-9912: ...', sev:'Low', score:2.1, cvss:3.2, expl:'', tc:false, hosts:0, jobs:0, actors:0, patch:1, riskFactors:[], ciseKev:false },
];

const QRDI_DEFAULTS = [
  { id:'QID-410001', type:'qrdi', qid:410001, title:'Custom XSS Detection', sub:'HTTP dialog – QRDI',
    sev:'Critical', score:9.0, cvss:7.5, expl:'POC Exploit', tc:true,
    hosts:14, jobs:2, actors:0, patch:0,
    vulnType:'Vulnerability', severity:4, debugLevel:0, enabled:true, detectionType:'http dialog',
    threat:'Cross-site scripting vulnerability detected via custom HTTP dialog detection.',
    impact:'Attacker can execute arbitrary scripts in the browser of a victim user.',
    solution:'Apply input validation and output encoding. Upgrade to patched version.',
    cveIds:'CVE-2023-1234', bugtraqIds:'', vendorRefs:[{ref:'Vendor1',url:'http://vendor.com'}],
    jsonDef:`{\n  "detection_type": "http dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "title": "custom XSS detection",\n  "dialog": [\n    {\n      "transaction": "http get",\n      "object": "/cgi-bin/no5_such3_file7.pl?\\"><script>alert(73541);</script>"\n    },\n    {\n      "transaction": "process",\n      "mode": "regexp",\n      "match": "\\"><script>alert\\\\(73541\\\\);</script>"\n    },\n    {\n      "transaction": "report",\n      "result": "XSS found"\n    }\n  ]\n}` },
  { id:'QID-410002', type:'qrdi', qid:410002, title:'IMAP Authentication Check', sub:'TCP dialog – QRDI',
    sev:'High', score:6.8, cvss:6.5, expl:'', tc:false,
    hosts:0, jobs:0, actors:0, patch:0,
    vulnType:'Information Gathered', severity:3, debugLevel:100, enabled:true, detectionType:'tcp dialog',
    threat:'IMAP service exposes account information through authentication checks.',
    impact:'Potential disclosure of mailbox counts and message metadata.',
    solution:'Disable unauthenticated IMAP enumeration or enforce strict authentication.',
    cveIds:'', bugtraqIds:'12345', vendorRefs:[],
    jsonDef:`{\n  "detection_type": "tcp dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "services": ["imap", "imaps"],\n  "debug_level": 100,\n  "title": "IMAP auth check",\n  "dialog": [\n    { "transaction": "send", "data": "a001 LOGIN myuser mypassword\\n" },\n    { "transaction": "receive", "mode": "luapattern", "match": "\\na001 [^\\n]*\\n" },\n    { "transaction": "report", "result": {"user": "result"} }\n  ]\n}` },
  { id:'QID-410003', type:'qrdi', qid:410003, title:'SMB Protocol Version Detection', sub:'TCP dialog – QRDI',
    sev:'Critical', score:9.1, cvss:9.0, expl:'Actively Exploited', tc:true,
    hosts:31, jobs:5, actors:2, patch:0,
    vulnType:'Vulnerability', severity:4, debugLevel:0, enabled:true, detectionType:'tcp dialog',
    threat:'SMB service exposes supported protocol versions, revealing potential downgrade attack vectors.',
    impact:'Attacker may negotiate legacy SMB versions to exploit known protocol weaknesses.',
    solution:'Disable legacy SMB versions (SMBv1, SMBv2.0.2). Enforce SMBv3.1.1 minimum.',
    cveIds:'CVE-2024-5678', bugtraqIds:'', vendorRefs:[{ref:'MS-ADV2024-001',url:'https://microsoft.com/security'}],
    jsonDef:`{\n  "detection_type": "tcp dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "services": ["microsoft-ds"],\n  "title": "SMB version detection",\n  "dialog": [\n    { "transaction": "send", "data": {"call": {"name": "qrdiuser_smb_create_v1_negotiate"}} },\n    { "transaction": "receive", "mode": "call", "name": "qrdiuser_smb_check" },\n    { "transaction": "process", "mode": "call", "name": "qrdiuser_smb_process_packet" },\n    { "transaction": "report", "result": {"user": "result"} }\n  ]\n}` },
  { id:'QID-410004', type:'qrdi', qid:410004, title:'HTTP Header Injection Test', sub:'HTTP dialog – QRDI',
    sev:'Critical', score:8.5, cvss:8.2, expl:'Easy Exploit', tc:true,
    hosts:7, jobs:1, actors:1, patch:0,
    vulnType:'Vulnerability', severity:4, debugLevel:200, enabled:true, detectionType:'http dialog',
    threat:'Custom HTTP header injection check targeting misconfigurations in reverse proxies.',
    impact:'May allow request smuggling or header manipulation leading to security bypass.',
    solution:'Validate and sanitize all incoming HTTP headers. Update proxy configuration.',
    cveIds:'', bugtraqIds:'', vendorRefs:[],
    jsonDef:`{\n  "detection_type": "http dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "debug_level": 200,\n  "title": "HTTP header injection test",\n  "dialog": [\n    {\n      "transaction": "http get",\n      "http_header": "HEADER_TEST: HeaderTest\\nCOMPANY: TestCo",\n      "object": "index.html"\n    },\n    { "transaction": "process", "mode": "substring", "match": "HeaderTest" },\n    { "transaction": "report", "result": "Header injection confirmed" }\n  ]\n}` },
  { id:'QID-410005', type:'qrdi', qid:410005, title:'TCP Service Banner Check', sub:'TCP dialog – QRDI',
    sev:'Low', score:2.4, cvss:3.1, expl:'', tc:false,
    hosts:0, jobs:0, actors:0, patch:0,
    vulnType:'Information Gathered', severity:1, debugLevel:0, enabled:false, detectionType:'tcp dialog',
    threat:'Service banner reveals version information useful in reconnaissance.',
    impact:'Version disclosure aids targeted exploitation.',
    solution:'Suppress or modify service banners to remove version information.',
    cveIds:'', bugtraqIds:'', vendorRefs:[],
    jsonDef:`{\n  "detection_type": "tcp dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "services": ["ftp"],\n  "title": "FTP banner check",\n  "dialog": [\n    { "transaction": "receive", "mode": "regexp", "match": "220.*FTP" },\n    { "transaction": "report", "result": {"system": "body"} }\n  ]\n}` },
];

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────
const S = {
  entries: [...CVE_DATA, ...QRDI_DEFAULTS],
  luaLib: { id:1369, name:'my_lua_library.lua', size:'999.5 KB', status:'Published', createdBy:'Patrick Skimmer', createdOn:'06/04/2019 10:52:16 AM (GMT-8:00)', updatedBy:'N/A', updatedOn:'N/A' },
  filter: { category:'all', severity:null, rti:null },
  search: '',
  activeModal: null,
  editEntry: null,
  nextQid: 410006,
  vendorRefs: [],
  jsonValid: null,
  detType: 'http dialog',
  debugSel: 0,
  statusEnabled: true,
  confirmCb: null,
};

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
const sevClass = s => ({'Critical':'b-crit','High':'b-high','Medium':'b-med','Low':'b-low','Informational':'b-blue'}[s]||'b-blue');
const sevFromNum = n => (['','Low','Medium','High','Critical','Critical'][n]||'Low');
const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const $=id=>document.getElementById(id);
const qs=(s,el=document)=>el.querySelector(s);
const qsa=(s,el=document)=>el.querySelectorAll(s);

function showToast(msg, type='tok'){
  const c = $('toast-c');
  const t = document.createElement('div');
  t.className=`toast t${type}`;
  t.innerHTML = `<span>${type==='tok'?'✓':type==='terr'?'✗':'ℹ'}</span><span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(()=>t.remove(), 3200);
}

// ─────────────────────────────────────────────
//  FILTER & SEARCH
// ─────────────────────────────────────────────
function filteredEntries(){
  return S.entries.filter(e=>{
    const q = S.search.toLowerCase();
    if(q && !e.title.toLowerCase().includes(q) && !e.id.toLowerCase().includes(q)) return false;
    if(S.filter.category==='qrdi' && e.type!=='qrdi') return false;
    if(S.filter.category==='cve' && e.type!=='cve') return false;
    if(S.filter.severity && e.sev!==S.filter.severity) return false;
    if(S.filter.rti==='debug' && (e.type!=='qrdi'||e.debugLevel===0)) return false;
    if(S.filter.rti==='disabled' && (e.type!=='qrdi'||e.enabled!==false)) return false;
    return true;
  });
}

function renderActiveFilters(){
  const c=$('active-filters');
  c.innerHTML='';
  if(S.filter.category!=='all'){
    const ch=document.createElement('span');
    ch.className='fchip';
    ch.innerHTML=`Category: ${S.filter.category.toUpperCase()} <span class="remove">×</span>`;
    ch.onclick=()=>{S.filter.category='all';renderAll();};
    c.appendChild(ch);
  }
  if(S.filter.severity){
    const ch=document.createElement('span');
    ch.className='fchip';
    ch.innerHTML=`Severity: ${S.filter.severity} <span class="remove">×</span>`;
    ch.onclick=()=>{S.filter.severity=null;renderAll();};
    c.appendChild(ch);
  }
  if(S.filter.rti){
    const ch=document.createElement('span');
    ch.className='fchip';
    ch.innerHTML=`Filter: ${S.filter.rti} <span class="remove">×</span>`;
    ch.onclick=()=>{S.filter.rti=null;renderAll();};
    c.appendChild(ch);
  }
}

// ─────────────────────────────────────────────
//  RENDER TABLE
// ─────────────────────────────────────────────
function renderTable(){
  const data = filteredEntries();
  const tbody = $('kb-tbody');
  if(!data.length){
    tbody.innerHTML=`<tr><td colspan="8"><div class="empty-s"><div class="ei">🔍</div><div class="et">No results found</div><div class="ed">Try adjusting your search or filters</div></div></td></tr>`;
    $('tcount').textContent=`Total 0`;
    return;
  }
  $('tcount').textContent=`Total ${data.length>99?'1.63K':data.length}`;
  tbody.innerHTML = data.map(e=>{
    const isQrdi = e.type==='qrdi';
    const disabled = isQrdi && !e.enabled;
    const sevCls = sevClass(e.sev);
    const expl = e.expl ? `<span style="display:flex;align-items:center;gap:4px;white-space:nowrap">
      <span>${e.expl==='Actively Exploited'?'🔥':e.expl==='POC Exploit'?'💻':'⚡'}</span>
      <span style="font-size:12px">${e.expl}</span></span>` : '<span style="color:var(--text-muted);font-size:12px">—</span>';
    const tcBadge = e.tc ? `<div class="tcbadge" style="margin-top:3px">🛡 TruConfirm Validation Available</div>` : '';
    const debugBadge = isQrdi && e.debugLevel>0 ? `<span class="badge b-debug" style="margin-left:4px">Debug ${e.debugLevel}</span>` : '';
    const disabledBadge = disabled ? `<span class="badge b-dis" style="margin-left:4px">Disabled</span>` : '';
    const qrdiBadge = isQrdi ? `<span class="badge b-qrdi">QRDI</span>` : '';
    const impact = `<div class="imp">
      <span class="impi">🖥 ${e.hosts}</span>
      <span class="impi">💼 ${e.jobs}</span>
    </div>`;
    const actors = `<span style="font-size:13px">${e.actors||0}</span>`;
    const patchNum = e.patch>0 ? `<span class="badge b-ok btn-sm">${e.patch}</span>` : `<span class="badge b-dis btn-sm">0</span>`;
    const qas = isQrdi ? `
      <button class="qab" onclick="openInfo('${e.id}',event)">Info</button>
      <button class="qab" onclick="openEdit('${e.id}',event)">Edit</button>
      <button class="qab ${disabled?'':'warn'}" onclick="toggleEnable('${e.id}',event)">${disabled?'Enable':'Disable'}</button>
    ` : `<button class="qab" onclick="openInfo('${e.id}',event)">Info</button>`;
    return `<tr class="${disabled?'row-disabled':''}" onclick="openInfo('${e.id}')">
      <td><div class="rt">${escHtml(e.title)}${debugBadge}${disabledBadge}</div><div class="rs">${escHtml(e.sub||e.id)}</div>${tcBadge}</td>
      <td>${qrdiBadge} <span class="badge ${sevCls}">${e.sev} · ${e.score}</span></td>
      <td><span style="font-size:13px;font-weight:600">${e.cvss}</span></td>
      <td>${expl}</td>
      <td>${riskIcons(e)}</td>
      <td>${impact}</td>
      <td>${actors}</td>
      <td><div style="display:flex;align-items:center;gap:5px">${patchNum}<div class="qa">${qas}</div></div></td>
    </tr>`;
  }).join('');
}

function riskIcons(e){
  const icons=['🌐','🖥','🔧','🔑'];
  return `<div style="display:flex;gap:3px">${(e.riskFactors||[]).slice(0,4).map((_,i)=>`<span style="font-size:14px;opacity:.7">${icons[i]||'◆'}</span>`).join('')}</div>`;
}

// ─────────────────────────────────────────────
//  RENDER STATS
// ─────────────────────────────────────────────
function renderStats(){
  const qrdi = S.entries.filter(e=>e.type==='qrdi');
  const crit = S.entries.filter(e=>e.sev==='Critical').length;
  const debug = qrdi.filter(e=>e.debugLevel>0).length;
  const aktExpl = S.entries.filter(e=>e.expl==='Actively Exploited').length;
  const withPatch = S.entries.filter(e=>e.patch>0).length;
  const statsEl = $('stats-row');
  statsEl.innerHTML = `
    <div class="sc" onclick="setStatFilter('ciseKev')" title="CISA Known Exploited"><span class="sico2">🛡</span><div><div class="sn2">246</div><div class="sl2">CISA KEV</div></div></div>
    <div class="sc" onclick="setStatFilter('ransomware')"><span class="sico2">🔒</span><div><div class="sn2">96</div><div class="sl2">Ransomware</div></div></div>
    <div class="sc" onclick="setStatFilter('malware')"><span class="sico2">🦠</span><div><div class="sn2">125</div><div class="sl2">Malware</div></div></div>
    <div class="sc" onclick="setStatFilter('exploited')"><span class="sico2">🔥</span><div><div class="sn2">${aktExpl}</div><div class="sl2">Actively Exploited</div></div></div>
    <div class="sc" onclick="setStatFilter('patch')"><span class="sico2">🩹</span><div><div class="sn2">${withPatch}</div><div class="sl2">Patch Available</div></div></div>
    <div class="sc" style="border-color:rgba(139,92,246,.3)" onclick="setCatFilter('qrdi')" title="Filter QRDI"><span class="sico2">🔬</span><div><div class="sn2" style="color:var(--qrdi)">${qrdi.length}</div><div class="sl2">Total QRDI</div></div></div>
    <div class="sc" style="border-color:rgba(245,158,11,.25)" onclick="setRtiFilter('debug')"><span class="sico2">🐛</span><div><div class="sn2" style="color:var(--debug)">${debug}</div><div class="sl2">Debug Mode</div></div></div>
    <div class="sc" onclick="setRtiFilter('disabled')"><span class="sico2">⏸</span><div><div class="sn2">${qrdi.filter(e=>!e.enabled).length}</div><div class="sl2">Disabled QRDI</div></div></div>
  `;
}

function renderFilterPanel(){
  const qrdi = S.entries.filter(e=>e.type==='qrdi');
  const luaDot = S.luaLib ? 'ok' : 'off';
  const luaTxt = S.luaLib ? `${S.luaLib.name} <span class="badge b-ok btn-sm">${S.luaLib.status}</span>` : 'No library uploaded';
  $('fp-qrdi-count').textContent = qrdi.length;
  $('fp-debug-count').textContent = qrdi.filter(e=>e.debugLevel>0).length;
  $('fp-disabled-count').textContent = qrdi.filter(e=>!e.enabled).length;
  $('lua-dot').className = `lua-dot ${luaDot}`;
  $('lua-txt').innerHTML = luaTxt;
}

function renderAll(){
  renderTable();
  renderStats();
  renderFilterPanel();
  renderActiveFilters();
}

// ─────────────────────────────────────────────
//  FILTER ACTIONS
// ─────────────────────────────────────────────
function setCatFilter(cat){
  S.filter.category = S.filter.category===cat ? 'all' : cat;
  renderAll();
}
function setSevFilter(sev){
  S.filter.severity = S.filter.severity===sev ? null : sev;
  renderAll();
}
function setRtiFilter(r){
  S.filter.rti = S.filter.rti===r ? null : r;
  renderAll();
}
function setStatFilter(type){ showToast(`Filtered by: ${type}`, 'tinf'); }

// ─────────────────────────────────────────────
//  MODAL OPEN/CLOSE
// ─────────────────────────────────────────────
function openModal(id){ $('ov-'+id).classList.remove('hide'); S.activeModal=id; }
function closeModal(id){ $('ov-'+id).classList.add('hide'); if(S.activeModal===id) S.activeModal=null; }
function closeAllModals(){ ['qrdi-vuln','lua-lib','vuln-info','confirm'].forEach(closeModal); }

// Click overlay to close
document.addEventListener('click', e=>{
  if(e.target.classList.contains('ov')) closeAllModals();
});

// ─────────────────────────────────────────────
//  INFO MODAL
// ─────────────────────────────────────────────
function openInfo(id, e){
  if(e) e.stopPropagation();
  const entry = S.entries.find(x=>x.id===id);
  if(!entry) return;
  const isQ = entry.type==='qrdi';
  const el=$('info-content');
  const sevCls=sevClass(entry.sev);
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
      <span class="badge ${sevCls}">${entry.sev} · ${entry.score}</span>
      ${isQ?`<span class="badge b-qrdi">QRDI</span>`:''}
      ${isQ&&entry.debugLevel>0?`<span class="badge b-debug">Debug Level: ${entry.debugLevel}</span>`:''}
      ${isQ&&!entry.enabled?`<span class="badge b-dis">Disabled</span>`:''}
      ${entry.tc?`<span class="tcbadge">🛡 TruConfirm Validation Available</span>`:''}
    </div>
    <table class="it">
      <tr><td>ID / QID</td><td><b>${isQ?entry.qid:entry.id}</b></td></tr>
      <tr><td>Title</td><td>${escHtml(entry.title)}</td></tr>
      ${isQ?`<tr><td>Category</td><td><span class="badge b-qrdi">QRDI</span></td></tr>`:''}
      ${isQ?`<tr><td>Type</td><td>${escHtml(entry.vulnType||'Vulnerability')}</td></tr>`:''}
      <tr><td>Severity</td><td><span class="badge ${sevCls}">${entry.sev}</span></td></tr>
      <tr><td>CVSS Base</td><td><b>${entry.cvss}</b></td></tr>
      <tr><td>Exploitability</td><td>${entry.expl||'—'}</td></tr>
      <tr><td>Affected Hosts</td><td>${entry.hosts||0}</td></tr>
    </table>
    ${isQ ? `
    <div class="isect">Descriptions</div>
    <table class="it">
      <tr><td>Threat</td><td>${escHtml(entry.threat||'—')}</td></tr>
      <tr><td>Impact</td><td>${escHtml(entry.impact||'—')}</td></tr>
      <tr><td>Solution</td><td>${escHtml(entry.solution||'—')}</td></tr>
    </table>
    <div class="isect">Mappings</div>
    <table class="it">
      <tr><td>CVE IDs</td><td>${entry.cveIds||'—'}</td></tr>
      <tr><td>Bugtraq IDs</td><td>${entry.bugtraqIds||'—'}</td></tr>
      <tr><td>Vendor References</td><td>${(entry.vendorRefs||[]).length?entry.vendorRefs.map(v=>`<a href="${v.url}" style="color:var(--accent)">${v.ref}</a>`).join(', '):'—'}</td></tr>
    </table>
    <div class="isect">QRDI Definition</div>
    <table class="it">
      <tr><td>Detection Type</td><td><span class="code-text">${entry.detectionType||'http dialog'}</span></td></tr>
      <tr><td>Debug Level</td><td>${entry.debugLevel===0?'<span style="color:var(--text-muted)">0 (Off)</span>':`<span class="badge b-debug">${entry.debugLevel}</span>`}</td></tr>
      <tr><td>API Version</td><td>1</td></tr>
    </table>
    <div style="margin-top:10px">
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:5px">JSON Detection Definition</div>
      <textarea class="jed" readonly style="min-height:140px">${escHtml(entry.jsonDef||'{}')}</textarea>
    </div>
    ` : ''}
  `;
  $('info-title').textContent = entry.title;
  $('info-edit-btn').style.display = isQ ? '' : 'none';
  $('info-edit-btn').onclick = ()=>{ closeModal('vuln-info'); openEdit(id); };
  openModal('vuln-info');
}

// ─────────────────────────────────────────────
//  NEW QRDI VULN MODAL
// ─────────────────────────────────────────────
function openNew(){
  S.editEntry = null;
  S.nextQid = Math.max(...S.entries.filter(e=>e.type==='qrdi').map(e=>e.qid), 410005) + 1;
  S.vendorRefs = [];
  S.detType = 'http dialog';
  S.debugSel = 0;
  S.statusEnabled = true;
  S.jsonValid = null;
  resetVulnForm();
  $('vuln-modal-title').textContent = 'New QRDI Vulnerability';
  $('qid-field').value = S.nextQid;
  $('qid-field').readOnly = false;
  $('det-type-http').classList.add('on');
  $('det-type-tcp').classList.remove('on');
  switchModalTab('tab-general');
  openModal('qrdi-vuln');
}

function openEdit(id, e){
  if(e) e.stopPropagation();
  const entry = S.entries.find(x=>x.id===id);
  if(!entry||entry.type!=='qrdi') return;
  S.editEntry = entry;
  S.vendorRefs = [...(entry.vendorRefs||[])];
  S.detType = entry.detectionType||'http dialog';
  S.debugSel = entry.debugLevel||0;
  S.statusEnabled = entry.enabled!==false;
  S.jsonValid = null;
  resetVulnForm();
  $('vuln-modal-title').textContent = 'Edit QRDI Vulnerability';
  $('qid-field').value = entry.qid;
  $('qid-field').readOnly = true;
  $('title-field').value = entry.title;
  $('type-field').value = entry.vulnType||'Vulnerability';
  $('sev-field').value = entry.severity||4;
  $('threat-field').value = entry.threat||'';
  $('impact-field').value = entry.impact||'';
  $('solution-field').value = entry.solution||'';
  $('cve-ids-field').value = entry.cveIds||'';
  $('bugtraq-field').value = entry.bugtraqIds||'';
  $('json-def').value = entry.jsonDef||'{}';
  $('status-toggle').checked = S.statusEnabled;
  $('status-lbl').textContent = S.statusEnabled?'Enabled':'Disabled';
  // detection type
  $('det-type-http').classList.toggle('on', S.detType==='http dialog');
  $('det-type-tcp').classList.toggle('on', S.detType==='tcp dialog');
  // debug
  qsa('.dbg-opt').forEach(opt=>{
    opt.classList.toggle('on', parseInt(opt.dataset.val)===S.debugSel);
  });
  // vendor refs
  renderVendorRefs();
  switchModalTab('tab-general');
  openModal('qrdi-vuln');
}

function resetVulnForm(){
  ['qid-field','title-field','cve-ids-field','bugtraq-field','threat-field','impact-field','solution-field'].forEach(id=>{ if($(id)) $(id).value=''; });
  $('type-field').value='Vulnerability';
  $('sev-field').value='4';
  $('json-def').value='{\n  "detection_type": "http dialog",\n  "api_version": 1,\n  "trigger_type": "service",\n  "title": "",\n  "dialog": []\n}';
  $('status-toggle').checked=true;
  $('status-lbl').textContent='Enabled';
  qsa('.dbg-opt').forEach(o=>o.classList.remove('on'));
  qs('.dbg-opt[data-val="0"]').classList.add('on');
  $('json-status').textContent='';
  $('json-status').className='jstat';
  S.vendorRefs=[];
  renderVendorRefs();
}

function saveQrdiVuln(){
  const qid = parseInt($('qid-field').value);
  const title = $('title-field').value.trim();
  if(!title){ showToast('Title is required','terr'); return; }
  if(!qid||qid<410001||qid>430000){ showToast('QID must be between 410001–430000','terr'); return; }
  if(!S.editEntry && S.entries.find(e=>e.type==='qrdi'&&e.qid===qid)){
    showToast(`QID ${qid} is already in use`,'terr'); return;
  }
  const jsonTxt = $('json-def').value.trim();
  try{ JSON.parse(jsonTxt); }catch(err){ showToast('Invalid JSON in QRDI Definition','terr'); return; }
  const sevNum = parseInt($('sev-field').value);
  const sevLbl = sevFromNum(sevNum);
  const entry = {
    id: S.editEntry ? S.editEntry.id : `QID-${qid}`,
    type:'qrdi', qid, title,
    sub:`${S.detType} – QRDI`,
    sev:sevLbl, score:parseFloat(((sevNum/5)*10).toFixed(1)),
    cvss:parseFloat(((sevNum/5)*10).toFixed(1)),
    expl: S.debugSel>0 ? 'POC Exploit' : '',
    tc:false, hosts:0, jobs:0, actors:0, patch:0,
    riskFactors:['internet'],
    vulnType:$('type-field').value,
    severity:sevNum,
    debugLevel:S.debugSel,
    enabled:$('status-toggle').checked,
    detectionType:S.detType,
    threat:$('threat-field').value,
    impact:$('impact-field').value,
    solution:$('solution-field').value,
    cveIds:$('cve-ids-field').value,
    bugtraqIds:$('bugtraq-field').value,
    vendorRefs:[...S.vendorRefs],
    jsonDef:jsonTxt
  };
  if(S.editEntry){
    const idx=S.entries.findIndex(e=>e.id===S.editEntry.id);
    if(idx>-1) S.entries[idx]=entry;
    showToast(`QID ${qid} updated successfully`,'tok');
  } else {
    S.entries.push(entry);
    showToast(`QID ${qid} created successfully`,'tok');
  }
  closeModal('qrdi-vuln');
  renderAll();
}

// ─────────────────────────────────────────────
//  ENABLE / DISABLE
// ─────────────────────────────────────────────
function toggleEnable(id, e){
  if(e) e.stopPropagation();
  const entry=S.entries.find(x=>x.id===id);
  if(!entry||entry.type!=='qrdi') return;
  const action = entry.enabled!==false ? 'disable' : 'enable';
  S.confirmCb = ()=>{
    entry.enabled = action==='enable';
    showToast(`QID ${entry.qid} ${action}d`,'tok');
    closeModal('confirm');
    renderAll();
  };
  $('cfm-title').textContent = `${action==='disable'?'Disable':'Enable'} QRDI Vulnerability`;
  $('cfm-desc').textContent = `Are you sure you want to ${action} QID ${entry.qid}: "${entry.title}"?`;
  $('cfm-ico').textContent = action==='disable' ? '⏸' : '▶';
  openModal('confirm');
}

// ─────────────────────────────────────────────
//  VENDOR REFS
// ─────────────────────────────────────────────
function renderVendorRefs(){
  const c=$('vendor-refs-list');
  c.innerHTML=S.vendorRefs.map((v,i)=>`
    <div class="vr-row">
      <input class="fi" placeholder="Reference ID" value="${escHtml(v.ref||'')}" oninput="S.vendorRefs[${i}].ref=this.value" />
      <input class="fi" placeholder="URL" value="${escHtml(v.url||'')}" oninput="S.vendorRefs[${i}].url=this.value" />
      <button class="rm-row" onclick="removeVendorRef(${i})">×</button>
    </div>`).join('');
}
function addVendorRef(){ S.vendorRefs.push({ref:'',url:''}); renderVendorRefs(); }
function removeVendorRef(i){ S.vendorRefs.splice(i,1); renderVendorRefs(); }

// ─────────────────────────────────────────────
//  MODAL TABS
// ─────────────────────────────────────────────
function switchModalTab(tabId){
  qsa('.mtab').forEach(t=>t.classList.remove('on'));
  qsa('.tpane').forEach(p=>p.classList.remove('on'));
  const tab = qs(`.mtab[data-tab="${tabId}"]`);
  const pane = $(tabId);
  if(tab) tab.classList.add('on');
  if(pane) pane.classList.add('on');
}

// ─────────────────────────────────────────────
//  JSON VALIDATION
// ─────────────────────────────────────────────
function validateJson(){
  const txt=$('json-def').value.trim();
  const el=$('json-status');
  try{
    const o=JSON.parse(txt);
    if(!o.detection_type||!o.api_version||!o.dialog){
      el.className='jstat err'; el.textContent='⚠ Missing required fields (detection_type, api_version, dialog)';
    } else {
      el.className='jstat ok'; el.textContent='✓ Valid JSON';
    }
  }catch(e){ el.className='jstat err'; el.textContent='✗ '+e.message.slice(0,60); }
}

function uploadJsonFile(){
  const inp=document.createElement('input');
  inp.type='file';
  inp.accept='.json,.txt';
  inp.onchange=e=>{
    const f=e.target.files[0]; if(!f) return;
    const r=new FileReader();
    r.onload=ev=>{ $('json-def').value=ev.target.result; validateJson(); showToast(`Loaded: ${f.name}`,'tok'); };
    r.readAsText(f);
  };
  inp.click();
}

// ─────────────────────────────────────────────
//  LUA LIBRARY MODAL
// ─────────────────────────────────────────────
function openLuaLib(){
  renderLuaModal();
  openModal('lua-lib');
}

function renderLuaModal(){
  const hasLib = !!S.luaLib;
  $('lua-upload-view').style.display = hasLib ? 'none' : 'block';
  $('lua-info-view').style.display = hasLib ? 'block' : 'none';
  if(hasLib){
    const lib=S.luaLib;
    $('lua-info-body').innerHTML=`
      <table class="it">
        <tr><td>ID</td><td>${lib.id}</td></tr>
        <tr><td>Purpose</td><td>QRDI</td></tr>
        <tr><td>LUA File Name</td><td><span class="code-text">${lib.name}</span></td></tr>
        <tr><td>LUA File Size</td><td>${lib.size}</td></tr>
        <tr><td>Library Status</td><td><span class="badge ${lib.status==='Published'?'b-ok':lib.status==='Draft'?'b-debug':'b-dis'}">${lib.status}</span></td></tr>
        <tr><td>Created By</td><td>${lib.createdBy}</td></tr>
        <tr><td>Created On</td><td>${lib.createdOn}</td></tr>
        <tr><td>Last Updated By</td><td>${lib.updatedBy}</td></tr>
        <tr><td>Last Updated On</td><td>${lib.updatedOn}</td></tr>
      </table>`;
  }
}

function saveLuaLib(){
  const nameEl=$('lua-file-name');
  const statusEl=$('lua-status');
  if(!nameEl.value.trim()){ showToast('Please select a Lua library file','terr'); return; }
  S.luaLib={
    id: S.luaLib ? S.luaLib.id : Math.floor(1000+Math.random()*8999),
    name:nameEl.value,
    size:'< 1 MB',
    status:statusEl.value,
    createdBy:'Current User',
    createdOn:new Date().toLocaleString(),
    updatedBy:'N/A',updatedOn:'N/A'
  };
  showToast('Lua Library saved successfully','tok');
  closeModal('lua-lib');
  renderAll();
}

function editLuaLib(){
  $('lua-info-view').style.display='none';
  $('lua-upload-view').style.display='block';
  if(S.luaLib){
    $('lua-file-name').value=S.luaLib.name;
    $('lua-status').value=S.luaLib.status;
  }
}

function deleteLuaLib(){
  S.confirmCb=()=>{
    S.luaLib=null;
    showToast('Lua Library deleted','tok');
    closeModal('confirm');
    renderAll();
  };
  $('cfm-title').textContent='Delete Lua Library';
  $('cfm-desc').textContent='Are you sure you want to delete the Lua library? This cannot be undone.';
  $('cfm-ico').textContent='🗑';
  openModal('confirm');
}

function downloadLuaLib(){
  if(!S.luaLib) return;
  const a=document.createElement('a');
  a.href='data:text/plain;charset=utf-8,-- Lua Library: '+S.luaLib.name;
  a.download=S.luaLib.name;
  a.click();
  showToast('Download started','tinf');
}

// ─────────────────────────────────────────────
//  NEW BUTTON DROPDOWN
// ─────────────────────────────────────────────
function toggleNewDrop(){
  $('new-drop').classList.toggle('open');
}
document.addEventListener('click', e=>{
  if(!e.target.closest('.nbw')) $('new-drop').classList.remove('open');
});

// ─────────────────────────────────────────────
//  LUA FILE PICK
// ─────────────────────────────────────────────
function pickLuaFile(){
  const inp=document.createElement('input');
  inp.type='file';
  inp.accept='.lua,.txt';
  inp.onchange=e=>{
    const f=e.target.files[0]; if(!f) return;
    $('lua-file-name').value=f.name;
    $('lua-chosen').innerHTML=`<div class="file-chosen">📄 ${escHtml(f.name)}</div>`;
    showToast(`Selected: ${f.name}`,'tinf');
  };
  inp.click();
}

// ─────────────────────────────────────────────
//  TAB SWITCHING
// ─────────────────────────────────────────────
function switchTab(tab){
  ['overview','scan','kb'].forEach(t=>{
    const v=$('view-'+t), b=$('tab-btn-'+t);
    if(v) v.classList.toggle('on', t===tab);
    if(b) b.classList.toggle('on', t===tab);
  });
  if(tab==='overview') renderDashboard();
  if(tab==='scan')     renderScanTab();
}

// ─────────────────────────────────────────────
//  JSON SYNTAX HIGHLIGHTING
// ─────────────────────────────────────────────
function syntaxHighlightJson(raw){
  const esc = raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return esc.replace(/("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|[{}\[\],:])/g, m=>{
    if(/^"/.test(m)) return /:$/.test(m) ? `<span class="jk">${m}</span>` : `<span class="js">${m}</span>`;
    if(/true|false/.test(m)) return `<span class="jb">${m}</span>`;
    if(/null/.test(m))       return `<span class="jnu">${m}</span>`;
    if(/^-?\d/.test(m))      return `<span class="jn">${m}</span>`;
    return `<span class="jp">${m}</span>`;
  });
}

function renderJsonHighlight(){
  const prev=$('json-preview');
  if(prev && prev.style.display!=='none') prev.innerHTML=syntaxHighlightJson($('json-def').value);
}

function toggleJsonPreview(){
  const ta=$('json-def'), prev=$('json-preview'), btn=$('json-preview-btn');
  const showingPreview = prev.style.display!=='none';
  if(showingPreview){
    ta.style.display=''; prev.style.display='none'; btn.textContent='🎨 Highlight';
  } else {
    prev.innerHTML=syntaxHighlightJson(ta.value);
    ta.style.display='none'; prev.style.display='block'; btn.textContent='✏ Edit';
  }
}

// ─────────────────────────────────────────────
//  SCAN PROFILES DATA
// ─────────────────────────────────────────────
const SCAN_PROFILES = [
  { id:'sp1', name:'Production Web Servers', assetGroup:'DMZ-PROD-01', schedule:'Daily 02:00',
    desc:'Public-facing web servers — DMZ production zone', checks:[
      {qid:410001,enabled:true}, {qid:410003,enabled:true}
    ], results:[
      {qid:410001,title:'Apache HTTP Server Version Disclosure',sev:'High',found:true,
       result:'Apache version: 2.4.51',
       evidence:'HTTP/1.1 200 OK\nServer: Apache/2.4.51 (Ubuntu)\nContent-Type: text/html',
       debug:'[100] Detection started: Apache HTTP Server Version Disclosure\n[200] TX1 http get / -> HTTP 200\n[200] TX2 process regexp match: Apache/2.4.51\n[300] VAR apache_ver = \'2.4.51\'\n[100] Detection ended: VULNERABLE',
       ts:'2026-04-02 03:12'},
      {qid:410003,title:'Cross-Site Scripting (XSS) Detection',sev:'Critical',found:true,
       result:'XSS reflection confirmed in search parameter',
       evidence:'GET /search?q="><script>alert(73541);</script> HTTP/1.1\nHost: 10.0.1.47\n\nHTTP/1.1 200 OK\n...<body>Results for: "><script>alert(73541);</script></body>',
       debug:'[100] Detection started: XSS Detection\n[200] TX1 http get /search?q=... -> HTTP 200\n[200] TX2 process regexp MATCH FOUND\n[100] Detection ended: VULNERABLE',
       ts:'2026-04-02 03:14'},
    ]},
  { id:'sp2', name:'Internal Mail Servers', assetGroup:'CORP-MAIL', schedule:'Weekly Mon',
    desc:'Internal IMAP / SMTP mail infrastructure', checks:[
      {qid:410002,enabled:true}
    ], results:[
      {qid:410002,title:'IMAP Authentication Check',sev:'High',found:true,
       result:'a001 NO [AUTHENTICATIONFAILED] Invalid credentials',
       evidence:'SENT: a001 LOGIN testuser testpass\nRECV: * OK Dovecot ready.\na001 NO [AUTHENTICATIONFAILED] Invalid credentials',
       debug:'[100] Detection started: IMAP Auth Check\n[200] TX1 send LOGIN -> ok\n[200] TX2 receive luapattern match found\n[100] Detection ended: VULNERABLE',
       ts:'2026-04-01 09:10'},
    ]},
  { id:'sp3', name:'Windows File Servers', assetGroup:'WIN-FS-POOL', schedule:'Daily 04:00',
    desc:'Windows SMB file server pool', checks:[
      {qid:410004,enabled:true}
    ], results:[
      {qid:410004,title:'SMB Protocol Version Detection',sev:'Critical',found:false,
       result:'',
       evidence:'',
       debug:'[100] Detection started: SMB Detection\n[200] TX1 send SMBv1 negotiate\n[200] TX2 receive -> TIMEOUT after 10000ms',
       errors:'RESULT_ERRORS: Connection timed out after 10000ms on 10.0.3.21:445',
       ts:'2026-04-01 11:45'},
    ]},
];

const WIZ = { step:1, entryId:null, profileId:null };
const ATTACH = { profileId:null, selectedQid:null };

// ─────────────────────────────────────────────
//  SCAN TAB RENDER
// ─────────────────────────────────────────────
function renderScanTab(){
  const list=$('profile-list');
  list.innerHTML=SCAN_PROFILES.map(p=>`
    <div class="profile-item ${S._activeProfile===p.id?'on':''}" onclick="selectProfile('${p.id}')">
      <div class="pi-name">${escHtml(p.name)}</div>
      <div class="pi-meta">${p.checks.length} QRDI check${p.checks.length!==1?'s':''} attached</div>
    </div>`).join('');
  if(S._activeProfile) renderProfileDetail(S._activeProfile);
}

function selectProfile(id){
  S._activeProfile=id;
  renderScanTab();
  renderProfileDetail(id);
}

function renderProfileDetail(id){
  const profile=SCAN_PROFILES.find(p=>p.id===id);
  if(!profile) return;

  $('scan-right-hdr').innerHTML=`
    <div>
      <div style="font-size:14px;font-weight:600">${escHtml(profile.name)}</div>
      <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
        Asset Group: <b style="color:var(--text-primary)">${escHtml(profile.assetGroup||'—')}</b>
        &nbsp;·&nbsp; Schedule: ${escHtml(profile.schedule||'—')}
        &nbsp;·&nbsp; ${escHtml(profile.desc||'')}
      </div>
    </div>
    <div style="display:flex;gap:7px">
      <button class="btn btn-q btn-sm" onclick="openAttachSelector('${id}')">+ Attach QRDI Check</button>
    </div>`;

  const checks=profile.checks;
  const checksHtml = checks.length===0
    ? `<div class="attach-empty"><div class="ei">🔬</div><p>No QRDI checks attached yet.<br>Click <b>+ Attach QRDI Check</b> to add one.</p></div>`
    : checks.map(c=>{
        const entry=S.entries.find(e=>e.type==='qrdi'&&e.qid===c.qid);
        if(!entry) return '';
        const sevCls=sevClass(entry.sev);
        return `<div class="qrdi-attach-row">
          <div class="qar-info">
            <div class="qar-title">QID ${entry.qid} — ${escHtml(entry.title)}</div>
            <div class="qar-meta"><span class="badge ${sevCls}">${entry.sev}</span> <span class="badge b-qrdi">QRDI</span> <span class="code-text">${entry.detectionType}</span></div>
          </div>
          <div class="qar-actions">
            <div class="tog-wrap">
              <label class="tog"><input type="checkbox" ${c.enabled?'checked':''} onchange="togglePerScan('${id}',${c.qid},this.checked)"><span class="tslider"></span></label>
              <span class="tog-lbl" style="font-size:11px">${c.enabled?'Enabled':'Disabled'}</span>
            </div>
            <button class="btn btn-d btn-sm" onclick="detachCheck('${id}',${c.qid})">✕</button>
          </div>
        </div>`;
      }).join('');

  const resultsHtml = profile.results.length===0
    ? `<div class="attach-empty" style="padding:16px"><div class="ei" style="font-size:20px">📊</div><p style="font-size:11px">No scan results yet for this profile.</p></div>`
    : profile.results.map(r=>`
      <div class="res-row" onclick="openFindingDetail(${JSON.stringify(r).replace(/"/g,'&quot;')})">
        <div class="res-ico">${r.sev==='Critical'?'🔴':r.sev==='High'?'🟠':'🟡'}</div>
        <div class="res-body">
          <div class="res-title">${escHtml(r.title)}</div>
          <div class="res-meta">
            <span class="res-badge">🔬 Custom Detection</span>
            <span class="udl">User-Defined</span>
            <span>QID ${r.qid}</span>
            <span>${r.ts}</span>
          </div>
        </div>
        <div class="res-sev"><span class="badge ${sevClass(r.sev)}">${r.sev}</span></div>
      </div>`).join('');

  $('scan-right-body').innerHTML=`
    <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Attached QRDI Checks <span style="color:var(--text-primary);font-size:13px;text-transform:none;font-weight:700;margin-left:6px">${checks.length}</span></div>
    ${checksHtml}
    <div class="results-section">
      <h3>Latest Scan Results — Custom Findings</h3>
      ${resultsHtml}
    </div>`;
}

function togglePerScan(profileId, qid, enabled){
  const p=SCAN_PROFILES.find(p=>p.id===profileId);
  if(!p) return;
  const c=p.checks.find(c=>c.qid===qid);
  if(c){ c.enabled=enabled; showToast(`QID ${qid} ${enabled?'enabled':'disabled'} for ${p.name}`,'tok'); }
}

function detachCheck(profileId, qid){
  const p=SCAN_PROFILES.find(p=>p.id===profileId);
  if(!p) return;
  p.checks=p.checks.filter(c=>c.qid!==qid);
  showToast(`QID ${qid} detached from ${p.name}`,'tok');
  renderProfileDetail(profileId);
  renderScanTab();
}

function newProfile(){
  const name=prompt('Scan profile name:');
  if(!name) return;
  const id='sp'+Date.now();
  SCAN_PROFILES.push({id,name,desc:'Custom scan profile',checks:[],results:[]});
  S._activeProfile=id;
  renderScanTab();
  showToast(`Profile "${name}" created`,'tok');
}

// ─────────────────────────────────────────────
//  ATTACH SELECTOR
// ─────────────────────────────────────────────
function openAttachSelector(profileId){
  ATTACH.profileId=profileId;
  ATTACH.selectedQid=null;
  const p=SCAN_PROFILES.find(x=>x.id===profileId);
  $('attach-profile-name').textContent=p?p.name:'';
  const attachedQids=(p?p.checks:[]).map(c=>c.qid);
  const available=S.entries.filter(e=>e.type==='qrdi'&&e.enabled!==false&&!attachedQids.includes(e.qid));
  if(!available.length){
    $('attach-selector-list').innerHTML=`<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:16px">All active QRDI checks are already attached to this profile.</div>`;
  } else {
    $('attach-selector-list').innerHTML=available.map(e=>`
      <div class="as-row" id="as-${e.qid}" onclick="selectAttach(${e.qid})">
        <div style="flex:1">
          <div style="font-size:12px;font-weight:500;color:var(--text-primary)">QID ${e.qid} — ${escHtml(e.title)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px"><span class="badge ${sevClass(e.sev)}">${e.sev}</span> <span class="code-text">${e.detectionType}</span></div>
        </div>
        <input type="radio" name="attach-qid" value="${e.qid}" style="accent-color:var(--accent)">
      </div>`).join('');
  }
  openModal('attach-selector');
}

function selectAttach(qid){
  ATTACH.selectedQid=qid;
  document.querySelectorAll('.attach-selector .as-row').forEach(r=>r.classList.remove('on'));
  const row=document.getElementById('as-'+qid);
  if(row){ row.classList.add('on'); const radio=row.querySelector('input'); if(radio) radio.checked=true; }
}

function confirmAttach(){
  if(!ATTACH.selectedQid){ showToast('Select a QRDI check first','terr'); return; }
  const p=SCAN_PROFILES.find(x=>x.id===ATTACH.profileId);
  if(!p) return;
  if(p.checks.find(c=>c.qid===ATTACH.selectedQid)){ showToast('Already attached','terr'); return; }
  p.checks.push({qid:ATTACH.selectedQid,enabled:true});
  closeModal('attach-selector');
  showToast(`QID ${ATTACH.selectedQid} attached to ${p.name}`,'tok');
  renderProfileDetail(ATTACH.profileId);
  renderScanTab();
}

// ─────────────────────────────────────────────
//  FINDING DETAIL MODAL
// ─────────────────────────────────────────────
function openFindingDetail(finding){
  if(typeof finding==='string') finding=JSON.parse(finding.replace(/&quot;/g,'"'));
  $('finding-title').innerHTML=`🔬 ${escHtml(finding.title)} <span class="udl" style="margin-left:6px">User-Defined</span>`;
  $('finding-body').innerHTML=`
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">
      <span class="badge ${sevClass(finding.sev)}">${finding.sev}</span>
      <span class="res-badge">🔬 Custom Detection</span>
      <span class="udl">User-Defined</span>
      <span class="badge b-qrdi">QRDI</span>
      <span style="font-size:11px;color:var(--text-muted)">QID ${finding.qid} · ${finding.ts}</span>
    </div>
    <table class="it">
      <tr><td>Detection Title</td><td><b>${escHtml(finding.title)}</b></td></tr>
      <tr><td>QID</td><td>${finding.qid}</td></tr>
      <tr><td>Result</td><td>${escHtml(finding.result)}</td></tr>
      <tr><td>Severity</td><td><span class="badge ${sevClass(finding.sev)}">${finding.sev}</span></td></tr>
      <tr><td>Scan Time</td><td>${finding.ts}</td></tr>
      <tr><td>Detection Type</td><td>Custom User-Defined (QRDI)</td></tr>
    </table>
    <div class="isect" style="margin-top:14px">Evidence</div>
    <div class="fd-evidence">${escHtml(finding.evidence||'No evidence captured.')}</div>
    ${finding.debug?`<div class="isect" style="margin-top:10px">Debug Output</div><div class="fd-debug">${escHtml(finding.debug)}</div>`:''}`;
  openModal('finding');
}

// ─────────────────────────────────────────────
//  ACTIVATION WIZARD
// ─────────────────────────────────────────────
function openActivateFromInfo(){
  const id=S._infoEntryId;
  if(id) openActivate(id);
}

function openActivate(entryId, e){
  if(e) e.stopPropagation();
  WIZ.step=1; WIZ.entryId=entryId; WIZ.profileId=null;
  updateWizardUI();
  openModal('activate');
}

function updateWizardUI(){
  const steps=[1,2,3];
  steps.forEach(i=>{
    const s=$('wiz-s'+i), d=$('wiz-d'+i);
    s.className='wiz-step'+(i<WIZ.step?' done':i===WIZ.step?' active':' pending');
    d.textContent=i<WIZ.step?'✓':String(i);
  });
  const entry=S.entries.find(e=>e.id===WIZ.entryId);
  const content=$('wiz-content');
  const ftr=$('wiz-ftr');

  if(WIZ.step===1){
    let jsonOk=false, hasReport=false, hasDetType=false;
    const rawDef = entry && (entry.jsonDef || entry.definition || '');
    if(rawDef){
      try{
        const parsed = typeof rawDef==='string' ? JSON.parse(rawDef) : rawDef;
        jsonOk=true;
        hasDetType=!!(parsed.detection_type&&parsed.api_version);
        hasReport=!!(parsed.dialog&&parsed.dialog.some(t=>t.transaction==='report'));
      }catch(e){}
    }
    const rows=[
      {ok:true, lbl:'QRDI vulnerability exists (QID '+( entry?entry.qid:'—')+')'},
      {ok:jsonOk, lbl:'JSON definition is valid and parseable'},
      {ok:hasDetType, lbl:'detection_type and api_version fields present'},
      {ok:hasReport, lbl:'dialog array contains a report transaction'},
      {ok:entry&&entry.enabled!==false, lbl:'Vulnerability is enabled'},
    ];
    content.innerHTML=`
      <div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">Running pre-activation validation for <b>${entry?escHtml(entry.title):'Unknown'}</b>…</div>
      ${rows.map(r=>`<div class="wiz-check-row ${r.ok?'ok':'err'}">
        <span class="wiz-check-ico">${r.ok?'✅':'❌'}</span>
        <span class="wiz-check-lbl">${r.lbl}</span>
      </div>`).join('')}
      ${rows.every(r=>r.ok)?'<div style="margin-top:12px;font-size:12px;color:var(--success)">✓ All checks passed. Ready to proceed.</div>':'<div style="margin-top:12px;font-size:12px;color:var(--critical)">Fix the issues above before activating.</div>'}`;
    const allOk=rows.every(r=>r.ok);
    ftr.innerHTML=`<button class="btn btn-s" onclick="closeModal('activate')">Cancel</button><button class="btn btn-p" onclick="wizNext()" ${allOk?'':'disabled'}>Next →</button>`;
  }

  if(WIZ.step===2){
    content.innerHTML=`
      <div style="font-size:12px;color:var(--text-secondary);margin-bottom:12px">Select the scan profile to attach <b>${entry?escHtml(entry.title):''}</b> to:</div>
      <div class="profile-picker">
        ${SCAN_PROFILES.map(p=>`
          <div class="pp-item ${WIZ.profileId===p.id?'on':''}" onclick="WIZ.profileId='${p.id}';updateWizardUI()">
            <input type="radio" ${WIZ.profileId===p.id?'checked':''} style="accent-color:var(--accent)">
            <div>
              <div class="pp-name">${escHtml(p.name)}</div>
              <div class="pp-meta">Asset Group: <b>${escHtml(p.assetGroup||'—')}</b> &nbsp;·&nbsp; ${escHtml(p.schedule||'No schedule')} &nbsp;·&nbsp; ${p.checks.length} check${p.checks.length!==1?'s':''} attached</div>
            </div>
          </div>`).join('')}
      </div>`;
    ftr.innerHTML=`<button class="btn btn-s" onclick="WIZ.step=1;updateWizardUI()">← Back</button><button class="btn btn-s" onclick="closeModal('activate')">Cancel</button><button class="btn btn-p" onclick="wizNext()" ${WIZ.profileId?'':'disabled'}>Next →</button>`;
  }

  if(WIZ.step===3){
    const prof=SCAN_PROFILES.find(p=>p.id===WIZ.profileId);
    content.innerHTML=`
      <table class="it" style="margin-bottom:14px">
        <tr><td>QRDI Check</td><td><b>${entry?escHtml(entry.title):''}</b> (QID ${entry?entry.qid:''})</td></tr>
        <tr><td>Scan Profile</td><td><b>${prof?escHtml(prof.name):''}</b></td></tr>
        <tr><td>Detection Type</td><td><span class="code-text">${entry?(entry.detType||entry.detectionType||'http dialog'):''}</span></td></tr>
        <tr><td>Debug Level</td><td>${entry&&entry.debugLevel>0?`<span class="badge b-debug">Level ${entry.debugLevel}</span>`:'Off (0)'}</td></tr>
        <tr><td>Status after attach</td><td><span class="badge b-ok">Enabled</span></td></tr>
      </table>
      <div style="font-size:12px;color:var(--text-muted)">Confirming will attach this QRDI check to the selected scan profile. It will execute alongside native checks on the next scan run.</div>`;
    ftr.innerHTML=`<button class="btn btn-s" onclick="WIZ.step=2;updateWizardUI()">← Back</button><button class="btn btn-s" onclick="closeModal('activate')">Cancel</button><button class="btn btn-p" onclick="confirmActivation()">⚡ Confirm Activation</button>`;
  }
}

function wizNext(){
  if(WIZ.step<3){ WIZ.step++; updateWizardUI(); }
}

function confirmActivation(){
  const prof=SCAN_PROFILES.find(p=>p.id===WIZ.profileId);
  const entry=S.entries.find(e=>e.id===WIZ.entryId);
  if(!prof||!entry) return;
  if(!prof.checks.find(c=>c.qid===entry.qid)) prof.checks.push({qid:entry.qid,enabled:true});
  // Mark lifecycle stage
  entry._stage='attached';
  closeModal('activate');
  closeModal('vuln-info');
  showToast(`QID ${entry.qid} activated on "${prof.name}" ✓`,'tok');
  renderAll();
}

// Expose openActivate for quick action row
S._infoEntryId=null;

// ─────────────────────────────────────────────
//  OVERVIEW METRICS DASHBOARD
// ─────────────────────────────────────────────
function renderDashboard(){
  const qrdi=S.entries.filter(e=>e.type==='qrdi');
  const attached=qrdi.filter(e=>e._stage==='attached'||SCAN_PROFILES.some(p=>p.checks.find(c=>c.qid===e.qid)));
  const debugOn=qrdi.filter(e=>e.debugLevel>0);
  const aiGenCount=qrdi.filter(e=>e._aiGenerated).length;
  const totalFindings=SCAN_PROFILES.reduce((s,p)=>s+p.results.length,0);

  $('metric-grid').innerHTML=`
    <div class="metric-card mc-purple"><div class="mc-val" style="color:var(--qrdi)">${qrdi.length}</div><div class="mc-lbl">Total QRDI Checks</div><div class="mc-sub">↑ Active custom detections</div></div>
    <div class="metric-card mc-green"><div class="mc-val" style="color:var(--success)">${attached.length}</div><div class="mc-lbl">Attached to Profiles</div><div class="mc-sub">↑ ${qrdi.length>0?Math.round(attached.length/qrdi.length*100):0}% activation rate</div></div>
    <div class="metric-card mc-blue"><div class="mc-val" style="color:var(--accent)">${totalFindings}</div><div class="mc-lbl">Custom Findings Reported</div><div class="mc-sub">↑ From last scan run</div></div>
    <div class="metric-card mc-amber"><div class="mc-val" style="color:var(--debug)">${debugOn.length}</div><div class="mc-lbl">In Debug Mode</div><div class="mc-sub ${debugOn.length>0?'neg':''}">⚠ Review before production</div></div>`;

  // Lifecycle board
  const stages=[
    {lbl:'Author',icon:'✍',count:qrdi.length,state:'done'},
    {lbl:'Validate',icon:'✓',count:qrdi.filter(e=>{try{const d=e.jsonDef||e.definition;JSON.parse(typeof d==='string'?d:JSON.stringify(d));return true;}catch(x){return false;}}).length,state:'done'},
    {lbl:'Attach',icon:'🔗',count:attached.length,state:attached.length>0?'done':'active'},
    {lbl:'Execute',icon:'▶',count:totalFindings,state:'active'},
    {lbl:'Report',icon:'📊',count:totalFindings,state:totalFindings>0?'done':'pending'},
    {lbl:'Iterate',icon:'🔄',count:qrdi.filter(e=>e._stage==='iterated').length,state:'pending'},
  ];
  $('lc-steps').innerHTML=stages.map(st=>`
    <div class="lc-step ${st.state}">
      <div class="lc-dot">${st.icon}</div>
      <div class="lc-step-lbl">${st.lbl}</div>
      <div class="lc-count">${st.count}</div>
    </div>`).join('');

  // Bar chart — last 7 days (mock data)
  const days=[{d:'Mon',v:1},{d:'Tue',v:0},{d:'Wed',v:2},{d:'Thu',v:1},{d:'Fri',v:3},{d:'Sat',v:0},{d:'Sun',v:2}];
  const max=Math.max(...days.map(d=>d.v),1);
  $('bar-chart-body').innerHTML=days.map(d=>`
    <div class="bar-row">
      <span class="bar-label">${d.d}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round(d.v/max*100)}%;background:var(--qrdi)"></div></div>
      <span class="bar-val">${d.v}</span>
    </div>`).join('');

  // Activity feed
  const activities=[
    {dot:'var(--success)',title:'QID 410001 – Apache Version Disclosure activated on Production Web Servers (DMZ-PROD-01)',time:'2 hours ago'},
    {dot:'var(--qrdi)',title:'AI-generated signature for "XSS detection in login page" applied to editor',time:'4 hours ago'},
    {dot:'var(--accent)',title:'QID 410003 – XSS Detection: VULNERABLE finding on 10.0.1.47 (DMZ-PROD-01)',time:'6 hours ago'},
    {dot:'var(--debug)',title:'QID 410002 – IMAP Auth Check activated on Internal Mail Servers (CORP-MAIL)',time:'Yesterday'},
    {dot:'var(--medium)',title:'QID 410004 – SMB Version Detection attached to Windows File Servers (WIN-FS-POOL)',time:'2 days ago'},
    {dot:'var(--critical)',title:'QID 410005 – SQL Error Disclosure disabled globally',time:'3 days ago'},
  ];
  $('activity-feed').innerHTML=activities.map(a=>`
    <div class="af-row">
      <div class="af-dot" style="background:${a.dot}"></div>
      <div class="af-body"><div class="af-title">${a.title}</div><div class="af-time">${a.time}</div></div>
    </div>`).join('');
}

// ─────────────────────────────────────────────
//  OVERRIDE openInfo TO TRACK ENTRY FOR WIZARD
// ─────────────────────────────────────────────
const _origOpenInfo = openInfo;
openInfo = function(id, e){
  S._infoEntryId = id;
  _origOpenInfo(id, e);
  const entry = S.entries.find(x=>x.id===id);
  if(entry && entry.type==='qrdi'){
    $('info-activate-btn').style.display='';
    // Add lifecycle stepper to info modal
    setTimeout(()=>{
      const body=$('info-content');
      if(body){
        const stage=SCAN_PROFILES.some(p=>p.checks.find(c=>c.qid===entry.qid))?'attached':'validate';
        const stepper=document.createElement('div');
        stepper.style.cssText='margin-bottom:14px';
        stepper.innerHTML=`
          <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Lifecycle Status</div>
          <div style="display:flex;align-items:center;gap:0">
            ${['Author','Validate','Attach','Execute','Report','Iterate'].map((lbl,i)=>{
              const done = i===0||(i===1&&(entry.jsonDef||entry.definition))||(i===2&&stage==='attached');
              const active = i===2&&stage!=='attached';
              return `<div style="flex:1;text-align:center;position:relative">
                ${i<5?`<div style="position:absolute;top:14px;left:50%;width:100%;height:2px;background:${done?'var(--accent)':'var(--border)'}"></div>`:''}
                <div style="width:28px;height:28px;border-radius:50%;border:2px solid ${done?'var(--accent)':active?'var(--qrdi)':'var(--border)'};background:${done?'var(--accent-light)':active?'var(--qrdi-bg)':'var(--bg-card)'};display:flex;align-items:center;justify-content:center;margin:0 auto 4px;position:relative;z-index:1;font-size:11px;color:${done?'var(--accent)':active?'var(--qrdi)':'var(--text-muted)'}">${done?'✓':i+1}</div>
                <div style="font-size:9px;color:${done?'var(--accent)':active?'var(--qrdi)':'var(--text-muted)'};font-weight:${active||done?'600':'400'}">${lbl}</div>
              </div>`;
            }).join('')}
          </div>`;
        body.insertBefore(stepper, body.firstChild);
      }
    }, 0);
  } else {
    $('info-activate-btn').style.display='none';
  }
};

// Add Activate quick action to table rows
const _origRenderTable=renderTable;
renderTable=function(){
  _origRenderTable();
  // Inject activate button into QRDI quick actions
};

// ─────────────────────────────────────────────
//  AI SIGNATURE ASSISTANT
// ─────────────────────────────────────────────

const QRDI_SYSTEM_PROMPT = `You are an expert in Qualys Remote Detection Interface (QRDI) vulnerability signatures.
Your task is to generate valid, executable QRDI JSON detection signatures from natural language descriptions.

STRICT RULES:
1. Output ONLY a valid JSON object — no markdown, no code fences, no explanation text before or after the JSON.
2. The JSON MUST be directly executable by the QRDI scan engine without any manual edits.
3. Always include: detection_type, api_version (always 1), trigger_type, title, and dialog array.
4. The "dialog" array must end with a "report" transaction to post the QID result.

SCHEMA REFERENCE:

Top-level fields:
- "detection_type": "http dialog" | "tcp dialog"  (required)
- "api_version": 1  (required, always 1)
- "trigger_type": "service" | "virtual host"  (HTTP); "service" | "port"  (TCP)
- "title": string describing the detection
- "debug_level": 0 | 100 | 200 | 300 | 400  (optional, default 0)
- "ports": integer or [integer, ...]  (optional)
- "os": "PCRE regex"  (optional, match target OS)
- "not_os": "PCRE regex"  (optional, exclude OS)
- "timeout": milliseconds, max 180000  (optional)
- "services": ["service-name", ...]  (TCP dialog only, when trigger_type is "service")

HTTP DIALOG TRANSACTIONS:
1. "http get" — sends HTTP GET
   { "transaction": "http get", "object": "/path", "http_header": "Header: value\n", "timeout": ms, "on_error": action }
   After: system variable "body" = response body, "http_status" = status code

2. "http post" — sends HTTP POST
   { "transaction": "http post", "object": "/path", "data": eval-expr, "http_header": "..." }

3. "process" — pattern match on data (default source is "body")
   { "transaction": "process", "mode": "substring"|"regexp"|"luapattern", "match": "pattern",
     "source": eval-expr (optional), "extract": [{"var":"name"}, ...] (optional),
     "on_found": action, "on_missing": action }

4. "report" — post the QID result (always last transaction that fires)
   { "transaction": "report", "result": eval-expr }

TCP DIALOG TRANSACTIONS:
1. "send" — send data to target
   { "transaction": "send", "data": eval-expr, "on_error": action }

2. "receive" — wait for data (same fields as process + wait action + timeout)
   { "transaction": "receive", "mode": "...", "match": "...", "timeout": ms }

3. "process" — same as HTTP process
4. "reconnect" — close and reopen TCP connection
5. "report" — same as HTTP report

RETURN ACTIONS (values for on_found, on_missing, on_error):
- "continue"  (default for on_found; proceed to next transaction)
- "stop"  (do not post QID)
- "report"  (jump to next report transaction)
- {"action": "goto", "label": "label-name"}
- {"action": "error", "message": "error message"}

EVAL-EXPRESSIONS (used in result, data, source, match when dynamic):
- String: "literal string"
- Integer: 123
- User variable: {"user": "varname"}
- System variable: {"system": "body"}  or  {"system": "http_status"}
- Concatenation: {"concat": ["string1", {"system": "body"}, " suffix"]}
- Lua call: {"call": {"name": "qrdiuser_functionname"}}

IMPORTANT NOTES:
- HTTP redirects are NOT followed. Handle 3xx using http_status_map if needed.
- The "process" default source is the HTTP body (system variable "body").
- For TCP, "receive" accumulates data until the match condition is met. Use "wait" to keep receiving.
- Never use HTTP dialog for raw TCP protocols (SMB, FTP data, etc.) — use tcp dialog.
- "extract" extracts regex sub-patterns into user variables. Index 0 = full match, 1+ = sub-groups.
- Labels in "goto" must match a "label" field on another transaction.
- All transactions execute serially unless a goto/stop/report action redirects flow.

COMMON PATTERNS:
- XSS: http get to inject payload → process regexp to find reflection → report
- Banner grab (TCP): receive banner → process regexp to extract version → report version
- HTTP response check: http get → process substring/regexp → report
- Auth test: send credentials (TCP) → receive response → process to verify → report
- Header check: http get with custom headers → process body → report

Always produce the minimum necessary dialog steps. Do not add unnecessary transactions.`;

const AI_IMPROVE_SUFFIX = `\n\nIMPROVE MODE: The user has provided an existing QRDI JSON signature and wants it improved.
Analyse the existing JSON for: missing error handling, incomplete match patterns, lack of variable extraction,
missing timeout fields, or structural issues that would prevent execution.
Return the improved JSON only — same format rules apply.`;

// ── AI STATE ──
const AI = {
  mode: 'generate',      // 'generate' | 'improve'
  apiKey: sessionStorage.getItem('qrdi_ai_key') || '',
  lastGenerated: null,
};

function toggleAIPanel(){
  const p=$('ai-panel');
  const isHidden = p.style.display==='none';
  p.style.display = isHidden ? 'block' : 'none';
  if(isHidden && AI.apiKey){ checkAIKeyStatus(); }
}

function setAIMode(mode){
  AI.mode = mode;
  $('ai-mode-generate').classList.toggle('on', mode==='generate');
  $('ai-mode-improve').classList.toggle('on', mode==='improve');
  const labelEl = $('ai-prompt-label-txt');
  const hintEl  = $('ai-hint-chips');
  const taEl    = $('ai-prompt');
  const btnEl   = $('ai-gen-btn').querySelector('.ai-btn-txt');
  if(mode==='improve'){
    labelEl.textContent = 'Describe what to improve (or leave blank to auto-analyse):';
    hintEl.innerHTML = `
      <span class="ai-hint-chip" onclick="setAIHint(this)">Add better error handling</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Extract version into variable</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Add OS filtering</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Improve regex pattern precision</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Add timeout handling</span>`;
    taEl.placeholder = 'e.g. Add on_error handling to the http get transaction and extract the server version into a variable...';
    btnEl.textContent = '⟳ Improve Signature';
  } else {
    labelEl.textContent = 'Describe the vulnerability or behaviour you want to detect:';
    hintEl.innerHTML = `
      <span class="ai-hint-chip" onclick="setAIHint(this)">Detect XSS in login page</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Check SMB version via TCP</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Grab HTTP server banner</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Test IMAP authentication</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Detect SQL error in response</span>
      <span class="ai-hint-chip" onclick="setAIHint(this)">Check for open redirect</span>`;
    taEl.placeholder = 'e.g. Check if the HTTP server exposes its version in the Server response header, and report the version string if found...';
    btnEl.textContent = '✦ Generate Signature';
  }
}

function setAIHint(el){
  $('ai-prompt').value = el.textContent.trim();
  $('ai-prompt').focus();
}

function saveAIKey(){
  const key = $('ai-api-key').value.trim();
  if(!key){ showToast('Please enter an API key','terr'); return; }
  AI.apiKey = key;
  sessionStorage.setItem('qrdi_ai_key', key);
  checkAIKeyStatus();
  showToast('API key saved for this session','tok');
}

function checkAIKeyStatus(){
  const el = $('ai-key-status');
  if(AI.apiKey && AI.apiKey.startsWith('sk-ant')){
    el.className='ai-key-status set'; el.textContent='● Key set';
    $('ai-api-key').value = AI.apiKey.slice(0,14)+'...';
  } else if(AI.apiKey){
    el.className='ai-key-status set'; el.textContent='● Key set';
  } else {
    el.className='ai-key-status unset'; el.textContent='● Not set';
  }
}

async function runAIGenerate(){
  const prompt = $('ai-prompt').value.trim();
  if(!prompt){ showToast('Please describe what you want to detect','terr'); return; }

  const btn    = $('ai-gen-btn');
  const status = $('ai-status-msg');
  const output = $('ai-output');

  btn.disabled = true;
  btn.classList.add('loading');
  output.classList.remove('show');
  status.textContent = 'Generating signature…';

  try {
    let jsonStr, explanation, confidence;
    if(AI.apiKey && AI.apiKey.length > 10){
      const result = await callClaudeAPI(prompt);
      jsonStr     = result.json;
      explanation = result.explanation;
      confidence  = result.confidence;
    } else {
      // Smart fallback generator — no API key needed
      await new Promise(r=>setTimeout(r,900));
      const result = smartGenerateQRDI(prompt, AI.mode==='improve' ? $('json-def').value : null);
      jsonStr     = result.json;
      explanation = result.explanation;
      confidence  = result.confidence;
    }

    // Validate the generated JSON
    JSON.parse(jsonStr); // throws if invalid
    AI.lastGenerated = jsonStr;

    $('ai-out-json').textContent = jsonStr;
    $('ai-explanation').innerHTML = explanation;
    const dot = $('ai-conf-dot');
    const txt = $('ai-conf-txt');
    dot.className = `ai-conf-dot ${confidence}`;
    txt.textContent = confidence==='high' ? 'High confidence — ready to deploy'
                    : confidence==='med'  ? 'Medium confidence — review before deploying'
                    : 'Low confidence — manual review required';
    output.classList.add('show');
    status.textContent = '';
  } catch(err){
    status.textContent = '';
    showToast('Generation failed: ' + (err.message||'Unknown error'), 'terr');
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

async function callClaudeAPI(userPrompt){
  const apiKey = $('ai-api-key').value.includes('...') ? AI.apiKey : $('ai-api-key').value.trim() || AI.apiKey;
  const systemPrompt = AI.mode==='improve'
    ? QRDI_SYSTEM_PROMPT + AI_IMPROVE_SUFFIX
    : QRDI_SYSTEM_PROMPT;

  const userContent = AI.mode==='improve'
    ? `Existing QRDI JSON:\n${$('json-def').value}\n\nImprovement request: ${userPrompt||'Analyse and improve this signature.'}`
    : `Detection requirement: ${userPrompt}`;

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true'
    },
    body: JSON.stringify({
      model: 'claude-opus-4-5',
      max_tokens: 2048,
      system: systemPrompt,
      messages: [{ role: 'user', content: userContent }]
    })
  });

  if(!resp.ok){
    const err = await resp.json().catch(()=>({}));
    throw new Error(err.error?.message || `API error ${resp.status}`);
  }

  const data = await resp.json();
  const raw  = data.content[0].text.trim();

  // Extract JSON from response (handle any stray text)
  const jsonMatch = raw.match(/\{[\s\S]*\}/);
  if(!jsonMatch) throw new Error('No valid JSON in API response');
  const jsonStr = jsonMatch[0];
  JSON.parse(jsonStr); // validate

  // Build explanation from parsed JSON
  const parsed = JSON.parse(jsonStr);
  const explanation = buildExplanation(parsed, userPrompt);
  const confidence  = scoreConfidence(parsed);
  return { json: JSON.stringify(parsed, null, 2), explanation, confidence };
}

// ── SMART FALLBACK GENERATOR (no API key required) ──
function smartGenerateQRDI(prompt, existingJson){
  const p = prompt.toLowerCase();

  if(existingJson && AI.mode==='improve'){
    return improveExisting(existingJson, prompt);
  }

  // Classify intent
  const isTCP   = /\b(tcp|smb|ftp|imap|smtp|pop3|ssh|telnet|ldap|service banner|banner grab)\b/.test(p);
  const isHTTP  = !isTCP || /\b(http|https|web|url|endpoint|header|response|page|xss|inject|redirect|sql)\b/.test(p);
  const useHTTP = isHTTP && !(/\b(smb|ftp data|imap|smtp|pop3|ssh|telnet|ldap)\b/.test(p));

  if(useHTTP) return generateHTTPSignature(p, prompt);
  else        return generateTCPSignature(p, prompt);
}

function generateHTTPSignature(p, originalPrompt){
  let obj = '/';
  let matchMode = 'regexp';
  let matchPattern = '';
  let reportResult = 'Vulnerability detected';
  let title = originalPrompt.slice(0,60);
  let httpHeader = null;
  let triggerType = 'service';
  let explanation = '';

  if(/xss|cross.site|script inject/.test(p)){
    obj = '/search?q="><script>alert(73541);</script>';
    matchPattern = '><script>alert\\(73541\\);</script>';
    reportResult = 'XSS reflection confirmed';
    title = 'Cross-Site Scripting (XSS) Detection';
    explanation = `<strong>HTTP GET</strong> injects an XSS payload into a query parameter. The <strong>process</strong> transaction checks if the payload is reflected unencoded in the response body. A <strong>report</strong> transaction fires only on successful reflection.`;
  } else if(/sql.error|sqli|sql inject/.test(p)){
    obj = "/login?user='";
    matchPattern = "(SQL syntax|mysql_fetch|ORA-|SQLSTATE|Unclosed quotation)";
    reportResult = 'SQL error string exposed in response';
    title = 'SQL Error Disclosure Detection';
    explanation = `<strong>HTTP GET</strong> sends a single-quote to trigger a SQL error. The <strong>process</strong> regexp matches known SQL error strings from MySQL, Oracle, MSSQL. Reports only when an error string is found.`;
  } else if(/redirect|open.redirect/.test(p)){
    obj = '/?redirect=https://evil.com';
    matchPattern = 'Location: https://evil\\.com';
    matchMode = 'regexp';
    reportResult = 'Open redirect to external host confirmed';
    title = 'Open Redirect Detection';
    explanation = `<strong>HTTP GET</strong> passes an external URL as a redirect parameter. The <strong>process</strong> transaction inspects the Location header (via body fallback) for the external domain.`;
  } else if(/header|server.version|x-powered|banner/.test(p)){
    obj = '/';
    matchPattern = 'Server:\\s*([^\\r\\n]+)';
    matchMode = 'regexp';
    reportResult = {"concat": ["Server header: ", {"user": "server_ver"}]};
    title = 'HTTP Server Version Disclosure';
    explanation = `<strong>HTTP GET</strong> fetches the root page. The <strong>process</strong> regexp extracts the Server header value into the user variable <code>server_ver</code>. The <strong>report</strong> concatenates and posts it.`;
  } else if(/login|auth|credential/.test(p)){
    obj = '/login';
    httpHeader = 'Content-Type: application/x-www-form-urlencoded\n';
    matchPattern = '(error|invalid|incorrect|failed)';
    matchMode = 'regexp';
    reportResult = 'Authentication error response detected';
    title = 'Login Error Disclosure Detection';
    explanation = `<strong>HTTP POST</strong> submits test credentials to the login endpoint. The <strong>process</strong> regexp looks for authentication failure message patterns in the response.`;
  } else {
    obj = '/';
    matchPattern = p.match(/find|detect|check|look for\s+([a-zA-Z0-9\-_]+)/)?.[1] || 'vulnerability';
    matchMode = 'substring';
    reportResult = 'Pattern detected in HTTP response';
    title = `HTTP Detection: ${originalPrompt.slice(0,40)}`;
    explanation = `<strong>HTTP GET</strong> fetches the target URL. The <strong>process</strong> transaction performs a substring match. Adjust the <code>object</code> path and <code>match</code> pattern to your target.`;
  }

  const isExtract = typeof reportResult === 'object';
  const dialog = [];

  const httpTx = { transaction: usePost(p)?'http post':'http get', object: obj };
  if(httpHeader) httpTx.http_header = httpHeader;
  if(usePost(p)) httpTx.data = 'user=test&pass=test';
  httpTx.on_error = 'stop';
  dialog.push(httpTx);

  const processTx = { transaction: 'process', mode: matchMode, match: matchPattern, on_missing: 'stop' };
  if(isExtract) processTx.extract = [{}, {var:'server_ver'}];
  dialog.push(processTx);

  dialog.push({ transaction: 'report', result: reportResult });

  const sig = {
    detection_type: 'http dialog',
    api_version: 1,
    trigger_type: triggerType,
    title,
    dialog
  };

  return {
    json: JSON.stringify(sig, null, 2),
    explanation,
    confidence: 'high'
  };
}

function usePost(p){ return /post|submit|form|credential|login/.test(p); }

function generateTCPSignature(p, originalPrompt){
  let services = ['unknown'];
  let sendData = null;
  let receiveMatch = '.+';
  let receiveMode = 'regexp';
  let extractVar = null;
  let reportResult = 'Service response captured';
  let title = originalPrompt.slice(0,60);
  let explanation = '';

  if(/imap/.test(p)){
    services = ['imap','imaps'];
    sendData = 'a001 LOGIN testuser testpass\n';
    receiveMatch = '\na001 [^\n]*\n';
    receiveMode = 'luapattern';
    reportResult = 'IMAP authentication response received';
    title = 'IMAP Authentication Check';
    explanation = `<strong>TCP send</strong> sends IMAP LOGIN command. <strong>Receive</strong> waits for the tagged response using a Lua pattern. A <strong>process</strong> checks for OK to confirm auth success.`;
  } else if(/smtp/.test(p)){
    services = ['smtp'];
    sendData = 'EHLO test.domain\n';
    receiveMatch = '250[- ]';
    receiveMode = 'regexp';
    reportResult = {"system":"body"};
    title = 'SMTP EHLO Capability Check';
    explanation = `<strong>TCP send</strong> issues EHLO to trigger the SMTP capability banner. <strong>Receive</strong> matches the 250 multi-line response and reports the body.`;
  } else if(/smb/.test(p)){
    services = ['microsoft-ds'];
    sendData = {"call":{"name":"qrdiuser_smb_create_v1_negotiate"}};
    receiveMatch = '.+';
    reportResult = {"user":"smb_version"};
    title = 'SMB Protocol Version Detection';
    explanation = `<strong>TCP send</strong> calls a Lua function to craft an SMBv1 negotiate packet. <strong>Receive</strong> captures the response. A <strong>process</strong> Lua call parses the SMB version. Requires the Lua library with <code>qrdiuser_smb_*</code> functions.`;
  } else if(/ftp|banner/.test(p)){
    services = ['ftp'];
    receiveMatch = '220[^\\r\\n]+';
    receiveMode = 'regexp';
    reportResult = {"system":"body"};
    title = 'FTP/Service Banner Capture';
    explanation = `<strong>Receive</strong> immediately waits for the FTP 220 greeting banner without sending anything. The banner is reported directly via the <code>body</code> system variable.`;
  } else if(/ssh/.test(p)){
    services = ['ssh'];
    receiveMatch = 'SSH-[0-9]';
    receiveMode = 'regexp';
    reportResult = {"system":"body"};
    title = 'SSH Protocol Banner Check';
    explanation = `<strong>Receive</strong> captures the SSH protocol identification string sent by the server on connection. Reported verbatim.`;
  } else {
    services = ['unknown'];
    receiveMatch = '.+';
    reportResult = 'Response captured';
    title = `TCP Detection: ${originalPrompt.slice(0,40)}`;
    explanation = `Generic TCP dialog. Update <code>services</code> to the correct service name and adjust the <strong>receive</strong> match pattern.`;
  }

  const dialog = [];
  if(sendData) dialog.push({ transaction: 'send', data: sendData, on_error: 'stop' });
  const rx = { transaction: 'receive', mode: receiveMode, match: receiveMatch, timeout: 10000 };
  if(extractVar) rx.extract = [{},{var:extractVar}];
  dialog.push(rx);
  dialog.push({ transaction: 'report', result: reportResult });

  const sig = {
    detection_type: 'tcp dialog',
    api_version: 1,
    trigger_type: 'service',
    services,
    title,
    dialog
  };

  return {
    json: JSON.stringify(sig, null, 2),
    explanation,
    confidence: /smb/.test(p) ? 'med' : 'high'
  };
}

function improveExisting(existingJson, prompt){
  try {
    const sig = JSON.parse(existingJson);
    const dialog = sig.dialog || [];
    let changes = [];

    // Add on_error to http get / send if missing
    dialog.forEach((tx, i) => {
      if((tx.transaction==='http get'||tx.transaction==='http post'||tx.transaction==='send') && !tx.on_error){
        tx.on_error = 'stop';
        changes.push('Added <code>on_error: stop</code> to prevent silent failure on network errors');
      }
      if((tx.transaction==='http get'||tx.transaction==='http post') && !tx.timeout){
        tx.timeout = 30000;
        changes.push('Added <code>timeout: 30000ms</code> to HTTP transaction');
      }
    });

    // Add debug_level 100 if missing and prompt mentions debug
    if(/debug|log|verbose/.test(prompt.toLowerCase()) && !sig.debug_level){
      sig.debug_level = 100;
      changes.push('Added <code>debug_level: 100</code> for start/end logging');
    }

    // Add title if missing
    if(!sig.title){ sig.title = 'QRDI Detection'; changes.push('Added missing <code>title</code> field'); }

    // Add on_missing to process if missing
    dialog.forEach(tx => {
      if(tx.transaction==='process' && !tx.on_missing){
        tx.on_missing = 'stop';
        changes.push('Added <code>on_missing: stop</code> to process transaction to prevent false positives');
      }
    });

    if(changes.length===0) changes.push('Signature structure is already well-formed. No critical issues found.');

    return {
      json: JSON.stringify(sig, null, 2),
      explanation: `<strong>Improvements applied:</strong><ul style="margin:6px 0 0 16px;line-height:1.8">${changes.map(c=>`<li>${c}</li>`).join('')}</ul>`,
      confidence: 'high'
    };
  } catch(e){
    throw new Error('Existing JSON is invalid — fix it first before improving');
  }
}

function buildExplanation(parsed, prompt){
  const txNames = (parsed.dialog||[]).map(t=>t.transaction);
  return `<strong>Detection type:</strong> ${parsed.detection_type} &nbsp;|&nbsp; <strong>Trigger:</strong> ${parsed.trigger_type}<br>
<strong>Dialog flow:</strong> ${txNames.map(n=>`<code>${n}</code>`).join(' → ')}<br>
<em>Generated from:</em> "${prompt.slice(0,80)}${prompt.length>80?'…':''}"`;
}

function scoreConfidence(parsed){
  const d = parsed.dialog || [];
  const hasReport = d.some(t=>t.transaction==='report');
  const hasProcess = d.some(t=>t.transaction==='process'||t.transaction==='receive');
  if(hasReport && hasProcess && parsed.detection_type && parsed.api_version===1) return 'high';
  if(hasReport) return 'med';
  return 'low';
}

function applyAISignature(){
  if(!AI.lastGenerated){ showToast('No signature to apply','terr'); return; }
  $('json-def').value = AI.lastGenerated;
  validateJson();
  showToast('Signature applied to editor ✓','tok');
  // Auto-set detection type pill
  try {
    const parsed = JSON.parse(AI.lastGenerated);
    const dt = parsed.detection_type || 'http dialog';
    S.detType = dt;
    $('det-type-http').classList.toggle('on', dt==='http dialog');
    $('det-type-tcp').classList.toggle('on', dt==='tcp dialog');
    if(parsed.debug_level){
      S.debugSel = parsed.debug_level;
      qsa('.dbg-opt').forEach(o=>o.classList.toggle('on', parseInt(o.dataset.val)===S.debugSel));
    }
  } catch(e){}
}

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────
function init(){
  renderAll();
  // Restore saved API key status
  if(AI.apiKey){ $('ai-api-key').value = AI.apiKey.slice(0,14)+'...'; checkAIKeyStatus(); }

  // search
  $('search-input').addEventListener('input', e=>{
    S.search=e.target.value; renderTable(); renderActiveFilters();
  });
  // status toggle label
  $('status-toggle').addEventListener('change', e=>{
    $('status-lbl').textContent=e.target.checked?'Enabled':'Disabled';
  });
}

document.addEventListener('DOMContentLoaded', init);

// ─────────────────────────────────────────────
//  MOCK BACKEND API LAYER
//  Connects to json-server running on port 3001.
//  Falls back silently if the backend is not running.
// ─────────────────────────────────────────────

const API_BASE = 'http://localhost:3001/api';
let backendOnline = false;

// ── Probe the backend once on load ──────────────────────────────────────────
async function probeBackend(){
  try {
    const r = await fetch(`${API_BASE}/stats`, { signal: AbortSignal.timeout(1500) });
    if(r.ok){
      backendOnline = true;
      showToast('Backend connected ✓', 'tok');
      await loadSignaturesFromAPI();
      await loadProfilesFromAPI();
      updateDashboardFromAPI();
    }
  } catch(e){
    // Backend not running — app works fine with in-memory data
    console.info('[API] Backend offline — using in-memory data');
  }
}

// ── Load signatures from /api/signatures ─────────────────────────────────────
async function loadSignaturesFromAPI(){
  try {
    const r = await fetch(`${API_BASE}/signatures`);
    if(!r.ok) return;
    const sigs = await r.json();
    if(!sigs.length) return;
    // Merge API signatures into in-memory state (API is source of truth when online)
    S.entries = sigs.map(s => ({
      id:          s.id,
      qid:         s.qid,
      title:       s.title,
      sev:         s.sev,
      score:       s.score,
      cvss:        s.cvss,
      type:        'qrdi',
      detType:     s.detection_type || 'http dialog',
      debugLevel:  s.debug_level || 0,
      status:      s.status || 'Active',
      enabled:     s.enabled !== false,
      cve:         s.cve || '',
      definition:  s.definition ? JSON.stringify(s.definition, null, 2) : '',
      jsonDef:     s.definition ? JSON.stringify(s.definition, null, 2) : '',  // ← same value, ensures wizard + info modal work on both old and new code paths
      expl:        s.expl || '',
      apiId:       s.id     // keep the DB id for PUT/DELETE
    }));
    renderAll();
  } catch(e){ console.warn('[API] loadSignatures failed', e); }
}

// ── Load profiles from /api/profiles ─────────────────────────────────────────
async function loadProfilesFromAPI(){
  try {
    const r = await fetch(`${API_BASE}/profiles`);
    if(!r.ok) return;
    const profiles = await r.json();
    // Map to the in-memory SCAN_PROFILES shape
    profiles.forEach(p => {
      const existing = SCAN_PROFILES.find(x => x.id === p.id);
      if(existing){
        existing.name       = p.name;
        existing.assetGroup = p.assetGroup;
        existing.schedule   = p.schedule;
        existing.checks     = (p.attachedQids||[]).map(qid => {
          const sig = S.entries.find(e => e.qid === qid);
          return { qid, title: sig?.title||`QID ${qid}`, enabled: (p.perScanEnabled||{})[String(qid)] !== false, results: [] };
        });
      }
    });
    if(document.querySelector('#view-scan.on')) renderScanTab();
  } catch(e){ console.warn('[API] loadProfiles failed', e); }
}

// ── Load findings for a profile ───────────────────────────────────────────────
async function loadFindingsFromAPI(profileId){
  try {
    const r = await fetch(`${API_BASE}/findings?profileId=${profileId}`);
    if(!r.ok) return [];
    return await r.json();
  } catch(e){ return []; }
}

// ── POST /api/scan/run — run a mock scan ──────────────────────────────────────
async function runScanAPI(profileId){
  if(!backendOnline){ showToast('Backend offline — start the mock server first','terr'); return; }

  const profile = SCAN_PROFILES.find(p=>p.id===profileId);
  if(!profile) return;

  const qids = profile.checks.filter(c=>c.enabled).map(c=>c.qid);
  if(!qids.length){ showToast('No enabled checks attached to this profile','terr'); return; }

  showToast('Scan running…', 'tok');

  try {
    const r = await fetch(`${API_BASE}/scan/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profileId, qids })
    });
    if(!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    const { scan, findings } = data;

    showToast(`Scan complete — ${scan.vulnerable} vulnerable, ${scan.errors} errors`, 'tok');

    // Push results into in-memory profile checks
    qids.forEach(qid => {
      const check = profile.checks.find(c=>c.qid===qid);
      if(!check) return;
      const checkFindings = findings.filter(f=>f.qid===qid);
      check.results = checkFindings.map(f=>({
        status: f.status, host: f.host, ts: f.ts, detail: f
      }));
    });

    // Refresh the scan tab view
    if(document.querySelector('#view-scan.on')) selectProfile(profileId);

    // Log telemetry
    logTelemetry({ event:'scan_executed', scanId: scan.id, profileId });

    // Refresh dashboard stats
    updateDashboardFromAPI();
  } catch(e){
    showToast('Scan failed: ' + e.message, 'terr');
  }
}

// ── Save a signature to /api/signatures ──────────────────────────────────────
async function saveSignatureToAPI(entry){
  if(!backendOnline) return;
  try {
    const payload = {
      qid:             entry.qid,
      title:           entry.title,
      sev:             entry.sev,
      score:           entry.score,
      cvss:            entry.cvss,
      detection_type:  entry.detType,
      debug_level:     entry.debugLevel,
      status:          entry.status,
      enabled:         entry.enabled,
      cve:             entry.cve || '',
      definition:      entry.definition ? JSON.parse(entry.definition) : {}
    };
    if(entry.apiId){
      // Update existing
      await fetch(`${API_BASE}/signatures/${entry.apiId}`, {
        method: 'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
      });
    } else {
      // Create new
      const r = await fetch(`${API_BASE}/signatures`, {
        method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
      });
      if(r.ok){ const saved = await r.json(); entry.apiId = saved.id; }
    }
    logTelemetry({ event: entry.apiId ? 'signature_updated' : 'signature_created', qid: entry.qid, title: entry.title });
  } catch(e){ console.warn('[API] saveSignature failed', e); }
}

// ── POST /api/telemetry ───────────────────────────────────────────────────────
async function logTelemetry(payload){
  if(!backendOnline) return;
  try {
    await fetch(`${API_BASE}/telemetry`, {
      method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
    });
  } catch(e){ /* silent */ }
}

// ── Update Overview dashboard from /api/stats ─────────────────────────────────
async function updateDashboardFromAPI(){
  if(!backendOnline) return;
  try {
    const r = await fetch(`${API_BASE}/stats`);
    if(!r.ok) return;
    const stats = await r.json();
    // Patch KPI cards if they are rendered
    const patch = (id, val) => { const el=$('kpi-'+id); if(el) el.textContent=val; };
    patch('total',    stats.total);
    patch('active',   stats.active);
    patch('lua',      stats.luaLibs);
    patch('pending',  stats.pending);
    // Telemetry chips
    patch('ai-runs',  stats.aiInvocations);
    patch('scans',    stats.scansExecuted);
    patch('vulns',    stats.vulns);
  } catch(e){ /* silent */ }
}

// ── Wire saveQrdiVuln to also push to API ────────────────────────────────────
const _origSaveQrdi = saveQrdiVuln;
saveQrdiVuln = async function(){
  _origSaveQrdi();
  // Find the entry that was just saved (last modified)
  const entry = S.entries[S.entries.length - 1];
  if(entry && entry.type === 'qrdi') await saveSignatureToAPI(entry);
  if(backendOnline) logTelemetry({ event:'signature_created', qid: entry?.qid, title: entry?.title });
};

// ── Wire runAIGenerate to log telemetry ──────────────────────────────────────
const _origRunAI = runAIGenerate;
runAIGenerate = async function(){
  await _origRunAI();
  logTelemetry({ event:'ai_generation_invoked', mode: AI.mode });
};

// ── Add Run Scan button to the Scan tab profile detail ───────────────────────
// Patches renderProfileDetail to inject a "▶ Run Scan" button when backend is online.
const _origRenderProfile = renderProfileDetail;
renderProfileDetail = function(profile){
  _origRenderProfile(profile);
  const detailEl = document.querySelector('.scan-right');
  if(!detailEl || !backendOnline) return;
  // Only inject if not already there
  if(detailEl.querySelector('.run-scan-btn')) return;
  const btn = document.createElement('button');
  btn.className = 'btn-primary run-scan-btn';
  btn.style.cssText = 'margin:16px 0 8px;width:100%;font-size:14px;padding:10px 0;';
  btn.innerHTML = '▶ Run Scan Now';
  btn.onclick = () => runScanAPI(profile.id);
  detailEl.prepend(btn);
};

// ── Boot the API layer ────────────────────────────────────────────────────────
probeBackend();
