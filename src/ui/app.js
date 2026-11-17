/* IBRA ANTIVIRUS — renderer */
const api = window.ibra;
let S = null;          // latest snapshot from main
let L = I18N.ar;       // current language strings
let scanView = 'chooser';
let liveThreats = [];
let runTimer = null;
let appUpd = null;
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SH = { green: '../../assets/shield-green.png', orange: '../../assets/shield-orange.png', red: '../../assets/shield-red.png' };

const IC = {
  shield: '<svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
  usb: '<svg viewBox="0 0 24 24"><rect x="7" y="9" width="10" height="12" rx="2"/><path d="M9 9V3h6v6M10.5 5.5h.01M13.5 5.5h.01"/></svg>',
  db: '<svg viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/></svg>',
  win: '<svg viewBox="0 0 24 24"><path d="M4 5l7-1v7H4zM13 4l7-1v8h-7zM4 13h7v7l-7-1zM13 13h7v8l-7-1z"/></svg>',
  dna: '<svg viewBox="0 0 24 24"><path d="M7 3c0 6 10 6 10 12s-10 6-10 6M17 3c0 6-10 6-10 12M8 7h8M8 17h8"/></svg>',
  brain: '<svg viewBox="0 0 24 24"><path d="M12 5a3 3 0 00-6 1 3 3 0 00-2 5 3 3 0 002 5 3 3 0 006 1zM12 5a3 3 0 016 1 3 3 0 012 5 3 3 0 01-2 5 3 3 0 01-6 1"/></svg>',
  globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
  wall: '<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="1"/><path d="M3 10h18M3 15h18M9 5v5M15 10v5M9 15v4"/></svg>',
  bug: '<svg viewBox="0 0 24 24"><rect x="8" y="7" width="8" height="12" rx="4"/><path d="M12 7V4M8 11H4M20 11h-4M8 16H5M19 16h-3M9 5l-2-2M15 5l2-2"/></svg>',
  lock: '<svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>',
  clock: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>',
  check: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/></svg>',
  lang: '<svg viewBox="0 0 24 24"><path d="M4 5h9M8.5 3v2M6 5c1 4 4 7 7 8M11 5c-1 4-4 7-7 8M13 21l4-9 4 9M14.5 18h5"/></svg>',
  power: '<svg viewBox="0 0 24 24"><path d="M12 3v8M6.3 7a8 8 0 1011.4 0"/></svg>',
  tray: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 15h18M15 18h2"/></svg>',
  size: '<svg viewBox="0 0 24 24"><path d="M6 2h8l5 5v15H6z"/><path d="M9 14h6M12 11v6"/></svg>',
  flask: '<svg viewBox="0 0 24 24"><path d="M9 3h6M10 3v6L4 20h16L14 9V3"/></svg>',
  refresh: '<svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 10-2 6M20 4v7h-7"/></svg>',
  folder: '<svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>'
};

function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('on'), 3200); }
function fmtDate(ts) { if (!ts) return ''; const d = new Date(ts); return d.toLocaleString(S && S.settings.lang === 'en' ? 'en-GB' : 'ar-IQ', { dateStyle: 'medium', timeStyle: 'short' }); }
function fmtDur(ms) { const s = Math.max(1, Math.round(ms / 1000)); const m = Math.floor(s / 60); return m ? `${m}${L.min} ${s % 60}${L.sec}` : `${s}${L.sec}`; }
function clock(ms) { const s = Math.floor(ms / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }
function fmtSize(b) { return b > 1048576 ? (b / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB'; }

// ---------------------------------------------------------------- language
function applyLang(lang) {
  L = I18N[lang] || I18N.ar;
  document.documentElement.lang = lang;   // layout stays LTR; only text direction follows the language
  $$('[data-t]').forEach(el => { const v = L[el.dataset.t]; if (typeof v === 'string') el.textContent = v; });
  $$('.lang-switch button').forEach(b => b.classList.toggle('on', b.dataset.lang === lang));
}

// ---------------------------------------------------------------- navigation
function go(page) {
  $$('.nav').forEach(n => n.classList.toggle('active', n.dataset.page === page));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  if (page === 'quarantine') renderQuarantine();
  if (page === 'history') renderHistory();
  if (page === 'settings') renderSettings();
  if (page === 'protect') renderProtect();
  if (page === 'browser') renderBrowser();
  if (page === 'firewall') renderFirewall(true);
  clearInterval(fwTimer);
  if (page === 'firewall') fwTimer = setInterval(() => renderFirewall(false), 6000);
}
let fwTimer = null;
$$('.nav').forEach(n => n.onclick = () => go(n.dataset.page));
$$('[data-win]').forEach(b => b.onclick = () => api.win(b.dataset.win));
$$('.lang-switch button').forEach(b => b.onclick = async () => { S = await api.set('lang', b.dataset.lang); render(); });
$$('[data-url]').forEach(b => b.onclick = () => api.openUrl(b.dataset.url));
api.onWin(w => { $('#maxIcon').innerHTML = w.maximized ? '<rect x="3.5" y="1.5" width="7" height="7" rx="1"/><path d="M1.5 4v6.5H8"/>' : '<rect x="2.5" y="2.5" width="7" height="7" rx="1"/>'; });

// ---------------------------------------------------------------- render
function render() {
  if (!S) return;
  applyLang(S.settings.lang);
  renderHome();
  renderScanArea();
  const qb = $('#qBadge'); qb.textContent = S.activeThreats.length || ''; qb.classList.toggle('on', S.activeThreats.length > 0);
  if ($('#page-protect').classList.contains('active')) renderProtect();
  if ($('#page-settings').classList.contains('active')) renderSettings();
  $('#aboutVer').textContent = 'v' + S.version;
}

function protectionComplete() {
  return S.realtime && S.settings.usbAutoScan && (!S.engines.clamav.installed || S.engines.clamav.ready) && fwAllOn() !== false;
}

function renderHome() {
  const hero = $('.hero');
  const st = S.state;
  const img = $('#heroShield');
  hero.classList.remove('ok', 'warn', 'bad');
  img.classList.remove('pulse', 'alarm');
  let title, sub;
  if (st === 'danger') { img.src = SH.red; img.classList.add('alarm'); hero.classList.add('bad'); title = L.stDanger; sub = L.stDangerSub(S.activeThreats.length); }
  else if (st === 'scanning') { img.src = SH.orange; img.classList.add('pulse'); hero.classList.add('warn'); title = L.stScanning; sub = L.stScanningSub; }
  else if (!protectionComplete()) { img.src = SH.orange; hero.classList.add('warn'); title = L.stWarn; sub = L.stWarnSub; }
  else { img.src = SH.green; hero.classList.add('ok'); title = L.stProtected; sub = L.stProtectedSub; }
  $('#heroTitle').textContent = title;
  $('#heroSub').textContent = sub;
  $('#btnFixAll').hidden = st !== 'danger';
  $('#btnQuick').disabled = !!S.scan;
  $('#lastScan').textContent = S.settings.lastScan ? L.lastScan(fmtDate(S.settings.lastScan)) : L.never;

  const c = S.engines.clamav;
  let dbText, dbBar = '';
  if (!c.installed) dbText = L.dbNotInstalled;
  else if (c.updating) {
    const p = c.progress && c.progress.percent;
    dbText = L.dbUpdating + (p != null ? ` ${p}%` : '');
    dbBar = `<div class="mini-bar ${p == null ? 'indet' : ''}"><i style="width:${p || 0}%"></i></div>`;
  } else dbText = c.ready ? L.dbReady(fmtDate(c.date)) : L.dbMissing;
  const tiles = [
    { ic: IC.shield, t: L.rtTitle, d: L.rtDesc, on: S.realtime, key: 'realtime' },
    { ic: IC.usb, t: L.usbTitle, d: L.usbDesc, on: S.settings.usbAutoScan, key: 'usbAutoScan' },
    { ic: IC.db, t: L.dbTitle, d: dbText, on: c.installed && c.ready, extra: dbBar + (c.installed && !c.updating ? `<button class="btn ghost sm" id="tileDb">${esc(L.dbUpdate)}</button>` : '') },
    { ic: IC.brain, t: L.ibraTitle, d: L.ibraDesc, on: true },
    { ic: IC.dna, t: L.yaraTitle, d: S.engines.yara ? L.yaraOn : L.yaraOff, on: S.engines.yara && S.settings.useYara },
    { ic: IC.win, t: L.defTitle, d: S.engines.defender ? L.defOn : L.defOff, on: S.engines.defender && S.settings.useDefender },
    { ic: IC.globe, t: L.navBrowser, d: browserOnline().length ? L.brOnSub(browserOnline().join('، ')) : L.brOffSub, on: browserOnline().length > 0, page: 'browser' },
    { ic: IC.wall, t: L.navFirewall, d: fwAllOn() === false ? L.fwOffSub(fwOffNames()) : L.fwOnSub, on: fwAllOn() !== false, page: 'firewall' }
  ];
  $('#tiles').innerHTML = tiles.map((x, i) => `
    <div class="tile glass ${x.soon ? 'soon' : x.on ? '' : 'off'}" ${x.key ? `data-key="${x.key}"` : ''} ${x.page ? `data-go="${x.page}" style="cursor:pointer"` : ''}>
      <div class="tile-top"><div class="tile-ic">${x.ic}</div><b class="tx">${esc(x.t)}</b>${x.key ? `<button class="switch ${x.on ? 'on' : ''}" data-set="${x.key}"></button>` : `<span class="dot"></span>`}</div>
      <p class="tx">${esc(x.d)}</p>${x.extra || ''}
    </div>`).join('');
  bindSwitches($('#tiles'));
  $$('#tiles [data-go]').forEach(t => t.onclick = () => go(t.dataset.go));
  const tb = $('#tileDb'); if (tb) tb.onclick = updateDb;
}

function bindSwitches(root) {
  root.querySelectorAll('[data-set]').forEach(sw => sw.onclick = async () => {
    const k = sw.dataset.set;
    const cur = k === 'realtime' ? S.realtime : S.settings[k];
    S = await api.set(k, !cur); render();
  });
}

async function updateDb() { toast(L.dbUpdating); await api.dbUpdate(); }

// ---------------------------------------------------------------- scanning
async function startScan(req) {
  const r = await api.scan(req);
  if (r && r.busy) toast(L.busy);
  else if (r && r.queued) toast(L.queued);
  else { liveThreats = []; scanView = 'running'; go('scan'); renderScanArea(); }
}
$('#btnQuick').onclick = () => startScan({ type: 'quick' });
$('#btnFixAll').onclick = () => { scanView = 'result'; go('scan'); renderScanArea(); };
$$('[data-scan]').forEach(b => b.onclick = async () => {
  const k = b.dataset.scan;
  if (k === 'quick') return startScan({ type: 'quick' });
  if (k === 'full') { if (confirm(L.fullWarn)) startScan({ type: 'full' }); return; }
  const paths = await api.pick(k === 'file' ? 'file' : 'folder');
  if (paths.length) startScan({ type: 'custom', targets: paths });
});
$('#btnCancel').onclick = () => api.cancel();
$('#btnResBack').onclick = () => { scanView = 'chooser'; renderScanArea(); };
$('#btnResAll').onclick = async () => { S = await api.threatsAll('quarantine'); render(); renderResults(); };

const drop = $('#drop');
['dragenter', 'dragover'].forEach(e => document.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(e => document.addEventListener(e, ev => { ev.preventDefault(); if (e === 'drop' || ev.target === drop) drop.classList.remove('over'); }));
document.addEventListener('drop', ev => {
  const paths = [...(ev.dataTransfer?.files || [])].map(f => api.pathForFile(f)).filter(Boolean);
  if (paths.length) startScan({ type: 'custom', targets: paths });
});

function renderScanArea() {
  if (S && S.scan) scanView = 'running';
  else if (scanView === 'running') scanView = S && S.lastResult ? 'result' : 'chooser';
  $('#scanChooser').hidden = scanView !== 'chooser';
  $('#scanRunning').hidden = scanView !== 'running';
  $('#scanResult').hidden = scanView !== 'result';
  if (scanView === 'running' && S.scan) renderProgress(S.scan);
  if (scanView === 'result') renderResults();
  clearInterval(runTimer);
  if (scanView === 'running') runTimer = setInterval(() => { if (S.scan) $('#runTime').textContent = clock(Date.now() - S.scan.started); }, 1000);
}

function renderProgress(p) {
  if (!p) return;
  S.scan = p;
  $('#runTitle').textContent = L.scanTitles[p.type] || L.scanTitles.custom;
  const pct = p.phase === 'collect' ? 0 : p.total ? Math.min(99, Math.floor(p.scanned / p.total * 100)) : 0;
  $('#runPct').textContent = pct + '%';
  $('#runBar').style.width = (p.phase === 'collect' ? 3 : pct) + '%';
  $('#runPhase').textContent = p.phase === 'collect' ? L.phaseCollect(p.collected || 0) : L.phaseEngine(p.engine || 'IBRA');
  $('#runFile').textContent = p.current || '';
  const passes = (p.engines || ['IBRA']).length;
  $('#runFiles').textContent = p.phase === 'collect' ? (p.collected || 0) : Math.round(p.total / passes) || 0;
  $('#runFound').textContent = p.found || 0;
  $('#runTime').textContent = clock(Date.now() - p.started);
}

function threatItem(t, { result = false } = {}) {
  const sev = t.severity === 'medium' ? 'med' : '';
  const done = t.action && t.action !== 'failed';
  const label = done ? `<span class="tag done">${esc(L[t.action] || t.action)}</span>` : `<span class="tag ${esc(t.severity)}">${esc(L[t.severity] || t.severity)}</span>`;
  const acts = done ? '' : `
    <button class="btn primary sm" data-act="quarantine">${esc(L.aQuarantine)}</button>
    <button class="btn ghost sm" data-act="delete">${esc(L.aDelete)}</button>
    <button class="btn ghost sm" data-act="ignore">${esc(L.aIgnore)}</button>
    <button class="btn ghost sm" data-act="exclude">${esc(L.aExclude)}</button>`;
  return `<div class="item glass ${sev} ${done ? 'ok' : ''}" data-path="${esc(t.path)}">
    <div class="ic">${done ? IC.check : IC.bug}</div>
    <div class="info"><b>${esc(t.name)}${label}${t.action === 'failed' ? `<span class="tag high">${esc(L.failed)}</span>` : ''}</b>
      <div class="path">${esc(t.path)}</div>
      <div class="meta">${esc((t.engines || []).join(' + '))}</div></div>
    <div class="acts">${acts}${result ? `<button class="btn ghost sm" data-act="reveal">${esc(L.aReveal)}</button>` : ''}</div>
  </div>`;
}

function bindThreatActions(root) {
  root.querySelectorAll('[data-act]').forEach(b => b.onclick = async () => {
    const p = b.closest('[data-path]').dataset.path;
    const a = b.dataset.act;
    if (a === 'reveal') return api.reveal(p);
    if (a === 'delete' && !confirm(L.confirmDel)) return;
    const r = await api.threatAction(p, a);
    if (!r.ok) toast(L.failed + ': ' + r.error);
    if (S.lastResult) for (const x of S.lastResult.threats) if (x.path === p && r.ok) x.action = a === 'quarantine' ? 'quarantined' : a === 'delete' ? 'deleted' : a === 'exclude' ? 'excluded' : 'ignored';
    S = await api.state(); render();
  });
}

function renderResults() {
  const r = S.lastResult;
  const list = $('#resList');
  if (!r) { list.innerHTML = ''; return; }
  // include threats from real-time protection that are still open
  const map = new Map();
  for (const t of r.threats) map.set(t.path.toLowerCase(), t);
  for (const t of S.activeThreats) if (!map.has(t.path.toLowerCase())) map.set(t.path.toLowerCase(), t);
  const all = [...map.values()];
  const open = all.filter(t => !t.action || t.action === 'failed');
  const img = $('#resShield');
  const dur = fmtDur((r.finished || Date.now()) - r.started);
  if (r.cancelled) { img.src = SH.orange; $('#resTitle').textContent = L.resCancelled; $('#resSub').textContent = ''; }
  else if (!all.length) { img.src = SH.green; $('#resTitle').textContent = L.resClean; $('#resSub').textContent = L.resCleanSub(r.files, dur); }
  else { img.src = open.length ? SH.red : SH.green; $('#resTitle').textContent = L.resFound(all.length); $('#resSub').textContent = L.resFoundSub(r.files, dur); }
  $('#btnResAll').hidden = !open.length;
  list.innerHTML = all.map(t => threatItem(t, { result: true })).join('');
  bindThreatActions(list);
}

api.onProgress(p => { if (!S) return; if (!S.scan) { S.scan = p; scanView = 'running'; renderScanArea(); } renderProgress(p); });
api.onThreat(t => {
  liveThreats.push(t);
  $('#liveThreats').innerHTML = liveThreats.slice(-6).reverse().map(x => `<div class="item glass ${x.severity === 'medium' ? 'med' : ''}"><div class="ic">${IC.bug}</div><div class="info"><b>${esc(x.name)}</b><div class="path">${esc(x.path)}</div></div></div>`).join('');
});
api.onScanDone(async r => { S = await api.state(); scanView = 'result'; render(); if (!$('#page-scan').classList.contains('active') && r.threats.length) go('scan'); });
api.onState(s => { const wasScan = S && S.scan; S = s; if (wasScan && !s.scan && scanView === 'running') scanView = 'result'; render(); });
api.onDbProgress(p => { if (!S) return; S.engines.clamav.updating = true; S.engines.clamav.progress = p; if ($('#page-home').classList.contains('active')) renderHome(); });
api.onDbDone(async r => { S = await api.state(); render(); if (!r.ok && !r.skipped) toast('ClamAV: ' + (r.error || 'update failed')); });
api.onRealtime(t => toast(L.rtCaught(t.name)));
api.onAppUpdate(u => { appUpd = u; if ($('#page-settings').classList.contains('active')) renderSettings(); if (u.status === 'ready') toast(L.updReady(u.version)); });

// ---------------------------------------------------------------- protection page
function row({ ic, t, d, key, val, soon, right }) {
  return `<div class="row glass ${soon ? 'soon' : ''}"><div class="ic">${ic}</div><div class="info"><b class="tx">${esc(t)}</b><p class="tx">${esc(d)}</p></div>
    ${soon ? `<span class="tag">${esc(L.soon)}</span>` : key ? `<button class="switch ${val ? 'on' : ''}" data-set="${key}"></button>` : ''}${right || ''}</div>`;
}
function renderProtect() {
  const c = S.engines.clamav;
  $('#protectRows').innerHTML = [
    row({ ic: IC.shield, t: L.rtTitle, d: L.rtDesc, key: 'realtime', val: S.realtime }),
    row({ ic: IC.usb, t: L.usbTitle, d: L.usbDesc, key: 'usbAutoScan', val: S.settings.usbAutoScan }),
    row({ ic: IC.lock, t: L.sAutoQ, d: L.sAutoQDesc, key: 'autoQuarantine', val: S.settings.autoQuarantine }),
    row({ ic: IC.brain, t: L.ibraTitle, d: L.ibraDesc, right: `<span class="tag done">${esc(L.on)}</span>` }),
    row({ ic: IC.db, t: L.sClam, d: !c.installed ? L.dbNotInstalled : c.ready ? L.dbReady(fmtDate(c.date)) : L.dbMissing, key: c.installed ? 'useClamAV' : null, val: S.settings.useClamAV }),
    row({ ic: IC.dna, t: L.sYara, d: S.engines.yara ? L.yaraOn : L.yaraOff, key: S.engines.yara ? 'useYara' : null, val: S.settings.useYara }),
    row({ ic: IC.win, t: L.sDef, d: S.engines.defender ? L.defOn : L.defOff, key: S.engines.defender ? 'useDefender' : null, val: S.settings.useDefender }),
    row({ ic: IC.globe, t: L.navBrowser, d: browserOnline().length ? L.brOnSub(browserOnline().join('، ')) : L.brOffSub, right: `<button class="btn ghost sm" data-go2="browser">${esc(L.navBrowser)}</button>` }),
    row({ ic: IC.wall, t: L.navFirewall, d: fwAllOn() === false ? L.fwOffSub(fwOffNames()) : L.fwOnSub, right: `<button class="btn ghost sm" data-go2="firewall">${esc(L.navFirewall)}</button>` })
  ].join('');
  bindSwitches($('#protectRows'));
  $$('#protectRows [data-go2]').forEach(b => b.onclick = () => go(b.dataset.go2));
}

// ---------------------------------------------------------------- settings
function renderSettings() {
  const s = S.settings;
  let upd = '';
  if (appUpd) {
    if (appUpd.status === 'latest') upd = L.updLatest;
    else if (appUpd.status === 'available') upd = L.updAvail(appUpd.version);
    else if (appUpd.status === 'downloading') upd = L.updDl(appUpd.percent);
    else if (appUpd.status === 'ready') upd = L.updReady(appUpd.version);
    else if (appUpd.status === 'error') upd = L.updErr;
  }
  $('#settingsRows').innerHTML = [
    row({ ic: IC.lang, t: L.sLang, d: L.sLangDesc, right: `<select id="selLang"><option value="ar" ${s.lang === 'ar' ? 'selected' : ''}>العربية</option><option value="en" ${s.lang === 'en' ? 'selected' : ''}>English</option></select>` }),
    row({ ic: IC.power, t: L.sStartup, d: L.sStartupDesc, key: 'runAtStartup', val: s.runAtStartup }),
    row({ ic: IC.tray, t: L.sTray, d: L.sTrayDesc, key: 'minimizeToTray', val: s.minimizeToTray }),
    row({ ic: IC.size, t: L.sMax, d: L.sMaxDesc, right: `<input type="number" id="inMax" min="10" max="2000" value="${+s.maxFileSizeMB || 150}" style="width:90px">` }),
    row({ ic: IC.db, t: L.dbTitle, d: S.engines.clamav.ready ? L.dbReady(fmtDate(S.engines.clamav.date)) : L.dbMissing, right: S.engines.clamav.installed ? `<button class="btn ghost sm" id="setDb">${esc(L.dbUpdate)}</button>` : '' }),
    row({ ic: IC.flask, t: L.sTest, d: L.sTestDesc, right: `<button class="btn ghost sm" id="btnTest">${esc(L.test)}</button>` }),
    row({ ic: IC.refresh, t: L.sAppUpd, d: L.sAppUpdDesc(S.version) + (upd ? ' — ' + upd : ''), right: appUpd && appUpd.status === 'ready' ? `<button class="btn primary sm" id="btnInstall">${esc(L.install)}</button>` : `<button class="btn ghost sm" id="btnUpd">${esc(L.check)}</button>` })
  ].join('');
  bindSwitches($('#settingsRows'));
  $('#selLang').onchange = async e => { S = await api.set('lang', e.target.value); render(); };
  $('#inMax').onchange = async e => { S = await api.set('maxFileSizeMB', Math.max(10, Math.min(2000, +e.target.value || 150))); };
  const sd = $('#setDb'); if (sd) sd.onclick = updateDb;
  $('#btnTest').onclick = async () => { const r = await api.testEicar(); if (r && r.blocked) toast('Defender ✔ EICAR'); else if (r && r.started) { liveThreats = []; scanView = 'running'; go('scan'); renderScanArea(); } else if (r && r.busy) toast(L.busy); };
  const bu = $('#btnUpd'); if (bu) bu.onclick = () => { appUpd = { status: 'checking' }; api.appUpdate().then(r => { if (r && r.dev) toast('dev'); }); };
  const bi = $('#btnInstall'); if (bi) bi.onclick = () => api.appInstallUpdate();
  renderExclusions();
}
function renderExclusions() {
  const ex = S.settings.exclusions || [];
  $('#exList').innerHTML = ex.length ? ex.map(p => `<div class="item glass ok" data-ex="${esc(p)}"><div class="ic">${IC.folder}</div><div class="info"><div class="path">${esc(p)}</div></div><div class="acts"><button class="btn ghost sm">${esc(L.remove)}</button></div></div>`).join('')
    : `<div class="empty"><span class="tx">${esc(L.exEmpty)}</span></div>`;
  $$('#exList [data-ex] button').forEach(b => b.onclick = async () => { await api.exclusionRemove(b.closest('[data-ex]').dataset.ex); S = await api.state(); renderSettings(); });
}
$('#exFolder').onclick = async () => { await api.exclusionAdd('folder'); S = await api.state(); renderSettings(); };
$('#exFile').onclick = async () => { await api.exclusionAdd('file'); S = await api.state(); renderSettings(); };

// ---------------------------------------------------------------- quarantine & history
async function renderQuarantine() {
  const items = await api.quarantineList();
  $('#btnQClear').hidden = !items.length;
  $('#qList').innerHTML = items.length ? items.map(i => `<div class="item glass" data-q="${esc(i.id)}"><div class="ic">${IC.lock}</div>
    <div class="info"><b>${esc(i.name)}</b><div class="path">${esc(i.original)}</div><div class="meta">${esc(fmtDate(i.date))} · ${esc(i.engine)} · ${fmtSize(i.size)}</div></div>
    <div class="acts"><button class="btn ghost sm" data-qa="restore">${esc(L.aRestore)}</button><button class="btn ghost sm" data-qa="delete">${esc(L.aDelete)}</button></div></div>`).join('')
    : `<div class="empty"><span class="tx">${esc(L.qEmpty)}</span></div>`;
  $$('#qList [data-qa]').forEach(b => b.onclick = async () => {
    const id = b.closest('[data-q]').dataset.q;
    if (b.dataset.qa === 'delete') { if (!confirm(L.confirmDel)) return; await api.quarantineDelete(id); }
    else { const r = await api.quarantineRestore(id); toast(r.ok ? L.restored : L.failed); }
    S = await api.state(); render(); renderQuarantine();
  });
}
$('#btnQClear').onclick = async () => { if (!confirm(L.confirmDel)) return; await api.quarantineClear(); S = await api.state(); render(); renderQuarantine(); };

async function renderHistory() {
  const h = await api.history();
  $('#btnHClear').hidden = !h.length;
  $('#hList').innerHTML = h.length ? h.map(x => {
    const bad = x.threats && x.threats.length;
    return `<div class="item glass ${bad ? '' : 'ok'}"><div class="ic">${bad ? IC.bug : IC.check}</div>
      <div class="info"><b class="tx">${esc(L.scanTitles[x.type] || x.type)} — ${bad ? esc(L.resFound(x.threats.length)) : esc(L.resClean)}</b>
      <div class="meta">${esc(fmtDate(x.started))} · ${x.files} ${esc(L.files)} · ${esc(fmtDur(x.finished - x.started))} · ${esc((x.engines || []).join(' + '))}</div>
      ${bad ? `<div class="path">${x.threats.slice(0, 3).map(t => esc(t.name + ' — ' + t.path)).join('<br>')}</div>` : ''}</div></div>`;
  }).join('') : `<div class="empty"><span class="tx">${esc(L.hEmpty)}</span></div>`;
}
$('#btnHClear').onclick = async () => { await api.historyClear(); renderHistory(); };

// ---------------------------------------------------------------- browser protection page
function browserOnline() { return ((S && S.browser && S.browser.connected) || []).filter(b => b.online).map(b => b.name); }
async function renderBrowser() {
  const on = browserOnline();
  $('#brShield').src = on.length ? SH.green : SH.orange;
  $('#brTitle').textContent = on.length ? L.brOn : L.brOff;
  $('#brSub').textContent = on.length ? L.brOnSub(on.join('، ')) : L.brOffSub;
  $('#brBlocked').textContent = S.browser.blocked || 0;
  const list = await api.browsers();
  const conn = S.browser.connected || [];
  const nameMap = { chrome: 'Chrome', edge: 'Edge', brave: 'Brave', opera: 'Opera', operagx: 'Opera', vivaldi: 'Vivaldi', yandex: 'Yandex' };
  const procMap = { chrome: 'chrome', edge: 'msedge', brave: 'brave', opera: 'opera', operagx: 'opera', vivaldi: 'vivaldi', yandex: 'browser' };
  const canAuto = await api.browserCanAuto();
  $('#brAutoAll').hidden = !canAuto || !list.length;
  $('#brList').innerHTML = list.length ? list.map(b => {
    const c = conn.find(x => x.name === nameMap[b.id] && x.online);
    return `<div class="bcard glass ${c ? 'on' : ''}"><div class="top">${IC.globe}<b>${esc(b.name)}</b></div>
      <div class="st tx">${c ? esc(L.connected) : esc(L.notConnected)}</div>
      <button class="btn ${c ? 'ghost' : 'primary'} sm" data-inst="${esc(b.id)}">${esc(c ? L.reinstall : L.install)}</button></div>`;
  }).join('') : `<div class="empty"><span class="tx">${esc(L.noBrowsers)}</span></div>`;
  $$('#brList [data-inst]').forEach(b => b.onclick = async () => {
    if (canAuto) { b.disabled = true; b.textContent = L.brInstalling; await api.browserAuto(procMap[b.dataset.inst]); S = await api.state(); renderBrowser(); return; }
    const r = await api.browserInstall(b.dataset.inst);
    if (r.ok) { $('#brSteps').hidden = false; $('#brDir').textContent = r.dir; } else toast(L.failed + ': ' + r.error);
  });
  $('#brFeatures').innerHTML = [
    row({ ic: IC.bug, t: L.fMal, d: L.fMalD }), row({ ic: IC.lock, t: L.fPhish, d: L.fPhishD }),
    row({ ic: IC.shield, t: L.fFrame, d: L.fFrameD }), row({ ic: IC.globe, t: L.fWarn, d: L.fWarnD }), row({ ic: IC.folder, t: L.fDl, d: L.fDlD })
  ].join('');
  const log = S.browser.log || [];
  const rName = { malware: L.rMalware, phishing: L.rPhishing, suspicious: L.rSuspicious };
  $('#brLogClear').hidden = !log.length;
  $('#brLog').innerHTML = log.length ? log.map(x => `<div class="item glass ${x.action === 'allowed' ? 'med' : ''}"><div class="ic">${x.action === 'allowed' ? IC.globe : IC.bug}</div>
    <div class="info"><b class="tx">${esc(x.action === 'allowed' ? L.aAllowed : (rName[x.reason] || L.rSuspicious))}</b><div class="path">${esc(x.url)}</div><div class="meta">${esc(fmtDate(x.date))}</div></div></div>`).join('')
    : `<div class="empty"><span class="tx">${esc(L.brLogEmpty)}</span></div>`;
}
$('#brOpenDir').onclick = () => api.browserFolder();
$('#brAutoAll').onclick = async () => { const b = $('#brAutoAll'); b.disabled = true; await api.browserAuto('all'); b.disabled = false; S = await api.state(); renderBrowser(); };
$('#brLogBtn').onclick = async () => { if (!(await api.extLog())) toast(L.brNoLog); };
$('#brManual').onclick = async () => { const d = await api.browserFolder(); if (d) { $('#brSteps').hidden = false; $('#brDir').textContent = d; } };
api.onExtInstall(e => { if (e.status === 'done' && $('#page-browser').classList.contains('active')) setTimeout(renderBrowser, 500); });
$('#brLogClear').onclick = async () => { await api.browserLogClear(); S = await api.state(); renderBrowser(); };
api.onBrowser(b => { if (!S) return; S.browser = b; if ($('#page-browser').classList.contains('active')) renderBrowser(); if ($('#page-home').classList.contains('active')) renderHome(); });

// ---------------------------------------------------------------- firewall page
let fwData = null;
const newApps = new Set();
const iconCache = {};
function fwAllOn() { const p = S && S.firewall && S.firewall.profiles; if (!p || !Object.keys(p).length) return null; return Object.values(p).every(Boolean); }
function fwOffNames() { const p = (S.firewall && S.firewall.profiles) || {}; return Object.keys(p).filter(k => !p[k]).map(k => (L.profiles && L.profiles[k]) || k).join('، '); }
async function iconFor(p) { if (!p) return null; if (!(p in iconCache)) iconCache[p] = await api.fileIcon(p); return iconCache[p]; }
async function renderFirewall(full) {
  if (full && !fwData) $('#fwLive').innerHTML = `<div class="empty"><span class="tx">${esc(L.fwLoading)}</span></div>`;
  $('#fwRows').innerHTML = row({ ic: IC.bell || IC.shield, t: L.fwAsk, d: L.fwAskD, key: 'fwAskNew', val: S.settings.fwAskNew });
  bindSwitches($('#fwRows'));
  fwData = await api.fwState();
  S.firewall.profiles = fwData.profiles;
  const on = fwAllOn() !== false;
  $('#fwShield').src = on ? SH.green : SH.red;
  $('#fwTitle').textContent = on ? L.fwOn : L.fwOff;
  $('#fwSub').textContent = on ? L.fwOnSub : L.fwOffSub(fwOffNames());
  $('#fwEnable').hidden = on;
  const blockedSet = new Set(fwData.blocked.map(b => b.path.toLowerCase()));
  const live = fwData.conns.filter(c => !c.path || !blockedSet.has(c.path.toLowerCase()));
  const icons = await Promise.all(live.map(c => iconFor(c.path)));
  $('#fwLive').innerHTML = live.length ? live.map((c, i) => `<div class="item glass ok ${newApps.has((c.path || '').toLowerCase()) ? 'new' : ''}" data-fp="${esc(c.path)}">
      <div class="ic">${icons[i] ? `<img src="${icons[i]}" alt="">` : IC.win}</div>
      <div class="info"><b>${esc(c.desc || c.name)}${newApps.has((c.path || '').toLowerCase()) ? `<span class="tag medium">${esc(L.newApp)}</span>` : ''}<span class="tag">${esc(L.conns(c.connections))}</span></b>
      <div class="path">${esc(c.path || c.name)}</div><div class="meta" style="direction:ltr;text-align:left">${esc(c.remotes.join('  ·  '))}</div></div>
      <div class="acts">${c.path ? `<button class="btn danger sm" data-fw="block">${esc(L.block)}</button>` : ''}</div></div>`).join('')
    : `<div class="empty"><span class="tx">${esc(L.fwLiveEmpty)}</span></div>`;
  const bicons = await Promise.all(fwData.blocked.map(b => iconFor(b.path)));
  $('#fwBlocked').innerHTML = fwData.blocked.length ? fwData.blocked.map((b, i) => `<div class="item glass" data-fp="${esc(b.path)}">
      <div class="ic">${bicons[i] ? `<img src="${bicons[i]}" alt="">` : IC.wall}</div>
      <div class="info"><b>${esc(b.name)}</b><div class="path">${esc(b.path)}</div></div>
      <div class="acts"><button class="btn primary sm" data-fw="allow">${esc(L.allow)}</button></div></div>`).join('')
    : `<div class="empty"><span class="tx">${esc(L.fwBlockedEmpty)}</span></div>`;
  $$('#page-firewall [data-fw]').forEach(b => b.onclick = async () => {
    const p = b.closest('[data-fp]').dataset.fp;
    b.disabled = true;
    const r = b.dataset.fw === 'block' ? await api.fwBlock([p]) : await api.fwUnblock([p]);
    toast(r.ok ? L.fwDone : L.fwDenied);
    renderFirewall(false);
  });
  const fb = $('#fwBadge'); fb.textContent = newApps.size || ''; fb.classList.toggle('on', newApps.size > 0);
}
$('#fwRefresh').onclick = () => renderFirewall(false);
$('#fwPick').onclick = async () => { const r = await api.fwPick(); if (r.ok) toast(L.fwDone); else if (r.denied) toast(L.fwDenied); renderFirewall(false); };
$('#fwEnable').onclick = async () => { const r = await api.fwEnable(); toast(r.ok ? L.fwDone : L.fwDenied); renderFirewall(false); };
api.onFwNew(c => { if (c.path) newApps.add(c.path.toLowerCase()); const fb = $('#fwBadge'); fb.textContent = newApps.size; fb.classList.add('on'); if ($('#page-firewall').classList.contains('active')) renderFirewall(false); });
api.onNavigate(p => go(p));

// ---------------------------------------------------------------- start
(async () => { S = await api.state(); render(); })();
