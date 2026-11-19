// IBRA ANTIVIRUS - main process
// برمجة وتطوير ابراهيم الخزرجي - IBRAPROGRAM
const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, shell, Notification } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const P = require('./engine/paths');
const Store = require('./engine/store');
const Quarantine = require('./engine/quarantine');
const Scanner = require('./engine/scanner');
const clam = require('./engine/clamav');
const yara = require('./engine/yara');
const defender = require('./engine/defender');
const heur = require('./engine/heuristics');
const sys = require('./engine/sys');
const { RealTime, UsbMonitor } = require('./engine/realtime');
const firewall = require('./engine/firewall');
const browsers = require('./engine/browsers');
const { Bridge } = require('./engine/bridge');

app.setAppUserModelId('com.ibraprogram.antivirus');
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }

let win, tray, store, quarantine, scanner, realtime, usb, bridge, fwMonitor;
let fwProfiles = null;
let quitting = false;
let activeThreats = [];   // detected and not yet handled
let lastResult = null;
let dbProgress = null;
const pendingScans = [];
const STARTED_HIDDEN = process.argv.includes('--hidden');

const T = {
  ar: {
    protected: 'جهازك محمي', scanning: 'جاري الفحص...', danger: 'تم اكتشاف تهديد!', open: 'فتح IBRA ANTIVIRUS',
    quick: 'فحص سريع', pause: 'إيقاف الحماية الفورية', resume: 'تشغيل الحماية الفورية', quit: 'خروج',
    threatTitle: 'IBRA ANTIVIRUS - تهديد', threatBody: (n, f) => `${n}\n${f}`, quarantined: 'تم عزله بالحجر الصحي',
    usbTitle: 'فلاشة جديدة', usbBody: d => `جاري فحص ${d}`, usbClean: d => `الفلاشة ${d} نظيفة ✔`,
    tray: 'IBRA ANTIVIRUS يشتغل بالخلفية ويحمي جهازك', scanDone: 'انتهى الفحص', clean: 'ما لكينا أي تهديد ✔', found: n => `تم اكتشاف ${n} تهديد`,
    fwNewTitle: 'برنامج جديد يتصل بالإنترنت', fwNewBody: n => `${n}\nاضغط هنا إذا تريد تمنعه`, siteBlocked: 'تم حظر موقع خطر بالمتصفح',
    extAskTitle: 'تنصيب حماية المتصفح', extAskMsg: b => `IBRA ANTIVIRUS راح ينصّب إضافة الحماية تلقائياً على: ${b}`,
    extAskDetail: '⚠ لا تضغط على أي شيء ولا تحرّك الماوس لحين انتهاء التنصيب (حوالي ١٥ ثانية لكل متصفح).', extStart: 'ابدأ التنصيب', extLater: 'لاحقاً',
    extDoneTitle: 'تم تنصيب حماية المتصفح ✔', extFailTitle: 'ما اكتمل تنصيب الإضافة', extFailHint: 'جرّب مرة ثانية من صفحة «المتصفح»، أو استخدم التنصيب اليدوي هناك.', extConfirmed: 'متصلة بالبرنامج ✔', extLoaded: 'انحملت (أعد تشغيل المتصفح إذا ما ظهر الدرع)'
  },
  en: {
    protected: 'Your PC is protected', scanning: 'Scanning...', danger: 'Threat detected!', open: 'Open IBRA ANTIVIRUS',
    quick: 'Quick scan', pause: 'Pause real-time protection', resume: 'Resume real-time protection', quit: 'Exit',
    threatTitle: 'IBRA ANTIVIRUS - Threat', threatBody: (n, f) => `${n}\n${f}`, quarantined: 'Moved to quarantine',
    usbTitle: 'New USB drive', usbBody: d => `Scanning ${d}`, usbClean: d => `USB drive ${d} is clean ✔`,
    tray: 'IBRA ANTIVIRUS keeps running in the background', scanDone: 'Scan finished', clean: 'No threats found ✔', found: n => `${n} threat(s) found`,
    fwNewTitle: 'New program is using the internet', fwNewBody: n => `${n}\nClick here if you want to block it`, siteBlocked: 'A dangerous site was blocked in the browser',
    extAskTitle: 'Install browser protection', extAskMsg: b => `IBRA ANTIVIRUS will install the protection extension automatically on: ${b}`,
    extAskDetail: '⚠ Do not click anything or move the mouse until it finishes (about 15 seconds per browser).', extStart: 'Start', extLater: 'Later',
    extDoneTitle: 'Browser protection installed ✔', extFailTitle: 'Extension install did not finish', extFailHint: 'Try again from the Browser page, or use the manual install there.', extConfirmed: 'connected to the app ✔', extLoaded: 'loaded (restart the browser if the shield does not appear)'
  }
};
const t = () => T[store.get('lang')] || T.ar;

// ---------------------------------------------------------------- state
function state() {
  if (activeThreats.length) return 'danger';
  if (scanner && scanner.running && !scanner.running.silent) return 'scanning';
  return 'protected';
}
function iconFor(s) { return P.asset(`tray-${s === 'danger' ? 'red' : s === 'scanning' ? 'orange' : 'green'}.png`); }

function snapshot() {
  const db = clam.dbInfo();
  return {
    state: state(),
    settings: (({ fwKnown, browserLog, fwBlockedCache, ...rest }) => rest)(store.all()),
    scan: scanner.status(),
    activeThreats,
    lastResult,
    engines: {
      ibra: true,
      clamav: { installed: clam.installed(), ready: db.ready, date: db.date, updating: !!dbProgress, progress: dbProgress },
      yara: yara.installed(),
      defender: defender.installed()
    },
    realtime: !!(realtime && realtime.active),
    usb: !!(usb && usb.timer),
    quarantineCount: quarantine.list().length,
    browser: { connected: bridge ? bridge.status() : [], blocked: store.get('browserBlocked') || 0, log: (store.get('browserLog') || []).slice(0, 30) },
    firewall: { profiles: fwProfiles, blockedCount: (store.get('fwBlockedCache') || []).length, monitor: !!(fwMonitor && fwMonitor.timer) },
    version: app.getVersion(),
    platform: process.platform
  };
}

function push(channel, payload) { if (win && !win.isDestroyed()) win.webContents.send(channel, payload); }
function refresh() {
  push('state', snapshot());
  updateTray();
}

function notify(title, body, onClick) {
  if (!Notification.isSupported()) return;
  const n = new Notification({ title, body, icon: iconFor(state()), silent: false });
  n.on('click', () => { showWindow(); onClick && onClick(); });
  n.show();
}

// ---------------------------------------------------------------- window & tray
function createWindow() {
  win = new BrowserWindow({
    width: 1120, height: 740, minWidth: 960, minHeight: 640,
    frame: false, show: false, backgroundColor: '#eef6f1',
    title: 'IBRA ANTIVIRUS', icon: P.asset('icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: false, spellcheck: false }
  });
  win.removeMenu();
  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  win.once('ready-to-show', () => { if (!STARTED_HIDDEN) win.show(); });
  win.on('close', e => {
    if (!quitting && store.get('minimizeToTray')) {
      e.preventDefault(); win.hide();
      if (!store.get('_trayHintShown')) { store.set('_trayHintShown', true); notify('IBRA ANTIVIRUS', t().tray); }
    }
  });
  win.on('maximize', () => push('win', { maximized: true }));
  win.on('unmaximize', () => push('win', { maximized: false }));
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https?:/.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', e => e.preventDefault());
}

let autoCheckScheduled = false;
function showWindow() {
  // started hidden at Windows login: check the browser extension the first time the user opens the app
  if (STARTED_HIDDEN && !autoCheckScheduled) { autoCheckScheduled = true; setTimeout(() => autoExtensionCheck(), 8000); }
  if (!win || win.isDestroyed()) createWindow();
  if (win.isMinimized()) win.restore();
  win.show(); win.focus();
}

function updateTray() {
  if (!tray) return;
  const s = state();
  tray.setImage(nativeImage.createFromPath(iconFor(s)).resize({ width: 16, height: 16 }));
  tray.setToolTip('IBRA ANTIVIRUS — ' + t()[s]);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: t().open, click: showWindow },
    { label: t().quick, enabled: !scanner.running, click: () => startScan({ type: 'quick' }) },
    { label: realtime.active ? t().pause : t().resume, click: () => setSetting('realtime', !realtime.active) },
    { type: 'separator' },
    { label: t().quit, click: () => { quitting = true; app.quit(); } }
  ]));
  if (win && !win.isDestroyed()) win.setIcon(nativeImage.createFromPath(iconFor(s)));
}

// ---------------------------------------------------------------- actions
async function startScan(req) {
  if (scanner.running) {
    if (req.type === 'usb' || req.type === 'custom') { pendingScans.push(req); return { queued: true }; }
    return { busy: true };
  }
  showWindowIfInteractive(req);
  scanner.scan(req).then(res => onScanDone(req, res));
  refresh();
  return { started: true };
}
function showWindowIfInteractive(req) { if (!req.silent && req.type !== 'usb') showWindow(); }

function onScanDone(req, res) {
  lastResult = res;
  const unresolved = res.threats.filter(x => x.action !== 'quarantined');
  for (const th of unresolved) if (!activeThreats.some(a => a.path.toLowerCase() === th.path.toLowerCase())) activeThreats.push(th);
  if (req.type === 'usb') {
    const root = req.targets[0];
    if (res.threats.some(x => /^(Worm|Trick)\./.test(x.name) || /autorun|shortcut/i.test(x.name))) unhideDrive(root);
    if (!res.threats.length && !res.cancelled) notify(t().usbTitle, t().usbClean(root));
  }
  if (!res.cancelled && (!document_isVisible() || req.type === 'usb')) {
    if (res.threats.length) notify(t().threatTitle, t().found(res.threats.length));
    else if (req.type !== 'usb') notify(t().scanDone, t().clean);
  }
  refresh();
  push('scan-done', res);
  const next = pendingScans.shift();
  if (next) setTimeout(() => startScan(next), 500);
}
function document_isVisible() { return win && !win.isDestroyed() && win.isVisible() && win.isFocused(); }

// Shortcut virus hides the user's real files - show them again after cleaning.
function unhideDrive(root) {
  if (process.platform !== 'win32' || !/^[A-Z]:\\$/i.test(root)) return;
  require('child_process').execFile('attrib.exe', ['-h', '-s', '-r', '/s', '/d', root + '*'], { windowsHide: true }, () => {});
}

function handleThreat(th, source) {
  if (store.get('autoQuarantine') && th.severity === 'high') {
    try {
      const it = quarantine.add(th.path, { name: th.name, engine: (th.engines || []).join(' + ') });
      th.action = 'quarantined'; th.qid = it.id;
      notify(t().threatTitle, `${th.name}\n${path.basename(th.path)}\n${t().quarantined}`);
      push('realtime-event', { ...th, source });
      refresh();
      return;
    } catch (e) { th.error = e.code || e.message; }
  }
  if (!activeThreats.some(a => a.path.toLowerCase() === th.path.toLowerCase())) activeThreats.push(th);
  notify(t().threatTitle, t().threatBody(th.name, th.path));
  push('realtime-event', { ...th, source });
  refresh();
}

function threatAction(p, action) {
  const i = activeThreats.findIndex(a => a.path.toLowerCase() === String(p).toLowerCase());
  const th = i >= 0 ? activeThreats[i] : { path: p, name: 'Manual' };
  try {
    if (action === 'quarantine') quarantine.add(th.path, { name: th.name, engine: (th.engines || []).join(' + ') });
    else if (action === 'delete') { try { fs.chmodSync(th.path, 0o666); } catch {} fs.unlinkSync(th.path); }
    else if (action === 'exclude') store.set('exclusions', [...new Set([...(store.get('exclusions') || []), th.path])]);
    // 'ignore' just dismisses it
    if (i >= 0) activeThreats.splice(i, 1);
    if (lastResult) for (const x of lastResult.threats) if (x.path.toLowerCase() === th.path.toLowerCase()) x.action = action === 'quarantine' ? 'quarantined' : action;
    refresh();
    return { ok: true };
  } catch (e) {
    if (e.code === 'ENOENT') { if (i >= 0) activeThreats.splice(i, 1); refresh(); return { ok: true }; }
    return { ok: false, error: e.code || e.message };
  }
}

function setSetting(k, v) {
  store.set(k, v);
  if (k === 'realtime') v ? realtime.start() : realtime.stop();
  if (k === 'usbAutoScan') v ? usb.start() : usb.stop();
  if (k === 'runAtStartup') applyStartup();
  if (k === 'fwAskNew') v ? fwMonitor.start() : fwMonitor.stop();
  refresh();
}
function applyStartup() {
  if (!app.isPackaged) return;
  app.setLoginItemSettings({ openAtLogin: !!store.get('runAtStartup'), args: ['--hidden'] });
}

async function updateDb(force) {
  if (!clam.installed() || dbProgress) return { ok: false };
  const last = store.get('lastDbUpdate');
  if (!force && last && Date.now() - last < 4 * 3600 * 1000 && clam.dbInfo().ready) return { ok: true, skipped: true };
  dbProgress = { percent: clam.dbInfo().ready ? null : 0 };
  refresh();
  const r = await clam.update(p => { dbProgress = { ...dbProgress, ...p }; push('db-progress', dbProgress); });
  dbProgress = null;
  if (r.ok) store.set('lastDbUpdate', Date.now());
  refresh();
  push('db-done', r);
  return r;
}

function argScanTarget(argv) {
  const i = argv.indexOf('--scan');
  return i >= 0 && argv[i + 1] ? argv[i + 1] : null;
}

// ---------------------------------------------------------------- automatic extension install (same method as IBRA Download Manager)
let extInstalling = false;
function onlineBrowserNames() { return (bridge ? bridge.status() : []).filter(b => b.online).map(b => b.name); }

function makeOverlay() {
  const { screen } = require('electron');
  const wa = screen.getPrimaryDisplay().workArea;
  const w = 560, h = 300;
  const ov = new BrowserWindow({
    width: w, height: h, x: Math.round(wa.x + (wa.width - w) / 2), y: wa.y + wa.height - h - 24,
    frame: false, transparent: true, resizable: false, movable: false, focusable: false, skipTaskbar: true,
    alwaysOnTop: true, show: false, hasShadow: false, webPreferences: { contextIsolation: true, sandbox: true }
  });
  ov.setAlwaysOnTop(true, 'screen-saver');
  ov.setIgnoreMouseEvents(true);   // clicks pass through so the browser keeps control
  ov.loadFile(path.join(__dirname, 'ui', 'overlay.html'));
  ov.once('ready-to-show', () => ov.showInactive());
  return ov;
}

async function installExtension({ which = 'all', ask = false, quiet = false, only = null } = {}) {
  if (extInstalling) return { busy: true };
  if (!browsers.canAutoInstall()) return { ok: false, error: 'helper-missing' };
  const found = browsers.installed();
  const online = onlineBrowserNames();
  const proc = b => browsers.PROCESS_OF[b.id];
  let skip, todo;
  if (only) { todo = found.filter(b => only.includes(proc(b))); skip = [...new Set(found.filter(b => !only.includes(proc(b))).map(proc))]; which = 'all'; }
  else if (which === 'all') {
    // skip browsers whose extension is already connected
    skip = found.filter(b => online.includes(browsers.HEARTBEAT_NAME[proc(b)])).map(proc);
    todo = found.filter(b => !skip.includes(proc(b)));
  } else { skip = []; todo = found.filter(b => proc(b) === which); }
  if (!todo.length) return { ok: true, nothing: true };
  if (ask) {
    const r = await dialog.showMessageBox(win && win.isVisible() ? win : undefined, {
      type: 'question', title: 'IBRA ANTIVIRUS', icon: P.asset('icon.png'),
      message: t().extAskMsg(todo.map(b => b.name).join(store.get('lang') === 'ar' ? '، ' : ', ')),
      detail: t().extAskDetail, buttons: [t().extStart, t().extLater], defaultId: 0, cancelId: 1, noLink: true
    });
    if (r.response !== 0) return { ok: false, later: true };
  }
  extInstalling = true;
  push('ext-install', { status: 'start' });
  const lang = store.get('lang');
  const wasVisible = win && !win.isDestroyed() && win.isVisible();
  if (wasVisible) win.minimize();
  const ov = makeOverlay();
  const send = d => { if (!ov.isDestroyed()) ov.webContents.executeJavaScript(`update(${JSON.stringify(d)})`).catch(() => {}); };
  ov.webContents.once('did-finish-load', () => send({ lang }));
  const started = Date.now();
  const logFile = P.data('ext-install.log');
  const log = line => { try { fs.appendFileSync(logFile, new Date().toISOString() + ' ' + line + '\n'); } catch {} };
  log(`--- install which=${which} skip=${skip.join(',')} todo=${todo.map(b => b.name).join(',')} online=${online.join(',')}`);
  const res = await browsers.autoInstall({ which, skip, lang, onLog: log }, ev => {
    log(JSON.stringify(ev));
    if (ev.start) send({ lang, browser: ev.start });
    else if (ev.step) send({ step: ev.step });
    else if (ev.result) send({ result: ev.message, cls: ev.ok ? 'ok' : 'bad' });
    push('ext-install', { status: 'event', ev });
  });
  // confirm: wait for each installed extension to call the app
  const lines = [];
  for (const r of res.results || []) {
    let confirmed = false;
    if (r.ok) {
      const name = browsers.HEARTBEAT_NAME[r.process];
      const until = Date.now() + 15000;
      while (Date.now() < until) {
        const st = bridge.status();
        if (st.some(b => b.lastSeen >= started && (b.name === name || !name))) { confirmed = true; break; }
        await new Promise(x => setTimeout(x, 700));
      }
      if (!confirmed && bridge.status().some(b => b.lastSeen >= started)) confirmed = true;
    }
    lines.push((r.ok ? '✓ ' : '✗ ') + r.result + ': ' + (r.ok ? (confirmed ? t().extConfirmed : t().extLoaded) : r.message));
    log(`result ${r.result} ok=${r.ok} confirmed=${confirmed} ${r.message || ''}`);
    const st = store.get('extState') || {};
    const cur = st[r.process] || { tries: 0, ok: false };
    st[r.process] = { tries: cur.tries + 1, ok: !!(r.ok && confirmed), at: Date.now() };
    store.set('extState', st);
  }
  if (!res.results || !res.results.length) log('no results: ' + JSON.stringify({ ok: res.ok, error: res.error, none: res.none }));
  if (!ov.isDestroyed()) ov.close();
  if (wasVisible && win && !win.isDestroyed()) { win.restore(); win.focus(); }
  extInstalling = false;
  store.set('extAutoDone', true);
  const ok = (res.results || []).length > 0 && res.results.every(r => r.ok);
  if (!res.cancelled && lines.length && !quiet) {
    await dialog.showMessageBox(win && !win.isDestroyed() ? win : undefined, {
      type: ok ? 'info' : 'warning', title: 'IBRA ANTIVIRUS', icon: P.asset(ok ? 'shield-green.png' : 'shield-orange.png'),
      message: ok ? t().extDoneTitle : t().extFailTitle, detail: lines.join('\n') + (ok ? '' : '\n\n' + t().extFailHint), buttons: ['OK'], noLink: true
    });
  }
  push('ext-install', { status: 'done', res });
  refresh();
  return { ...res, lines };
}

async function autoExtensionCheck() {
  if (extInstalling || (scanner && scanner.running) || !browsers.canAutoInstall()) return;
  const st = store.get('extState') || {};
  const online = onlineBrowserNames();
  const todo = [...new Set(browsers.installed()
    .map(b => browsers.PROCESS_OF[b.id])
    .filter(p => !online.includes(browsers.HEARTBEAT_NAME[p]))
    .filter(p => !(st[p] && st[p].ok) && !((st[p] && st[p].tries) >= 3)))];
  if (!todo.length) return;
  await installExtension({ only: todo, ask: false });
}

// ---------------------------------------------------------------- IPC
function ipc() {
  ipcMain.handle('state', () => snapshot());
  ipcMain.handle('set', (_, k, v) => { setSetting(k, v); return snapshot(); });
  ipcMain.handle('scan', (_, req) => startScan(req));
  ipcMain.handle('cancel', () => { scanner.cancel(); return true; });
  ipcMain.handle('pick', async (_, kind) => {
    const r = await dialog.showOpenDialog(win, { properties: kind === 'file' ? ['openFile', 'multiSelections'] : ['openDirectory', 'multiSelections'] });
    return r.canceled ? [] : r.filePaths;
  });
  ipcMain.handle('threat-action', (_, p, a) => threatAction(p, a));
  ipcMain.handle('threats-all', (_, a) => { for (const th of activeThreats.slice()) threatAction(th.path, a); return snapshot(); });
  ipcMain.handle('quarantine-list', () => quarantine.list());
  ipcMain.handle('quarantine-restore', (_, id) => { try { const p = quarantine.restore(id); store.set('exclusions', [...new Set([...(store.get('exclusions') || []), p])]); refresh(); return { ok: true, path: p }; } catch (e) { return { ok: false, error: e.message }; } });
  ipcMain.handle('quarantine-delete', (_, id) => { quarantine.remove(id); refresh(); return { ok: true }; });
  ipcMain.handle('quarantine-clear', () => { quarantine.clear(); refresh(); return { ok: true }; });
  ipcMain.handle('history', () => store.history);
  ipcMain.handle('history-clear', () => { store.clearHistory(); return []; });
  ipcMain.handle('exclusion-add', async (_, kind) => {
    const r = await dialog.showOpenDialog(win, { properties: [kind === 'file' ? 'openFile' : 'openDirectory'] });
    if (!r.canceled) store.set('exclusions', [...new Set([...(store.get('exclusions') || []), ...r.filePaths])]);
    refresh(); return store.get('exclusions');
  });
  ipcMain.handle('exclusion-remove', (_, p) => { store.set('exclusions', (store.get('exclusions') || []).filter(x => x !== p)); refresh(); return store.get('exclusions'); });
  ipcMain.handle('db-update', () => updateDb(true));
  ipcMain.handle('open-url', (_, u) => { if (/^https?:\/\//.test(u)) shell.openExternal(u); });
  ipcMain.handle('reveal', (_, p) => shell.showItemInFolder(p));
  ipcMain.handle('test-eicar', () => {
    // Writes the harmless EICAR test file so the user can confirm protection works.
    const dir = path.join(os.tmpdir(), 'ibra-antivirus-test'); fs.mkdirSync(dir, { recursive: true });
    const f = path.join(dir, 'eicar-test.com');
    try { fs.writeFileSync(f, heur.EICAR); } catch (e) { return { ok: false, blocked: true }; }
    return startScan({ type: 'custom', targets: [f] });
  });
  ipcMain.handle('app-update', () => checkAppUpdate(true));
  ipcMain.handle('app-install-update', () => { try { quitting = true; require('electron-updater').autoUpdater.quitAndInstall(); } catch {} });
  // ---- firewall
  ipcMain.handle('fw-state', async () => {
    const [conns, blocked, profiles] = await Promise.all([firewall.connections(), firewall.blocked(), firewall.profiles()]);
    fwProfiles = profiles; store.set('fwBlockedCache', blocked.map(b => b.path));
    return { conns, blocked, profiles };
  });
  ipcMain.handle('fw-block', async (_, paths) => { const r = await firewall.block(paths.filter(Boolean)); refresh(); return r; });
  ipcMain.handle('fw-unblock', async (_, paths) => { const r = await firewall.unblock(paths.filter(Boolean)); refresh(); return r; });
  ipcMain.handle('fw-enable', () => firewall.enableAll());
  ipcMain.handle('fw-pick', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'], filters: [{ name: 'Programs', extensions: ['exe'] }] });
    if (r.canceled || !r.filePaths.length) return { ok: false };
    return firewall.block(r.filePaths);
  });
  ipcMain.handle('file-icon', async (_, p) => { try { return (await app.getFileIcon(p, { size: 'normal' })).toDataURL(); } catch { return null; } });
  // ---- browser protection
  ipcMain.handle('browsers', () => browsers.installed().map(b => ({ id: b.id, name: b.name })));
  ipcMain.handle('browser-install', (_, id) => {
    try {
      const dir = browsers.prepareExtension();
      require('electron').clipboard.writeText(dir);
      const opened = browsers.openExtensionsPage(id);
      shell.openPath(dir);
      return { ok: true, dir, opened };
    } catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('browser-auto', (_, which) => installExtension({ which: which || 'all', ask: false }));
  ipcMain.handle('browser-can-auto', () => browsers.canAutoInstall());
  ipcMain.handle('ext-log', () => { const f = P.data('ext-install.log'); if (fs.existsSync(f)) shell.showItemInFolder(f); return fs.existsSync(f); });
  ipcMain.handle('browser-folder', () => { try { const d = browsers.prepareExtension(); shell.openPath(d); return d; } catch { return null; } });
  ipcMain.handle('browser-log-clear', () => { store.set('browserLog', []); refresh(); return true; });
  ipcMain.on('win', (_, a) => {
    if (!win) return;
    if (a === 'min') win.minimize();
    else if (a === 'max') win.isMaximized() ? win.unmaximize() : win.maximize();
    else if (a === 'close') win.close();
  });
}

// ---------------------------------------------------------------- app updates (GitHub releases)
let updater = null;
function checkAppUpdate(manual) {
  if (!app.isPackaged) return Promise.resolve({ dev: true });
  try {
    if (!updater) {
      updater = require('electron-updater').autoUpdater;
      updater.autoDownload = true;
      updater.on('update-available', i => push('app-update', { status: 'available', version: i.version }));
      updater.on('update-not-available', () => push('app-update', { status: 'latest' }));
      updater.on('download-progress', p => push('app-update', { status: 'downloading', percent: Math.round(p.percent) }));
      updater.autoInstallOnAppQuit = true;
      updater.on('update-downloaded', i => {
        push('app-update', { status: 'ready', version: i.version });
        notify('IBRA ANTIVIRUS', (store.get('lang') === 'en' ? `Updating to version ${i.version}...` : `جاري التحديث للنسخة ${i.version}...`));
        // the app lives in the tray and is rarely closed, so install the update by itself when nothing is running
        const tryInstall = () => {
          if ((scanner && scanner.running) || extInstalling) return setTimeout(tryInstall, 60000);
          quitting = true;
          updater.quitAndInstall(true, true);   // silent, start again after updating
        };
        setTimeout(tryInstall, 20000);
      });
      updater.on('error', e => push('app-update', { status: 'error', error: String(e.message || e).slice(0, 200) }));
    }
    return updater.checkForUpdates().then(() => ({ ok: true })).catch(e => ({ ok: false, error: e.message }));
  } catch (e) { return Promise.resolve({ ok: false, error: e.message }); }
}

// ---------------------------------------------------------------- boot
app.on('second-instance', (_, argv) => {
  const target = argScanTarget(argv);
  if (target) startScan({ type: 'custom', targets: [target] });
  showWindow();
});

app.whenReady().then(() => {
  store = new Store(P.data());
  quarantine = new Quarantine(P.data('quarantine'));
  scanner = new Scanner({ store, quarantine, selfDirs: [app.isPackaged ? path.dirname(process.execPath) : path.join(__dirname, '..'), P.data()] });
  realtime = new RealTime(scanner, store);
  usb = new UsbMonitor();

  scanner.on('start', refresh);
  scanner.on('progress', p => push('progress', p));
  scanner.on('threat', th => push('threat', th));
  realtime.on('threat', th => handleThreat(th, 'realtime'));
  realtime.on('state', refresh);
  usb.on('inserted', d => {
    if (!store.get('usbAutoScan')) return;
    notify(t().usbTitle, t().usbBody(d));
    startScan({ type: 'usb', targets: [d], removableRoots: [d] });
  });

  // browser extension bridge
  bridge = new Bridge({
    lang: () => store.get('lang'),
    extVersion: () => { try { return JSON.parse(fs.readFileSync(P.data('browser-extension', 'manifest.json'), 'utf8')).version; } catch { return null; } },
    scan: async (file, url) => {
      const th = await scanner.checkFile(file, {}, { clam: true });
      if (th) { th.source = 'browser'; th.url = url; handleThreat(th, 'browser'); return { name: th.name, severity: th.severity }; }
      return null;
    }
  });
  bridge.on('change', () => push('browser', snapshot().browser));
  bridge.on('event', ev => {
    if (ev.type === 'blocked') {
      store.set('browserBlocked', (store.get('browserBlocked') || 0) + 1);
      const log = store.get('browserLog') || [];
      log.unshift({ url: ev.url, reason: ev.reason, date: Date.now(), action: 'blocked' });
      store.set('browserLog', log.slice(0, 200));
    } else if (ev.type === 'allowed') {
      const log = store.get('browserLog') || [];
      log.unshift({ url: ev.url, date: Date.now(), action: 'allowed' });
      store.set('browserLog', log.slice(0, 200));
    }
    push('browser', snapshot().browser);
  });
  bridge.start();
  try { if (fs.existsSync(P.data('browser-extension'))) browsers.prepareExtension(); } catch {}

  // firewall: watch for programs that start using the internet
  fwMonitor = new firewall.Monitor(store);
  fwMonitor.on('new-app', c => {
    push('fw-new', c);
    notify(t().fwNewTitle, t().fwNewBody(c.desc || c.name), () => push('navigate', 'firewall'));
  });
  if (store.get('fwAskNew')) setTimeout(() => fwMonitor.start(), 8000);
  firewall.profiles().then(p => { fwProfiles = p; refresh(); });

  ipc();
  createWindow();
  tray = new Tray(nativeImage.createFromPath(iconFor('protected')).resize({ width: 16, height: 16 }));
  tray.on('click', showWindow);
  updateTray();

  if (store.get('realtime')) realtime.start();
  if (store.get('usbAutoScan')) usb.start();
  applyStartup();

  setTimeout(() => updateDb(false), 4000);
  setInterval(() => updateDb(false), 60 * 60 * 1000);
  setTimeout(() => checkAppUpdate(false), 15000);

  const target = argScanTarget(process.argv);
  if (target) setTimeout(() => startScan({ type: 'custom', targets: [target] }), 1200);

  if (process.argv.includes('--test-ext-install')) {
    setTimeout(async () => {
      const r = await installExtension({ which: 'all', ask: false, quiet: true });
      fs.writeFileSync(P.data('ext-test-result.json'), JSON.stringify({ r, bridge: bridge.status() }, null, 2));
      quitting = true; app.exit(0);
    }, 3000);
  }
  // install the browser extension automatically on every browser that does not have it yet
  // (same method as IBRA Download Manager). Each browser is tried at most 3 times; done once it connects.
  if (!STARTED_HIDDEN && !target && !process.argv.includes('--test-ext-install')) setTimeout(autoExtensionCheck, 12000);
});

app.on('before-quit', () => { quitting = true; });
app.on('window-all-closed', () => { /* keep running in tray */ });
