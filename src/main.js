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

app.setAppUserModelId('com.ibraprogram.antivirus');
if (!app.requestSingleInstanceLock()) { app.quit(); process.exit(0); }

let win, tray, store, quarantine, scanner, realtime, usb;
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
    tray: 'IBRA ANTIVIRUS يشتغل بالخلفية ويحمي جهازك', scanDone: 'انتهى الفحص', clean: 'ما لكينا أي تهديد ✔', found: n => `تم اكتشاف ${n} تهديد`
  },
  en: {
    protected: 'Your PC is protected', scanning: 'Scanning...', danger: 'Threat detected!', open: 'Open IBRA ANTIVIRUS',
    quick: 'Quick scan', pause: 'Pause real-time protection', resume: 'Resume real-time protection', quit: 'Exit',
    threatTitle: 'IBRA ANTIVIRUS - Threat', threatBody: (n, f) => `${n}\n${f}`, quarantined: 'Moved to quarantine',
    usbTitle: 'New USB drive', usbBody: d => `Scanning ${d}`, usbClean: d => `USB drive ${d} is clean ✔`,
    tray: 'IBRA ANTIVIRUS keeps running in the background', scanDone: 'Scan finished', clean: 'No threats found ✔', found: n => `${n} threat(s) found`
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
    settings: store.all(),
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

function showWindow() {
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
      updater.on('update-downloaded', i => push('app-update', { status: 'ready', version: i.version }));
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
});

app.on('before-quit', () => { quitting = true; });
app.on('window-all-closed', () => { /* keep running in tray */ });
