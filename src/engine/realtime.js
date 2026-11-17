// Real-time protection: watches risky folders and checks every new or changed file.
// USB monitor: notices when a flash drive / memory card is plugged in.
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const os = require('os');
const sys = require('./sys');
const clam = require('./clamav');

const WATCH_EXT = new Set(['.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.msi', '.jar', '.lnk', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.ps1', '.reg', '.zip', '.rar', '.7z', '.iso', '.docm', '.xlsm', '.pptm', '.doc', '.xls', '.pdf', '.apk', '.inf']);
const TEMP_EXT = /\.(crdownload|part|partial|download|tmp|opdownload)$/i;

class RealTime extends EventEmitter {
  constructor(scanner, store) {
    super();
    this.scanner = scanner;
    this.store = store;
    this.watchers = [];
    this.pending = new Map();
    this.queue = [];
    this.busy = false;
    this.clamBatch = new Set();
    this.recent = new Map();
    this.active = false;
  }

  folders() {
    const h = os.homedir();
    return [path.join(h, 'Downloads'), path.join(h, 'Desktop'), path.join(h, 'Documents'), ...sys.startupFolders(), process.env.TEMP]
      .filter(Boolean).filter((p, i, a) => a.indexOf(p) === i)
      .filter(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } });
  }

  start() {
    if (this.active) return;
    this.active = true;
    for (const dir of this.folders()) {
      try {
        const deep = !/\\temp$/i.test(dir);
        const w = fs.watch(dir, { recursive: deep, persistent: false }, (ev, name) => {
          if (!name) return;
          this.touch(path.join(dir, name.toString()));
        });
        w.on('error', () => {});
        this.watchers.push(w);
      } catch (e) { /* folder not watchable */ }
    }
    this.clamTimer = setInterval(() => this.flushClam(), 6000);
    this.emit('state', true);
  }

  stop() {
    this.active = false;
    for (const w of this.watchers) try { w.close(); } catch {}
    this.watchers = [];
    clearInterval(this.clamTimer);
    this.emit('state', false);
  }

  touch(file) {
    const ext = path.extname(file).toLowerCase();
    if (TEMP_EXT.test(file) || !WATCH_EXT.has(ext)) return;
    if (this.scanner.isSelf(file) || this.store.isExcluded(file)) return;
    clearTimeout(this.pending.get(file));
    // wait until the file stops changing (download finished)
    this.pending.set(file, setTimeout(() => { this.pending.delete(file); this.enqueue(file); }, 1500));
  }

  enqueue(file) {
    let st; try { st = fs.statSync(file); } catch { return; }
    if (!st.isFile()) return;
    const key = file.toLowerCase();
    const sig = st.size + ':' + st.mtimeMs;
    if (this.recent.get(key) === sig) return;
    this.recent.set(key, sig);
    if (this.recent.size > 5000) this.recent.clear();
    this.queue.push(file);
    this.pump();
  }

  async pump() {
    if (this.busy) return;
    this.busy = true;
    while (this.queue.length) {
      const f = this.queue.shift();
      this.emit('checking', f);
      try {
        const t = await this.scanner.checkFile(f, {}, { clam: false });
        if (t) this.emit('threat', t);
        else this.clamBatch.add(f);
      } catch {}
    }
    this.busy = false;
  }

  async flushClam() {
    if (!this.clamBatch.size || this.scanner.running || this.clamBusy) return;
    if (!this.store.get('useClamAV') || !clam.installed() || !clam.dbInfo().ready) { this.clamBatch.clear(); return; }
    const files = [...this.clamBatch].filter(f => { try { return fs.statSync(f).isFile(); } catch { return false; } });
    this.clamBatch.clear();
    if (!files.length) return;
    this.clamBusy = true;
    await clam.scan(files, { onFound: t => this.emit('threat', { path: t.path, name: t.name, severity: 'high', engines: ['ClamAV'] }) }, { maxFileSizeMB: this.store.get('maxFileSizeMB') });
    this.clamBusy = false;
  }
}

class UsbMonitor extends EventEmitter {
  constructor() { super(); this.known = new Set(); this.timer = null; }
  letters() {
    const r = [];
    for (let c = 68; c <= 90; c++) { const d = String.fromCharCode(c) + ':\\'; try { fs.accessSync(d); r.push(d); } catch {} }
    return r;
  }
  start() {
    if (this.timer || process.platform !== 'win32') return;
    this.known = new Set(this.letters());
    this.timer = setInterval(async () => {
      const now = new Set(this.letters());
      const added = [...now].filter(d => !this.known.has(d));
      this.known = now;
      if (!added.length) return;
      const removable = await sys.removableDrives();
      for (const d of added) if (removable.includes(d.toUpperCase())) this.emit('inserted', d);
    }, 2500);
  }
  stop() { clearInterval(this.timer); this.timer = null; }
}

module.exports = { RealTime, UsbMonitor };
