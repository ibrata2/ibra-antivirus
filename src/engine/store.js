// Simple JSON storage for settings, scan history and events
const fs = require('fs');
const path = require('path');

class Store {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.file = path.join(dir, 'settings.json');
    this.histFile = path.join(dir, 'history.json');
    this.defaults = {
      lang: 'ar',
      realtime: true,
      usbAutoScan: true,
      autoQuarantine: true,
      useDefender: true,
      useClamAV: true,
      useYara: true,
      runAtStartup: true,
      minimizeToTray: true,
      maxFileSizeMB: 150,
      exclusions: [],
      lastScan: null,
      lastDbUpdate: null
    };
    this.data = { ...this.defaults, ...this._read(this.file, {}) };
    this.history = this._read(this.histFile, []);
  }
  _read(f, def) {
    try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return def; }
  }
  _write(f, v) {
    try {
      const tmp = f + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(v, null, 2));
      fs.renameSync(tmp, f);
    } catch (e) { console.error('store write', e); }
  }
  get(k) { return this.data[k]; }
  all() { return { ...this.data }; }
  set(k, v) { this.data[k] = v; this._write(this.file, this.data); }
  patch(obj) { Object.assign(this.data, obj); this._write(this.file, this.data); }
  addHistory(entry) {
    this.history.unshift(entry);
    this.history = this.history.slice(0, 200);
    this._write(this.histFile, this.history);
  }
  clearHistory() { this.history = []; this._write(this.histFile, this.history); }
  isExcluded(p) {
    const lp = String(p).toLowerCase();
    return (this.data.exclusions || []).some(e => {
      const le = String(e).toLowerCase().replace(/[\\/]+$/, '');
      return lp === le || lp.startsWith(le + '\\') || lp.startsWith(le + '/');
    });
  }
}
module.exports = Store;
