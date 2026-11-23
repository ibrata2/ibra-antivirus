// Scan orchestrator: collects files and runs them through every engine.
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const heur = require('./heuristics');
const clam = require('./clamav');
const yara = require('./yara');
const defender = require('./defender');
const sys = require('./sys');

const RISKY_EXT = new Set([
  '.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.msi', '.msp', '.jar', '.lnk', '.inf',
  '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.psm1', '.reg',
  '.zip', '.rar', '.7z', '.cab', '.iso', '.img', '.tar', '.gz',
  '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.rtf', '.pdf', '.php', '.apk'
]);
const SKIP_DIRS = new Set(['system volume information', 'winsxs', '$windows.~bt', '$windows.~ws', 'windowsapps', 'servicing', 'installer']);
const SEV_RANK = { high: 2, medium: 1 };

class Scanner extends EventEmitter {
  constructor({ store, quarantine, selfDirs = [] }) {
    super();
    this.store = store;
    this.q = quarantine;
    this.selfDirs = selfDirs.map(d => path.resolve(d).toLowerCase());
    this.running = null;
    this.procs = new Set();
  }

  isSelf(p) {
    const lp = path.resolve(p).toLowerCase();
    return this.selfDirs.some(d => lp === d || lp.startsWith(d + path.sep));
  }

  register(p) { this.procs.add(p); p.on('close', () => this.procs.delete(p)); }

  cancel() {
    if (!this.running) return;
    this.running.cancelled = true;
    for (const p of this.procs) { try { p.kill(); } catch {} }
  }

  status() { return this.running ? { ...this.running.progress, type: this.running.type } : null; }

  async walk(root, out, job, opts) {
    const stack = [{ dir: root, depth: 0 }];
    let st;
    try { st = fs.statSync(root); } catch { return; }
    if (st.isFile()) { if (!this.isSelf(root) && !this.store.isExcluded(root)) out.push(root); return; }
    while (stack.length) {
      if (job.cancelled) return;
      const { dir, depth } = stack.pop();
      if (this.isSelf(dir) || this.store.isExcluded(dir)) continue;
      let entries;
      try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        if (e.isSymbolicLink()) continue;
        const f = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (SKIP_DIRS.has(e.name.toLowerCase())) continue;
          if (opts.maxDepth == null || depth < opts.maxDepth) stack.push({ dir: f, depth: depth + 1 });
        } else if (e.isFile()) {
          if (opts.riskyOnly && !RISKY_EXT.has(path.extname(e.name).toLowerCase())) continue;
          if (this.store.isExcluded(f)) continue;
          out.push(f);
          if (out.length % 500 === 0) this._emit(job, { phase: 'collect', collected: out.length, current: dir });
          if (out.length % 2000 === 0) await new Promise(r => setImmediate(r));
        }
      }
    }
  }

  _emit(job, patch, force) {
    Object.assign(job.progress, patch);
    const now = Date.now();
    if (force || now - job.lastEmit > 120) { job.lastEmit = now; this.emit('progress', { ...job.progress, type: job.type }); }
  }

  /**
   * @param {{type:'quick'|'full'|'custom'|'usb'|'realtime', targets?:string[], removableRoots?:string[], silent?:boolean}} req
   */
  async scan(req) {
    if (this.running) throw new Error('busy');
    const s = this.store.all();
    const job = {
      type: req.type, cancelled: false, lastEmit: 0,
      progress: { phase: 'collect', collected: 0, scanned: 0, total: 0, found: 0, current: '', engine: '' , started: Date.now() }
    };
    this.running = job;
    this.emit('start', { type: req.type, silent: !!req.silent });
    const threats = new Map();
    const addThreat = t => {
      if (!t || !t.path) return;
      const key = t.path.toLowerCase();
      const sev = t.severity || 'high';
      const ex = threats.get(key);
      if (ex) {
        if (!ex.engines.includes(t.engine)) ex.engines.push(t.engine);
        if (SEV_RANK[sev] > SEV_RANK[ex.severity]) { ex.severity = sev; ex.name = t.name; }
        if (ex.engines.length >= 2) ex.severity = 'high';
      } else {
        threats.set(key, { path: t.path, name: t.name, severity: sev, engines: [t.engine] });
        job.progress.found = threats.size;
        this.emit('threat', threats.get(key));
      }
    };

    const maxMB = s.maxFileSizeMB || 150;
    const files = [];
    const removable = (req.removableRoots || []).map(r => r.toLowerCase());
    let defenderTargets = [];

    try {
      // ---------- 1. collect ----------
      this._emit(job, { phase: 'collect' }, true);
      if (req.type === 'quick') {
        const roots = sys.quickRoots();
        for (const r of roots) await this.walk(r, files, job, { riskyOnly: true, maxDepth: 5 });
        for (const p of await sys.runningProcessPaths()) files.push(p);
        for (const e of await sys.startupEntries()) if (e.file) files.push(e.file);
        defenderTargets = roots.filter(r => /desktop|downloads|startup|temp/i.test(r));
      } else if (req.type === 'full') {
        for (const d of sys.allDrives()) await this.walk(d, files, job, {});
        defenderTargets = clam.dbInfo().ready && s.useClamAV ? [] : sys.allDrives();
      } else {
        for (const t of req.targets || []) await this.walk(t, files, job, {});
        defenderTargets = (req.targets || []).slice();
      }
      // de-dup + size filter
      const seen = new Set();
      const list = [];
      for (const f of files) {
        const k = f.toLowerCase();
        if (seen.has(k) || this.isSelf(f) || this.q.isQuarantineFile(f)) continue;
        seen.add(k);
        try {
          const st = fs.statSync(f);
          if (!st.isFile()) continue;
          if (st.size > maxMB * 1048576) { const inf = heur.inflated(f, st.size); if (inf) addThreat({ path: f, name: inf.name, severity: inf.severity, engine: 'IBRA' }); continue; }
        } catch { continue; }
        list.push(f);
      }
      if (job.cancelled) throw new Error('cancelled');

      // ---------- 2. IBRA heuristics ----------
      const total = list.length;
      const engines = ['IBRA'];
      const useClam = s.useClamAV && clam.installed() && clam.dbInfo().ready;
      const useYara = s.useYara && yara.installed();
      const useDef = s.useDefender && defender.installed() && defenderTargets.length > 0;
      if (useClam) engines.push('ClamAV');
      if (useYara) engines.push('YARA');
      if (useDef) engines.push('Defender');
      const passes = engines.length;
      job.progress.engines = engines;
      let done = 0;
      const step = (n = 1) => { done += n; this._emit(job, { scanned: Math.min(done, total * passes), total: total * passes }); };

      this._emit(job, { phase: 'scan', engine: 'IBRA', total: total * passes, scanned: 0 }, true);
      for (let i = 0; i < list.length; i++) {
        if (job.cancelled) throw new Error('cancelled');
        const f = list[i];
        const dir = path.dirname(f).toLowerCase() + (path.dirname(f).endsWith('\\') ? '' : '\\');
        const r = heur.check(f, { removableRoot: removable.includes(dir) || removable.includes(path.dirname(f).toLowerCase()) });
        if (r) addThreat({ path: f, name: r.name, severity: r.severity, engine: 'IBRA' });
        job.progress.current = f;
        step();
        if (i % 200 === 0) await new Promise(r2 => setImmediate(r2));
      }

      // ---------- 3. ClamAV ----------
      if (useClam && !job.cancelled) {
        this._emit(job, { engine: 'ClamAV' }, true);
        const base = done;
        let c = 0;
        await clam.scan(list, {
          onFile: fp => { c++; job.progress.current = fp; done = base + Math.min(c, total); this._emit(job, { scanned: done }); },
          onFound: t => addThreat({ ...t, severity: 'high' })
        }, { maxFileSizeMB: maxMB, register: p => this.register(p) });
        done = base + total;
      }
      if (job.cancelled) throw new Error('cancelled');

      // ---------- 4. YARA ----------
      if (useYara) {
        this._emit(job, { engine: 'YARA', current: '' }, true);
        await yara.scan(list, { onFound: addThreat }, { maxFileSizeMB: maxMB, register: p => this.register(p) });
        step(total);
      }
      if (job.cancelled) throw new Error('cancelled');

      // ---------- 5. Microsoft Defender ----------
      if (useDef) {
        const per = total / defenderTargets.length;
        for (const t of defenderTargets) {
          if (job.cancelled) break;
          this._emit(job, { engine: 'Defender', current: t }, true);
          const r = await defender.scanPath(t, { register: p => this.register(p) });
          for (const th of r.threats) addThreat({ ...th, severity: 'high' });
          step(per);
        }
      }
      if (job.cancelled) throw new Error('cancelled');

      // ---------- 6. auto quarantine ----------
      const result = [...threats.values()];
      if (s.autoQuarantine && !req.noAutoAction) {
        for (const t of result) {
          if (t.severity !== 'high') continue;
          try { const it = this.q.add(t.path, { name: t.name, engine: t.engines.join(' + ') }); t.action = 'quarantined'; t.qid = it.id; }
          catch (e) { t.action = 'failed'; t.error = e.code || e.message; }
        }
      }
      const summary = {
        type: req.type, targets: req.targets || [], started: job.progress.started, finished: Date.now(),
        files: total, engines, threats: result, cancelled: false
      };
      if (req.type !== 'realtime') { this.store.addHistory(summary); this.store.set('lastScan', summary.finished); }
      this._emit(job, { phase: 'done', scanned: total * passes }, true);
      this.running = null;
      this.emit('done', summary);
      return summary;
    } catch (e) {
      const summary = { type: req.type, targets: req.targets || [], started: job.progress.started, finished: Date.now(), files: job.progress.scanned, engines: job.progress.engines || [], threats: [...threats.values()], cancelled: job.cancelled, error: job.cancelled ? null : String(e.message || e) };
      this.running = null;
      this.emit('done', summary);
      return summary;
    }
  }

  /** Quick single-file check used by real-time protection (does not block full scans). */
  async checkFile(file, ctx = {}, opt = { clam: true }) {
    if (this.isSelf(file) || this.store.isExcluded(file) || this.q.isQuarantineFile(file)) return null;
    let st; try { st = fs.statSync(file); } catch { return null; }
    if (!st.isFile()) return null;
    if (st.size > (this.store.get('maxFileSizeMB') || 150) * 1048576) {
      const inf = heur.inflated(file, st.size);
      return inf ? { path: file, name: inf.name, severity: inf.severity, engines: ['IBRA'] } : null;
    }
    const found = [];
    const h = heur.check(file, ctx);
    if (h) found.push({ name: h.name, severity: h.severity, engine: 'IBRA' });
    const s = this.store.all();
    if (s.useYara && yara.installed()) await yara.scan([file], { onFound: t => found.push(t) });
    if (opt.clam && s.useClamAV && clam.installed() && clam.dbInfo().ready && !found.some(f => f.severity === 'high')) {
      await clam.scan([file], { onFound: t => found.push({ ...t, severity: 'high' }) }, { maxFileSizeMB: s.maxFileSizeMB });
    }
    if (s.useDefender && defender.installed() && !found.some(f => f.severity === 'high')) {
      const r = await defender.scanPath(file);
      for (const t of r.threats) found.push({ ...t, severity: 'high' });
    }
    if (!found.length) return null;
    found.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
    const engines = [...new Set(found.map(f => f.engine))];
    return { path: file, name: found[0].name, severity: engines.length > 1 ? 'high' : found[0].severity, engines };
  }
}

module.exports = Scanner;
