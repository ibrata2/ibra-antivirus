// IBRA ANTIVIRUS — behaviour guard controller (talks to tools/guard/ibra-guard.exe).
// Service mode : the installer registers the "IBRA ANTIVIRUS Guard" task that runs the guard as SYSTEM from boot —
//                launch + command + stealer + ransomware guard, and self-protection of the app (normal programs cannot
//                stop it or close the app). What to protect is sent from guardplan.js once it connects.
// Basic mode   : no task (development / repair needed): the guard runs with the app, without admin rights.
const EventEmitter = require('events');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const P = require('./paths');

const PORT = 47220;
const TASK = 'IBRA ANTIVIRUS Guard';
const NEVER_QUARANTINE = /\\windows\\|\\program files( \(x86\))?\\(windowsapps|common files)\\/i;
const SCRIPT_HOSTS = /\\(powershell|pwsh|powershell_ise|wscript|cscript|mshta|cmd|rundll32|regsvr32|msbuild|installutil|regasm|regsvcs|wmic|conhost|bitsadmin|certutil|curl|msiexec|forfiles|finger|hh|cmstp|python|pythonw|node)\.exe$/i;

class Guard extends EventEmitter {
  constructor({ store, scanner, quarantine }) {
    super();
    this.store = store; this.scanner = scanner; this.q = quarantine;
    this.sock = null; this.child = null; this.server = null;
    this.state = { connected: false, admin: false, mode: null, protected: 0, audit: false };
    this.cacheFile = P.data('guard-cache.json');
    try { this.clean = new Map(Object.entries(JSON.parse(fs.readFileSync(this.cacheFile, 'utf8')))); } catch { this.clean = new Map(); }
    this.serviceTokenFile = path.join(process.env.ProgramData || 'C:\\ProgramData', 'IBRA ANTIVIRUS', 'guard.token');
    this.tokenFile = P.data('guard.token');
    try { this.token = fs.readFileSync(this.tokenFile, 'utf8').trim(); } catch { this.token = ''; }
    if (!this.token) { this.token = crypto.randomBytes(24).toString('hex'); try { fs.mkdirSync(P.data(), { recursive: true }); fs.writeFileSync(this.tokenFile, this.token); } catch {} }
  }

  exe() { return P.vendor('ibra-guard.exe'); }
  available() { return process.platform === 'win32' && P.exists(this.exe()); }

  start() {
    if (!this.available() || this.started) return;
    this.started = true;
    this.server = net.createServer(s => this.attach(s, 'task'));
    this.server.on('error', () => {});
    this.server.listen(PORT, '127.0.0.1');
    // the SYSTEM guard connects by itself within a few seconds; without it fall back to the basic guard
    setTimeout(() => { if (!this.state.connected) this.startChild(); }, 9000);
  }

  serviceToken() { try { return fs.readFileSync(this.serviceTokenFile, 'utf8').trim(); } catch { return ''; } }
  bye() { this.cmd('bye'); }

  // the user approves with an administrator prompt (programs cannot click it) — used before closing the app
  confirmAdmin() {
    return new Promise(resolve => {
      if (!this.available()) return resolve(true);
      execFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        `try { $p = Start-Process -FilePath '${this.exe().replace(/'/g, "''")}' -ArgumentList '--ok' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; if ($p.ExitCode -eq 0) { 'ok' } } catch { 'denied' }`],
      { windowsHide: true, timeout: 180000 }, (e, out) => resolve(/ok/.test(String(out || ''))));
    });
  }

  stop() { try { this.child && this.child.kill(); } catch {} this.child = null; }

  startChild() {
    if (this.child || (this.state.connected && this.state.admin)) return;
    try {
      const c = spawn(this.exe(), ['--stdio'], { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
      this.child = c;
      this.attach({ write: d => { try { c.stdin.write(d); } catch {} }, stream: c.stdout, child: true }, 'child');
      c.on('exit', () => { if (this.child === c) { this.child = null; if (this.mode === 'child') this.setState({ connected: false }); setTimeout(() => this.startChild(), 5000); } });
    } catch {}
  }

  attach(s, kind) {
    const stream = s.stream || s;
    let buf = '';
    let authed = kind === 'child';
    const send = line => { try { (s.write ? s.write.bind(s) : stream.write.bind(stream))(line + '\n'); } catch {} };
    stream.on('data', d => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        let ev; try { ev = JSON.parse(line); } catch { continue; }
        if (ev.type === 'hello') {
          if (kind === 'task' && (!ev.token || (ev.token !== this.token && ev.token !== this.serviceToken()))) { try { stream.destroy(); } catch {} return; }
          authed = true;
          if (kind === 'task') { this.sock = send; this.mode = 'task'; this.stop(); }   // elevated guard replaces the basic one
          if (kind === 'task' && ev.admin) { try { for (const l of require('./guardplan').plan()) send(l); } catch {} }
          else if (this.mode !== 'task') { this.sock = send; this.mode = 'child'; }
          this.setState({ connected: true, admin: !!ev.admin, mode: kind, protected: ev.protected || this.state.protected, audit: !!ev.audit || this.state.audit });
          for (const p of this.trusted()) send('trust ' + p);
          continue;
        }
        if (!authed) continue;
        this.onEvent(ev, send);
      }
    });
    const gone = () => { if (this.mode === kind) { this.sock = null; this.mode = null; this.setState({ connected: false, admin: false }); if (kind === 'task') this.startChild(); } };
    stream.on('close', gone); stream.on('error', gone);
  }

  setState(p) { Object.assign(this.state, p); this.emit('state', this.state); }
  trusted() { return (this.store.get('guardTrusted') || []).slice(0, 500); }
  cmd(line) { if (this.sock) this.sock(line); }

  log(entry) {
    const l = this.store.get('guardLog') || [];
    l.unshift({ ...entry, date: Date.now() });
    this.store.set('guardLog', l.slice(0, 200));
    const st = this.store.get('guardStats') || { checked: 0, blocked: 0 };
    if (entry.action === 'checked') st.checked++; else if (entry.action !== 'info') st.blocked++;
    this.store.set('guardStats', st);
    this.emit('log', entry);
  }

  saveCache() {
    if (this.clean.size > 5000) this.clean = new Map([...this.clean].slice(-3000));
    clearTimeout(this._st); this._st = setTimeout(() => { try { fs.writeFileSync(this.cacheFile, JSON.stringify(Object.fromEntries(this.clean))); } catch {} }, 2000);
  }

  // the killed process may hold its file for a moment: retry for ~4 s
  async quarantineImage(p, name) {
    if (!p || NEVER_QUARANTINE.test(p) || SCRIPT_HOSTS.test(p)) return null;
    for (let i = 0; i < 10; i++) {
      try { if (!fs.existsSync(p)) return null; return this.q.add(p, { name, engine: 'IBRA Guard' }); } catch { await new Promise(r => setTimeout(r, 400)); }
    }
    return null;
  }

  async onEvent(ev, send) {
    if (ev.type === 'protected') return this.setState({ protected: ev.count });
    if (ev.type === 'audit') return this.setState({ audit: !!ev.on });
    if (ev.type === 'watch') return this.setState({ watch: ev.mode });
    if (ev.type === 'restarted') return;
    if (ev.type === 'launch') return this.onLaunch(ev, send);
    if (ev.type === 'blocked') {
      const name = ev.kind === 'stealer' ? 'Behavior.Stealer' : ev.kind === 'ransomware' ? 'Behavior.Ransomware' : 'Behavior.MaliciousCommand';
      // a process that tried to steal passwords or encrypt files: its program file goes to quarantine
      const qi = ev.kind === 'command' ? null : await this.quarantineImage(ev.path, name);
      this.log({ action: 'blocked', kind: ev.kind, path: ev.path, file: ev.file, what: ev.what, cmd: ev.cmd, quarantined: !!qi });
      this.emit('blocked', { ...ev, name, quarantined: !!qi });
      return;
    }
    if (ev.type === 'access') { this.log({ action: 'info', kind: 'access', path: ev.path, file: ev.file, what: ev.what }); return; }
  }

  async onLaunch(ev, send) {
    const file = ev.path;
    let st; try { st = fs.statSync(file); } catch { send('resume ' + ev.pid); return; }
    const key = `${file}|${st.size}|${st.mtimeMs}`;
    if (this.clean.has(key)) { send('resume ' + ev.pid); return; }
    let threat = null;
    try {
      threat = await Promise.race([
        this.scanner.checkFile(file, {}, { clam: st.size < 40 * 1048576, launch: true }),
        new Promise(r => setTimeout(() => r(undefined), 15000))
      ]);
    } catch {}
    if (threat === undefined) { send('resume ' + ev.pid); return; }           // scan too slow: never block the user
    if (threat && threat.severity === 'high') {
      send('kill ' + ev.pid);
      await new Promise(r => setTimeout(r, 400));
      const qi = await this.quarantineImage(file, threat.name);
      this.log({ action: 'blocked', kind: 'launch', path: file, name: threat.name, engines: threat.engines, quarantined: !!qi });
      this.emit('blocked', { kind: 'launch', path: file, name: threat.name, engines: threat.engines, quarantined: !!qi });
      return;
    }
    send('resume ' + ev.pid);
    if (!threat) { this.clean.set(key, 1); this.saveCache(); }
    this.log({ action: 'checked', kind: 'launch', path: file, name: threat ? threat.name : null });
  }

  trust(p) {
    const t = new Set(this.trusted()); t.add(p);
    this.store.set('guardTrusted', [...t]);
    this.cmd('trust ' + p);
  }

  // ---------------------------------------------------------------- advanced mode (scheduled task, elevated)
  runTask() { execFile('schtasks.exe', ['/run', '/tn', TASK], { windowsHide: true }, () => {}); }

  script() { return path.join(P.resRoot(), 'scripts', 'guard-task.ps1'); }

  // repair: install the SYSTEM task again (the installer normally does this) — needs one administrator approval
  enableAdvanced() {
    return new Promise(resolve => {
      const q = s => "'" + String(s).replace(/'/g, "''") + "'";
      execFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        `try { $p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',${q('"' + this.script() + '"')},'-Exe',${q('"' + this.exe() + '"')}; 'ok' } catch { 'denied' }`],
      { windowsHide: true, timeout: 180000 }, (e, out) => {
        const ok = /ok/.test(String(out || ''));
        if (ok) this.store.set('guardAdvanced', true);
        let n = 0;
        const iv = setInterval(() => { if ((this.state.connected && this.state.admin) || ++n > 30) { clearInterval(iv); resolve({ ok: ok && this.state.admin, registered: ok }); } }, 500);
      });
    });
  }

  disableAdvanced() {
    return new Promise(resolve => {
      execFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
        `Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-Command',"Unregister-ScheduledTask -TaskName '${TASK}' -Confirm:$false; Stop-Process -Name ibra-guard -Force -ErrorAction SilentlyContinue"`],
      { windowsHide: true, timeout: 60000 }, () => { this.store.set('guardAdvanced', false); this.startChild(); resolve({ ok: true }); });
    });
  }
}

module.exports = { Guard, TASK };
