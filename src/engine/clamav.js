// ClamAV engine (open-source signatures, updated daily by Cisco Talos)
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const P = require('./paths');

const clamscan = () => P.vendor('clamav', 'clamscan.exe');
const freshclam = () => P.vendor('clamav', 'freshclam.exe');
const dbDir = () => P.data('clamdb');

function installed() { return P.exists(clamscan()) && P.exists(freshclam()); }

function dbInfo() {
  const d = dbDir();
  const has = n => P.exists(path.join(d, n + '.cvd')) || P.exists(path.join(d, n + '.cld'));
  let date = null;
  for (const n of ['daily.cld', 'daily.cvd']) {
    try { date = fs.statSync(path.join(d, n)).mtime.toISOString(); break; } catch {}
  }
  return { ready: has('main') && has('daily'), date };
}

function dirSize(d) {
  let total = 0;
  try {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) total += dirSize(f);
      else try { total += fs.statSync(f).size; } catch {}
    }
  } catch {}
  return total;
}

function writeConf() {
  fs.mkdirSync(dbDir(), { recursive: true });
  const conf = path.join(P.data(), 'freshclam.conf');
  fs.writeFileSync(conf, [
    'DatabaseMirror database.clamav.net',
    `DatabaseDirectory ${dbDir()}`,
    'ConnectTimeout 60',
    'ReceiveTimeout 0',
    'MaxAttempts 3',
    'Checks 12',
    'Bytecode yes',
    ''
  ].join('\r\n'));
  return conf;
}

let updating = null;
/** Download / update signatures. onProgress({file, percent, line}) */
function update(onProgress = () => {}) {
  if (!installed()) return Promise.resolve({ ok: false, error: 'clamav-missing' });
  if (updating) return updating;
  updating = new Promise(resolve => {
    const conf = writeConf();
    const p = spawn(freshclam(), [`--config-file=${conf}`, `--datadir=${dbDir()}`, '--stdout'], { windowsHide: true, cwd: path.dirname(freshclam()) });
    let out = '';
    // Progress estimate from bytes on disk (full database is ~240 MB)
    const startSize = dirSize(dbDir());
    const fresh = startSize < 50 * 1024 * 1024;
    const timer = setInterval(() => {
      const now = dirSize(dbDir());
      const percent = fresh ? Math.min(99, Math.round(now / (240 * 1024 * 1024) * 100)) : null;
      onProgress({ percent, mb: Math.round(now / 1048576) });
    }, 1000);
    const onData = d => {
      const s = d.toString();
      out += s;
      for (const line of s.split(/[\r\n]+/)) if (line.trim()) onProgress({ line: line.trim() });
    };
    p.stdout.on('data', onData);
    p.stderr.on('data', onData);
    p.on('error', e => { clearInterval(timer); updating = null; resolve({ ok: false, error: e.message }); });
    p.on('close', code => {
      clearInterval(timer);
      updating = null;
      const info = dbInfo();
      resolve({ ok: info.ready && (code === 0 || code === 1 || /up.to.date|updated/i.test(out)), code, info, tail: out.slice(-1500) });
    });
  });
  return updating;
}

/**
 * Scan a list of files.
 * cb.onFile(path) per scanned file, cb.onFound({path,name})
 * returns { ok, killed, error }
 */
function scan(files, cb, opts = {}) {
  return new Promise(resolve => {
    if (!installed() || !dbInfo().ready || !files.length) return resolve({ ok: false, skipped: true });
    const list = path.join(os.tmpdir(), `ibra-clam-${process.pid}-${Date.now()}.txt`);
    fs.writeFileSync(list, files.join('\n'), 'utf8');
    const mb = opts.maxFileSizeMB || 150;
    const args = [
      `--database=${dbDir()}`, `--file-list=${list}`, '--stdout', '--no-summary',
      `--max-filesize=${mb}M`, `--max-scansize=${mb * 2}M`, '--max-recursion=12', '--max-files=20000'
    ];
    const p = spawn(clamscan(), args, { windowsHide: true, cwd: path.dirname(clamscan()) });
    if (opts.register) opts.register(p);
    let buf = '';
    let killed = false;
    p.on('killed-by-user', () => { killed = true; });
    p.stdout.on('data', d => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
        const k = line.lastIndexOf(': ');
        if (k < 0) continue;
        const fp = line.slice(0, k); const res = line.slice(k + 2);
        if (/ FOUND$/.test(res)) cb.onFound && cb.onFound({ path: fp, name: res.replace(/ FOUND$/, ''), engine: 'ClamAV' });
        cb.onFile && cb.onFile(fp);
      }
    });
    p.stderr.on('data', () => {});
    p.on('error', e => resolve({ ok: false, error: e.message }));
    p.on('close', code => {
      try { fs.unlinkSync(list); } catch {}
      resolve({ ok: code === 0 || code === 1, code, killed: killed || p.killed });
    });
  });
}

module.exports = { installed, dbInfo, update, scan, dbDir };
