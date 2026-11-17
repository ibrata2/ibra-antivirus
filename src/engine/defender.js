// Microsoft Defender as a second engine (scan only, no remediation - IBRA decides)
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

function findMpCmdRun() {
  const cands = [];
  const pd = process.env.ProgramData || 'C:\\ProgramData';
  const plat = path.join(pd, 'Microsoft', 'Windows Defender', 'Platform');
  try {
    const vers = fs.readdirSync(plat).filter(v => /^\d/.test(v)).sort((a, b) => {
      const pa = a.split(/[.-]/).map(Number), pb = b.split(/[.-]/).map(Number);
      for (let i = 0; i < 4; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
      return 0;
    });
    for (const v of vers) cands.push(path.join(plat, v, 'MpCmdRun.exe'));
  } catch {}
  cands.push(path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe'));
  return cands.find(c => { try { return fs.existsSync(c); } catch { return false; } }) || null;
}

let cached;
function exe() { if (cached === undefined) cached = findMpCmdRun(); return cached; }
function installed() { return process.platform === 'win32' && !!exe(); }

function parse(out) {
  const threats = [];
  let cur = null;
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trim();
    let m = line.match(/^Threat\s*:\s*(.+)$/i);
    if (m) { cur = m[1].trim(); continue; }
    m = line.match(/^(file|containerfile)\s*:\s*(.+)$/i);
    if (m && cur) {
      let p = m[2].trim();
      const arrow = p.indexOf('->'); // inside an archive: "C:\a.zip->inner.exe"
      if (arrow > 0) p = p.slice(0, arrow);
      threats.push({ path: p, name: cur, engine: 'Defender' });
    }
  }
  return threats;
}

/** Scan a file or folder (recursive). Returns { ok, threats, unavailable } */
function scanPath(target, opts = {}) {
  return new Promise(resolve => {
    if (!installed()) return resolve({ ok: false, unavailable: true, threats: [] });
    const p = spawn(exe(), ['-Scan', '-ScanType', '3', '-File', target, '-DisableRemediation'], { windowsHide: true });
    if (opts.register) opts.register(p);
    let out = '';
    p.stdout.on('data', d => { out += d.toString(); });
    p.stderr.on('data', d => { out += d.toString(); });
    p.on('error', () => resolve({ ok: false, unavailable: true, threats: [] }));
    p.on('close', code => {
      const threats = parse(out);
      // 0 = clean, 2 = threats found; other codes usually mean Defender is off (another AV installed)
      const unavailable = code !== 0 && code !== 2 && !threats.length;
      resolve({ ok: !unavailable, unavailable, code, threats });
    });
  });
}

module.exports = { installed, scanPath, parse };
