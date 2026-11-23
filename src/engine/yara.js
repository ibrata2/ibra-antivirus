// YARA engine: pattern rules that catch malware families even when the file changes
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const P = require('./paths');

function exe() {
  for (const n of ['yara64.exe', 'yara.exe']) { const f = P.vendor('yara', n); if (P.exists(f)) return f; }
  return null;
}
function ruleFiles() {
  try { return fs.readdirSync(P.rules()).filter(f => /\.yara?$/i.test(f)).map(f => P.rules(f)); } catch { return []; }
}
function installed() { return !!exe() && ruleFiles().length > 0; }

const SEVERITY = { high: 'high', medium: 'medium' };

function scan(files, cb, opts = {}) {
  return new Promise(resolve => {
    if (!installed() || !files.length) return resolve({ ok: false, skipped: true });
    const list = path.join(os.tmpdir(), `ibra-yara-${process.pid}-${Date.now()}.txt`);
    // YARA for Windows reads --scan-list as UTF-16 (wide) text: UTF-8 garbles every path ("could not open file")
    fs.writeFileSync(list, Buffer.from(files.join('\r\n'), 'utf16le')); // no BOM: yara reads it as part of the first path
    const threads = String(Math.max(2, Math.min(8, os.cpus().length)));
    // yara [options] RULES_FILE... TARGET   (with --scan-list, TARGET is a text file of paths)
    const base = ['-w', '-m', '-p', threads, '--skip-larger=' + ((opts.maxFileSizeMB || 150) * 1048576)];
    // a single file is passed directly (no list file needed)
    const a = files.length === 1 ? [...base, ...ruleFiles(), files[0]] : [...base, '--scan-list', ...ruleFiles(), list];
    const p = spawn(exe(), a, { windowsHide: true });
    if (opts.register) opts.register(p);
    let buf = '';
    p.stdout.on('data', d => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
        // "RuleName [meta=..] C:\path"
        const m = line.match(/^(\S+)\s+(?:\[(.*?)\]\s+)?(.+)$/);
        if (!m) continue;
        const meta = m[2] || '';
        const sev = (meta.match(/severity="(\w+)"/) || [])[1] || 'high';
        cb.onFound && cb.onFound({ path: m[3], name: 'YARA.' + m[1], engine: 'YARA', severity: SEVERITY[sev] || 'high' });
      }
    });
    p.stderr.on('data', () => {});
    p.on('error', e => resolve({ ok: false, error: e.message }));
    p.on('close', code => { try { fs.unlinkSync(list); } catch {} resolve({ ok: code === 0, code }); });
  });
}

module.exports = { installed, scan };
