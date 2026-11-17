// Windows helpers (PowerShell queries). All return safe defaults on other platforms.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function ps(script, timeout = 30000) {
  return new Promise(resolve => {
    if (process.platform !== 'win32') return resolve('');
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      '[Console]::OutputEncoding=[Text.Encoding]::UTF8;' + script],
    { windowsHide: true, timeout, maxBuffer: 32 * 1024 * 1024 }, (err, out) => resolve(err && !out ? '' : String(out || '')));
  });
}

async function runningProcessPaths() {
  const out = await ps('Get-Process | Where-Object { $_.Path } | ForEach-Object { $_.Path } | Sort-Object -Unique');
  return out.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

// Program paths from Run/RunOnce registry keys
async function startupEntries() {
  const out = await ps(`
$keys='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
foreach($k in $keys){ try { $p=Get-ItemProperty -Path $k -ErrorAction Stop; $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $k + '|' + $_.Name + '|' + $_.Value } } catch {} }`);
  return out.split(/\r?\n/).filter(Boolean).map(l => {
    const [key, name, ...rest] = l.split('|');
    const cmd = rest.join('|');
    return { key, name, cmd, file: extractExe(cmd) };
  });
}

function extractExe(cmd) {
  if (!cmd) return null;
  cmd = cmd.replace(/%([^%]+)%/g, (_, v) => process.env[v] || process.env[v.toUpperCase()] || _);
  let m = cmd.match(/^\s*"([^"]+)"/);
  if (m) return m[1];
  m = cmd.match(/^\s*(.+?\.(exe|bat|cmd|vbs|js|ps1|scr|com))\b/i);
  return m ? m[1] : null;
}

/** Removable drives (USB sticks / memory cards) -> ['E:\\', ...] */
async function removableDrives() {
  if (process.platform !== 'win32') return [];
  const out = await ps('Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ForEach-Object { $_.DeviceID }', 15000);
  return out.split(/\r?\n/).map(s => s.trim()).filter(s => /^[A-Z]:$/i.test(s)).map(s => s.toUpperCase() + '\\');
}

/** Fixed + removable drive roots that exist */
function allDrives() {
  if (process.platform !== 'win32') return ['/'];
  const r = [];
  for (let c = 67; c <= 90; c++) { const d = String.fromCharCode(c) + ':\\'; try { fs.accessSync(d); r.push(d); } catch {} }
  return r;
}

function quickRoots() {
  const h = os.homedir();
  const e = process.env;
  const list = [
    path.join(h, 'Desktop'), path.join(h, 'Downloads'),
    e.TEMP, path.join(e.LOCALAPPDATA || '', 'Temp'),
    e.APPDATA, e.LOCALAPPDATA, path.join(h, 'AppData', 'LocalLow'),
    path.join(e.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    path.join(e.ProgramData || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    e.PUBLIC, e.ProgramData
  ].filter(Boolean);
  return [...new Set(list)].filter(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } });
}

function startupFolders() {
  const e = process.env;
  return [
    path.join(e.APPDATA || '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    path.join(e.ProgramData || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
  ];
}

module.exports = { ps, runningProcessPaths, startupEntries, removableDrives, allDrives, quickRoots, startupFolders, extractExe };
