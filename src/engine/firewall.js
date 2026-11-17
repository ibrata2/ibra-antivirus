// Firewall: uses the built-in Windows Firewall. Lists programs using the internet,
// blocks / allows them with rules named "IBRA Block | ...", and watches for new programs.
const EventEmitter = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ps } = require('./sys');

const PREFIX = 'IBRA Block';
const q = s => "'" + String(s).replace(/'/g, "''") + "'";   // PowerShell single-quoted string

/** Programs with live internet connections: [{ path, name, pids, connections, remotes }] */
async function connections() {
  const out = await ps(`
$c = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1$|0\\.0\\.0\\.0|::$)' }
$u = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\\.|::1$)' }
$byPid = @{}
foreach ($x in $c) { if (-not $byPid[$x.OwningProcess]) { $byPid[$x.OwningProcess] = @() }; $byPid[$x.OwningProcess] += ($x.RemoteAddress + ':' + $x.RemotePort) }
foreach ($k in $byPid.Keys) {
  $p = Get-Process -Id $k -ErrorAction SilentlyContinue
  $path = if ($p) { $p.Path } else { '' }
  $name = if ($p) { $p.ProcessName } else { 'pid ' + $k }
  $desc = if ($p -and $p.Path) { (Get-Item $p.Path -ErrorAction SilentlyContinue).VersionInfo.FileDescription } else { '' }
  $name + '|' + $path + '|' + $k + '|' + $byPid[$k].Count + '|' + (($byPid[$k] | Select-Object -Unique -First 4) -join ',') + '|' + $desc
}`, 25000);
  const map = new Map();
  for (const line of out.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [name, p, pid, count, remotes, desc] = line.split('|');
    const key = (p || name).toLowerCase();
    const e = map.get(key) || { name, desc: desc || '', path: p || '', pids: [], connections: 0, remotes: [] };
    e.pids.push(+pid); e.connections += +count || 0;
    for (const r of (remotes || '').split(',')) if (r && e.remotes.length < 4 && !e.remotes.includes(r)) e.remotes.push(r);
    map.set(key, e);
  }
  return [...map.values()].sort((a, b) => b.connections - a.connections);
}

/** Blocked programs: [{ path, name, rules }] */
async function blocked() {
  const out = await ps(`Get-NetFirewallRule -DisplayName '${PREFIX}*' -ErrorAction SilentlyContinue | ForEach-Object { $f = $_ | Get-NetFirewallApplicationFilter; $_.DisplayName + '|' + $_.Direction + '|' + $f.Program + '|' + $_.Enabled }`, 25000);
  const map = new Map();
  for (const line of out.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [display, dir, prog, enabled] = line.split('|');
    if (!prog) continue;
    const key = prog.toLowerCase();
    const e = map.get(key) || { path: prog, name: path.win32.basename(prog), directions: [], enabled: enabled === 'True' };
    e.directions.push(dir);
    map.set(key, e);
  }
  return [...map.values()];
}

async function profiles() {
  const out = await ps(`Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '|' + $_.Enabled }`, 15000);
  const r = {};
  for (const l of out.split(/\r?\n/)) { const [n, e] = l.trim().split('|'); if (n) r[n] = e === 'True'; }
  return r;
}

/** Runs a PowerShell script as administrator (Windows shows one UAC prompt). */
function elevated(script) {
  const file = path.join(os.tmpdir(), `ibra-fw-${Date.now()}.ps1`);
  const done = file + '.done';
  fs.writeFileSync(file, '﻿' + script + `\r\nSet-Content -Path ${q(done)} -Value 'ok'\r\n`, 'utf8');
  return ps(`try { Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',${q('"' + file + '"')} ; 'started' } catch { 'denied' }`, 120000)
    .then(out => {
      const ok = fs.existsSync(done);
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(done); } catch {}
      return { ok, denied: /denied/.test(out) };
    });
}

function blockScript(paths) {
  return paths.map(p => {
    const name = `${PREFIX} | ${path.win32.basename(p)}`;
    return `Remove-NetFirewallRule -DisplayName ${q(name)} -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName ${q(name)} -Description 'IBRA ANTIVIRUS' -Group 'IBRA ANTIVIRUS' -Direction Outbound -Program ${q(p)} -Action Block -Profile Any | Out-Null
New-NetFirewallRule -DisplayName ${q(name)} -Description 'IBRA ANTIVIRUS' -Group 'IBRA ANTIVIRUS' -Direction Inbound -Program ${q(p)} -Action Block -Profile Any | Out-Null`;
  }).join('\r\n');
}
function unblockScript(paths) {
  return paths.map(p => `Get-NetFirewallRule -DisplayName '${PREFIX}*' -ErrorAction SilentlyContinue | Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq ${q(p)} } | Remove-NetFirewallRule`).join('\r\n');
}

const block = paths => elevated(blockScript(paths));
const unblock = paths => elevated(unblockScript(paths));
const enableAll = () => elevated('Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True');

/** Notices programs that connect to the internet for the first time. */
class Monitor extends EventEmitter {
  constructor(store) { super(); this.store = store; this.timer = null; this.busy = false; }
  start() {
    if (this.timer || process.platform !== 'win32') return;
    this.timer = setInterval(() => this.tick(), 10000);
    this.tick(true);
  }
  stop() { clearInterval(this.timer); this.timer = null; }
  async tick(seed) {
    if (this.busy) return;
    this.busy = true;
    try {
      const list = await connections();
      const known = new Set((this.store.get('fwKnown') || []).map(s => s.toLowerCase()));
      const firstRun = known.size === 0;
      let changed = false;
      for (const c of list) {
        if (!c.path) continue;
        const k = c.path.toLowerCase();
        if (known.has(k)) continue;
        known.add(k); changed = true;
        if (!seed && !firstRun) this.emit('new-app', c);
      }
      if (changed) this.store.set('fwKnown', [...known].slice(-3000));
      this.emit('snapshot', list);
    } catch {}
    this.busy = false;
  }
}

module.exports = { connections, blocked, profiles, block, unblock, enableAll, Monitor };
