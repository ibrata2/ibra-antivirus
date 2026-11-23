// IBRA heuristic engine: fast checks that need no external binaries.
// Returns { name, severity: 'high' | 'medium' } or null.
const fs = require('fs');
const path = require('path');

const EXEC_EXT = new Set(['.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.msi', '.dll', '.cpl', '.jar', '.lnk']);
const SCRIPT_EXT = new Set(['.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.psm1', '.reg', '.inf']);
const DOC_LIKE = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|mp[34]|avi|mkv|txt|rtf|zip|rar)$/i;

// Built from pieces so our own files are never flagged by other antivirus products
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR', '-STANDARD-ANTI', 'VIRUS-TEST-FILE!$H+H*'].join('');

// [regex, name, weight]
const SCRIPT_RULES = [
  [/vssadmin(\.exe)?\s+delete\s+shadows/i, 'Ransom.ShadowDelete', 10],
  [/wmic(\.exe)?\s+shadowcopy\s+delete/i, 'Ransom.ShadowDelete', 10],
  [/bcdedit(\.exe)?.{0,40}recoveryenabled\s+no/i, 'Ransom.DisableRecovery', 10],
  [/wbadmin(\.exe)?\s+delete\s+catalog/i, 'Ransom.BackupDelete', 10],
  [/cipher(\.exe)?\s+\/w:/i, 'Wiper.CipherWipe', 6],
  [/Set-MpPreference\s+-Disable(RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)\s+\$?true/i, 'Trojan.DefenderKiller', 10],
  [/Add-MpPreference\s+-ExclusionPath/i, 'Trojan.DefenderExclusion', 6],
  [/(IEX|Invoke-Expression)\s*\(?\s*\(?\s*New-Object\s+(System\.)?Net\.WebClient\)?\.Download(String|Data)/i, 'Downloader.PowerShell', 10],
  [/\.DownloadString\(\s*['"]https?:/i, 'Downloader.PowerShell', 5],
  [/FromBase64String\(.{0,200}(IEX|Invoke-Expression|\[Reflection\.Assembly\]::Load)/is, 'Obfuscated.PowerShell', 9],
  [/powershell(\.exe)?\s+.{0,40}-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{60,}/i, 'Obfuscated.EncodedCommand', 8],
  [/-(w|windowstyle)\s+hidden.{0,80}(http|iex|downloadstring)/i, 'Downloader.HiddenPowerShell', 7],
  [/certutil(\.exe)?\s+.{0,20}-urlcache.{0,20}-f\s+https?:/i, 'Downloader.Certutil', 9],
  [/bitsadmin(\.exe)?\s+\/transfer.{0,80}https?:/i, 'Downloader.Bitsadmin', 6],
  [/mshta(\.exe)?\s+(https?:|vbscript:|javascript:)/i, 'Downloader.Mshta', 9],
  [/regsvr32(\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:https?:/i, 'Downloader.Squiblydoo', 10],
  [/CreateObject\(\s*["']WScript\.Shell["']\s*\).{0,300}\.Run.{0,200}(http|powershell|cmd)/is, 'Dropper.WScript', 6],
  [/CreateObject\(\s*["']MSXML2\.(Server)?XMLHTTP["']\).{0,500}(ADODB\.Stream|SaveToFile)/is, 'Downloader.VBS', 8],
  [/schtasks(\.exe)?\s+\/create.{0,200}(powershell|mshta|wscript|\\appdata\\|\\temp\\)/i, 'Persistence.ScheduledTask', 6],
  [/reg(\.exe)?\s+add\s+["']?HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i, 'Persistence.RunKey', 4],
  [/attrib(\.exe)?\s+\+s\s+\+h.{0,80}(%~d0|[a-z]:\\\*)/i, 'Worm.HideFiles', 6],
  [/your files (have been|are) encrypted|all your files .{0,30}encrypted|decrypt.{0,40}(bitcoin|btc|monero)/i, 'Ransom.Note', 7],
  [/net\s+user\s+\S+\s+\S+\s+\/add.{0,80}net\s+localgroup\s+administrators/is, 'HackTool.AddAdmin', 7]
];

const LNK_BAD = /(cmd(\.exe)?\s*\/c|powershell|wscript|cscript|mshta|rundll32|regsvr32|\.vbs|\.js\b|%~d0)/i;

function readHead(file, max) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(max);
    const n = fs.readSync(fd, buf, 0, max, 0);
    return buf.subarray(0, n);
  } catch { return null; } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch {} }
}

function asText(buf) {
  // handle UTF-16LE text (common in .lnk and some scripts)
  let t = buf.toString('latin1');
  if (buf.length > 4 && (buf[1] === 0 || (buf[0] === 0xff && buf[1] === 0xfe))) {
    t += '\n' + buf.toString('utf16le');
  }
  return t;
}

/**
 * @param {string} file full path
 * @param {object} ctx { removableRoot: boolean }
 */
function check(file, ctx = {}) {
  const base = path.basename(file);
  const lower = base.toLowerCase();
  const ext = path.extname(lower);

  // Right-to-left override trick: "photo\u202Egpj.exe" looks like "photoexe.jpg"
  if (/[\u202E\u202D\u2066-\u2069]/.test(base)) return { name: 'Trick.RTLO.FileName', severity: 'high' };

  // Double extension: invoice.pdf.exe / photo.jpg.scr
  if (EXEC_EXT.has(ext) && ext !== '.lnk' && ext !== '.dll') {
    const stem = lower.slice(0, -ext.length);
    if (DOC_LIKE.test(stem)) return { name: 'Trick.DoubleExtension', severity: 'high' };
    if (/\s{8,}\S*$/.test(stem)) return { name: 'Trick.HiddenExtension', severity: 'high' };
  }

  // USB worm: autorun.inf at drive root
  if (lower === 'autorun.inf' && ctx.removableRoot) {
    const head = readHead(file, 8192);
    if (head && /(open|shellexecute|shell\\[^\n]*\\command)\s*=/i.test(head.toString('latin1'))) {
      return { name: 'Worm.Autorun.INF', severity: 'high' };
    }
  }

  // Shortcut virus: .lnk running a script/cmd (very common on USB sticks)
  if (ext === '.lnk') {
    const head = readHead(file, 16384);
    if (head) {
      const t = asText(head);
      if (LNK_BAD.test(t)) return { name: ctx.removableRoot ? 'Worm.ShortcutVirus' : 'Suspicious.Shortcut', severity: ctx.removableRoot ? 'high' : 'medium' };
    }
    return null;
  }

  const isScript = SCRIPT_EXT.has(ext);
  const head = readHead(file, isScript ? 2 * 1024 * 1024 : 512);
  if (!head) return null;

  // EICAR test file (must start at offset 0 per spec)
  if (head.length >= 68 && head.subarray(0, 68).toString('latin1') === EICAR) return { name: 'EICAR-Test-File', severity: 'high' };

  // Executable disguised as a document/image (PE header with doc extension)
  if (head[0] === 0x4d && head[1] === 0x5a && DOC_LIKE.test(lower) && !/\.(zip|rar)$/.test(lower)) {
    return { name: 'Trick.DisguisedExecutable', severity: 'high' };
  }

  if (isScript) {
    const t = asText(head);
    let score = 0; let top = null; let topW = 0;
    for (const [re, name, w] of SCRIPT_RULES) {
      if (re.test(t)) { score += w; if (w > topW) { topW = w; top = name; } }
    }
    if (score >= 9) return { name: 'Script.' + top, severity: 'high' };
    if (score >= 5) return { name: 'Suspicious.' + top, severity: 'medium' };
  }
  return null;
}

/**
 * Infostealers are often "inflated" to hundreds of MB with zero bytes so antivirus engines skip them (size limits)
 * and upload sites refuse them. Reads only the last 4 MB.
 */
function inflated(file, size) {
  if (!/\.(exe|scr|dll|msi|com)$/i.test(file) || size < 100 * 1048576) return null;
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(2); fs.readSync(fd, head, 0, 2, 0);
    const isPE = head[0] === 0x4d && head[1] === 0x5a;
    const n = 4 * 1048576; const buf = Buffer.alloc(n);
    const got = fs.readSync(fd, buf, 0, n, size - n);
    let zeros = 0, same = 0; const b0 = buf[0];
    for (let i = 0; i < got; i++) { if (buf[i] === 0) zeros++; if (buf[i] === b0) same++; }
    if (isPE && (zeros / got > 0.985 || same / got > 0.985)) return { name: 'Trick.InflatedExecutable', severity: 'high' };
  } catch {} finally { if (fd !== undefined) try { fs.closeSync(fd); } catch {} }
  return null;
}

module.exports = { check, inflated, EICAR, EXEC_EXT, SCRIPT_EXT };
