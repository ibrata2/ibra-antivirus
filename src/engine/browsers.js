// Finds installed browsers and helps install the IBRA browser extension.
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const P = require('./paths');

const PF = process.env.ProgramFiles || 'C:\\Program Files';
const PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
const LAD = process.env.LOCALAPPDATA || '';

const BROWSERS = [
  { id: 'chrome', name: 'Google Chrome', page: 'chrome://extensions', exe: [path.join(PF, 'Google\\Chrome\\Application\\chrome.exe'), path.join(PF86, 'Google\\Chrome\\Application\\chrome.exe'), path.join(LAD, 'Google\\Chrome\\Application\\chrome.exe')] },
  { id: 'edge', name: 'Microsoft Edge', page: 'edge://extensions', exe: [path.join(PF86, 'Microsoft\\Edge\\Application\\msedge.exe'), path.join(PF, 'Microsoft\\Edge\\Application\\msedge.exe')] },
  { id: 'brave', name: 'Brave', page: 'brave://extensions', exe: [path.join(PF, 'BraveSoftware\\Brave-Browser\\Application\\brave.exe'), path.join(PF86, 'BraveSoftware\\Brave-Browser\\Application\\brave.exe'), path.join(LAD, 'BraveSoftware\\Brave-Browser\\Application\\brave.exe')] },
  { id: 'opera', name: 'Opera', page: 'opera://extensions', exe: [path.join(LAD, 'Programs\\Opera\\opera.exe'), path.join(PF, 'Opera\\opera.exe')] },
  { id: 'operagx', name: 'Opera GX', page: 'opera://extensions', exe: [path.join(LAD, 'Programs\\Opera GX\\opera.exe')] },
  { id: 'vivaldi', name: 'Vivaldi', page: 'vivaldi://extensions', exe: [path.join(LAD, 'Vivaldi\\Application\\vivaldi.exe'), path.join(PF, 'Vivaldi\\Application\\vivaldi.exe')] },
  { id: 'yandex', name: 'Yandex', page: 'browser://extensions', exe: [path.join(LAD, 'Yandex\\YandexBrowser\\Application\\browser.exe')] }
];

function installed() {
  return BROWSERS.map(b => ({ id: b.id, name: b.name, exe: b.exe.find(e => { try { return fs.existsSync(e); } catch { return false; } }) || null }))
    .filter(b => b.exe);
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) copyDir(s, d); else fs.copyFileSync(s, d);
  }
}

/** Copies the extension to a stable folder the browser can load (updated with every app version). */
function prepareExtension() {
  const src = [path.join(P.resRoot(), 'browser-extension'), path.join(__dirname, '..', '..', 'browser-extension')].find(p => fs.existsSync(path.join(p, 'manifest.json')));
  if (!src) throw new Error('extension-missing');
  const dst = P.data('browser-extension');
  copyDir(src, dst);
  return dst;
}

/** Opens the browser on its extensions page. */
function openExtensionsPage(id) {
  const b = BROWSERS.find(x => x.id === id);
  const exe = b && b.exe.find(e => fs.existsSync(e));
  if (!exe) return false;
  spawn(exe, [b.page], { detached: true, stdio: 'ignore' }).unref();
  return true;
}

// process name used by the helper -> browser name reported by the extension heartbeat
const HEARTBEAT_NAME = { chrome: 'Chrome', msedge: 'Edge', brave: 'Brave', opera: 'Opera', vivaldi: 'Vivaldi', browser: 'Yandex' };
const PROCESS_OF = { chrome: 'chrome', edge: 'msedge', brave: 'brave', opera: 'opera', operagx: 'opera', vivaldi: 'vivaldi', yandex: 'browser' };

function helperExe() { return P.vendor('ibra-ext-installer.exe'); }
function canAutoInstall() { return process.platform === 'win32' && P.exists(helperExe()); }

/**
 * Installs the extension automatically, the same way IBRA Download Manager does:
 * opens the extensions page, turns on developer mode, presses "Load unpacked" and picks the folder.
 * onEvent receives every JSON line from the helper ({start}|{step}|{result}|{done}).
 */
function autoInstall({ which = 'all', skip = [], lang = 'ar' }, onEvent = () => {}) {
  return new Promise(resolve => {
    if (!canAutoInstall()) return resolve({ ok: false, error: 'helper-missing' });
    let dir;
    try { dir = prepareExtension(); } catch (e) { return resolve({ ok: false, error: e.message }); }
    const args = ['--install', which, '--dir', dir, '--lang', lang];
    if (skip.length) args.push('--skip', skip.join(','));
    const p = spawn(helperExe(), args, { windowsHide: true });
    const results = [];
    let buf = '';
    let final = null;
    p.stdout.on('data', d => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        let ev; try { ev = JSON.parse(line); } catch { continue; }
        if (ev.result) results.push(ev);
        if (ev.done) final = ev;
        onEvent(ev);
      }
    });
    p.stderr.on('data', () => {});
    p.on('error', e => resolve({ ok: false, error: e.message }));
    p.on('close', () => resolve({ ok: !!(final && final.ok), none: !!(final && final.none), cancelled: !!(final && final.cancelled), results, dir }));
  });
}

module.exports = { installed, prepareExtension, openExtensionsPage, autoInstall, canAutoInstall, HEARTBEAT_NAME, PROCESS_OF };
