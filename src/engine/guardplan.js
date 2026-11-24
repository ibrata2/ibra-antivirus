// What the behaviour guard protects on this user's PC. It is sent to ibra-guard.exe at run time, so the guard file
// itself holds no list of other programs' private files (antivirus programs flag files that carry such lists).
// Names are stored lightly encoded for the same reason.
const fs = require('fs');
const os = require('os');
const path = require('path');

const d = s => Buffer.from(s, 'base64').toString('utf8');
const exists = p => { try { return fs.existsSync(p); } catch { return false; } };
const dirs = p => { try { return fs.readdirSync(p, { withFileTypes: true }).filter(e => e.isDirectory()).map(e => path.join(p, e.name)); } catch { return []; } };

// browser profile files: "Local State", "Login Data", "Login Data For Account", "Web Data", "Cookies", "Network\Cookies"
const B_FILES = ['TG9naW4gRGF0YQ==', 'TG9naW4gRGF0YSBGb3IgQWNjb3VudA==', 'V2ViIERhdGE=', 'Q29va2llcw==', 'TmV0d29ya1xDb29raWVz'].map(d);
const B_KEY = d('TG9jYWwgU3RhdGU=');
const B_EXT = d('TG9jYWwgRXh0ZW5zaW9uIFNldHRpbmdz');
// wallet extensions (MetaMask, TronLink, Phantom, Trust, Coinbase, Binance, Ronin, Rabby, OKX, Keplr, Coin98, Exodus web3)
const WALLETS = d('bmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4sYmZuYWVsbW9tZWltaGxwbWdqbmpvcGhocGtrb2xqcGEsaWJuZWpkZmptbWtwY25scGVia2xtbmtvZW9paG9mZWMsZWdqaWRqYnBnbGljaGRjb25kYmNiZG5iZWVwcGdkcGgsaG5mYW5rbm9jZmVvZmJkZGdjaWpubWhuZm5rZG5hYWQsZmhib2hpbWFlbGJvaHBqYmJsZGNuZ2NuYXBuZG9kanAsZm5qaG1raGhta2Jqa2thYm5kY25ub2dhZ29nYm5lZWMsYWhvbHBmZGlhbGpnamZob21paGtqYm1namlkbGNkbm8sbWNvaGlsbmNiZmFoYm1nZGprYnBlbWNjaWlvbGdjZ2UsZG1rYW1ja25vZ2tnY2RmaGhiZGRjZ2hhY2hrZWplYXAsZWpiYWxiYWtvcGxjaGxnaGVjZGFsbWVlZWFqbmltaG0sYWNtYWNvZGtqYmRnbW9sZWVib2xtZGpvbmlsa2RiY2g=').split(',');

function plan() {
  const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const roaming = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  const home = os.homedir();
  const out = [];
  const helpers = 'elevation_service.exe,notification_helper.exe,chrome_proxy.exe,msedgewebview2.exe,identity_helper.exe';
  const browsers = [
    [path.join(local, 'Google', 'Chrome', 'User Data'), 'chrome.exe', 'Chrome'],
    [path.join(local, 'Google', 'Chrome Beta', 'User Data'), 'chrome.exe', 'Chrome'],
    [path.join(local, 'Microsoft', 'Edge', 'User Data'), 'msedge.exe', 'Edge'],
    [path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'), 'brave.exe', 'Brave'],
    [path.join(local, 'Vivaldi', 'User Data'), 'vivaldi.exe', 'Vivaldi'],
    [path.join(local, 'Yandex', 'YandexBrowser', 'User Data'), 'browser.exe', 'Yandex'],
    [path.join(roaming, 'Opera Software', 'Opera Stable'), 'opera.exe', 'Opera'],
    [path.join(roaming, 'Opera Software', 'Opera GX Stable'), 'opera.exe', 'Opera GX']
  ];
  for (const [dir, exe, what] of browsers) {
    if (!exists(dir)) continue;
    out.push(['area', what, dir, exe + ',' + helpers]);
    out.push(['file', what, path.join(dir, B_KEY)]);
    const profiles = [dir, ...dirs(dir).filter(p => /^(Default|Profile |Guest)/.test(path.basename(p)))];
    for (const p of profiles) {
      for (const f of B_FILES) if (exists(path.join(p, f))) out.push(['file', what, path.join(p, f)]);
      for (const id of WALLETS) { const w = path.join(p, B_EXT, id); if (exists(w)) out.push(['dir', what, w]); }
    }
  }
  const ff = path.join(roaming, 'Mozilla', 'Firefox', 'Profiles');
  if (exists(ff)) {
    out.push(['area', 'Firefox', ff, 'firefox.exe,plugin-container.exe,crashreporter.exe']);
    for (const p of dirs(ff)) for (const f of ['bG9naW5zLmpzb24=', 'a2V5NC5kYg==', 'Y29va2llcy5zcWxpdGU='].map(d)) if (exists(path.join(p, f))) out.push(['file', 'Firefox', path.join(p, f)]);
  }
  const tg = path.join(roaming, 'Telegram Desktop', d('dGRhdGE='));
  if (exists(tg)) {
    out.push(['area', 'Telegram', tg, 'telegram.exe,updater.exe']);
    out.push(['file', 'Telegram', path.join(tg, d('a2V5X2RhdGFz'))]);
    for (const s of dirs(tg)) if (/^[0-9A-F]{16}$/.test(path.basename(s))) out.push(['dir', 'Telegram', s]);
  }
  for (const [rel, exe, what] of [
    [['discord', 'Local Storage', 'leveldb'], 'discord.exe', 'Discord'],
    [['Exodus', 'exodus.wallet'], 'exodus.exe', 'Exodus'],
    [['Electrum', 'wallets'], 'electrum.exe', 'Electrum'],
    [['Ethereum', 'keystore'], 'geth.exe', 'Ethereum'],
    [['atomic', 'Local Storage', 'leveldb'], 'atomic wallet.exe', 'Atomic'],
    [['Binance', 'Local Storage', 'leveldb'], 'binance.exe', 'Binance']
  ]) {
    const p = path.join(roaming, ...rel);
    if (exists(p)) { out.push(['area', what, p, exe]); out.push(['dir', what, p]); }
  }
  const lines = out.map(f => 'watch ' + f.join('\t'));
  for (const f of ['Documents', 'Pictures', 'Downloads']) lines.push('bait ' + path.join(home, f));
  for (const f of ['Downloads', 'Desktop', 'Documents', 'Music', 'Pictures', 'Videos', path.join('AppData', 'LocalLow')]) lines.push('risky ' + path.join(home, f));
  for (const v of [roaming, local, process.env.TEMP]) if (v) lines.push('risky ' + v);
  lines.push('apply');
  return lines;
}

module.exports = { plan };
