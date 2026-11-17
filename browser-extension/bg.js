// IBRA ANTIVIRUS - Browser Protection (background)
// برمجة وتطوير ابراهيم الخزرجي - IBRAPROGRAM
const APP = 'http://127.0.0.1:47219';
const FEEDS = [
  { id: 'urlhaus', type: 'hosts', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', reason: 'malware' },
  { id: 'urlhaus-online', type: 'urls', url: 'https://urlhaus.abuse.ch/downloads/text_online/', reason: 'malware' },
  { id: 'openphish', type: 'urls', url: 'https://openphish.com/feed.txt', reason: 'phishing' },
  { id: 'phishing-army', type: 'domains', url: 'https://phishing.army/download/phishing_army_blocklist.txt', reason: 'phishing' }
];
const RULE_BASE_REDIRECT = 1000;   // ids 1000..2999 main-frame redirects
const RULE_BASE_BLOCK = 3000;      // ids 3000..4999 sub-resource blocks
const CHUNK = 1000;
// Big shared platforms: never blocked by domain (Chrome Safe Browsing still covers single URLs there)
const SHARED = new Set(['google.com', 'google.iq', 'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'youtu.be', 'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'microsoft.com', 'live.com', 'office.com', 'sharepoint.com', '1drv.ms', 'windows.net', 'msn.com', 'bing.com', 'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'dropbox.com', 'dropboxusercontent.com', 'mediafire.com', 'mega.nz', 'discord.com', 'discordapp.com', 'discordapp.net', 'telegram.org', 't.me', 'amazonaws.com', 'amazon.com', 'cloudfront.net', 'azureedge.net', 'akamaized.net', 'akamaihd.net', 'cloudflare.com', 'jsdelivr.net', 'unpkg.com', 'pastebin.com', 'bit.ly', 'tinyurl.com', 'apple.com', 'icloud.com', 'twitter.com', 'x.com', 'tiktok.com', 'yandex.ru', 'mail.ru', 'archive.org', 'sourceforge.net', 'wikipedia.org', 'anthropic.com', 'claude.ai', 'openai.com', 'netflix.com', 'zoom.us']);
// Platforms where every subdomain belongs to a different person (subdomains may be blocked, the platform itself never)
const PER_USER = /(^|\.)(netlify\.app|vercel\.app|pages\.dev|web\.app|firebaseapp\.com|weebly\.com|wixsite\.com|000webhostapp\.com|blogspot\.com|glitch\.me|repl\.co|herokuapp\.com|ngrok\.io|ngrok-free\.app|duckdns\.org|webflow\.io|godaddysites\.com|square\.site|carrd\.co|framer\.app|github\.io)$/;
const OWN = ['ibraprogram.netlify.app'];

// Official domains of brands that phishers copy (international + Iraqi services)
const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'], facebook: ['facebook.com', 'fb.com', 'fb.me', 'facebook.net', 'fbcdn.net'],
  instagram: ['instagram.com', 'cdninstagram.com'], whatsapp: ['whatsapp.com', 'whatsapp.net', 'wa.me'],
  telegram: ['telegram.org', 't.me', 'telegram.me'], apple: ['apple.com', 'icloud.com'], icloud: ['icloud.com', 'apple.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'windows.net', 'azure.com'],
  outlook: ['outlook.com', 'live.com', 'office.com', 'microsoft.com'], office365: ['office.com', 'microsoft.com', 'office365.com'],
  google: ['google.com', 'google.iq', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'goo.gl', 'g.co'],
  gmail: ['google.com', 'gmail.com'], youtube: ['youtube.com', 'youtu.be', 'google.com'], tiktok: ['tiktok.com', 'tiktokcdn.com'],
  netflix: ['netflix.com'], amazon: ['amazon.com', 'amazon.ae', 'amazon.sa', 'aws.amazon.com', 'amazonaws.com'],
  binance: ['binance.com'], coinbase: ['coinbase.com'], metamask: ['metamask.io'], trustwallet: ['trustwallet.com'],
  steam: ['steampowered.com', 'steamcommunity.com'], steamcommunity: ['steamcommunity.com'], epicgames: ['epicgames.com'],
  pubg: ['pubg.com', 'pubgmobile.com', 'tencentgames.com'], freefire: ['ff.garena.com', 'garena.com'],
  snapchat: ['snapchat.com'], twitter: ['twitter.com', 'x.com'], dhl: ['dhl.com'], aramex: ['aramex.com'],
  zaincash: ['zaincash.iq'], zain: ['iq.zain.com', 'zain.com', 'zain.iq'], asiacell: ['asiacell.com'], korek: ['korektel.com'],
  qicard: ['qi.iq', 'qicard.iq'], fastpay: ['fast-pay.iq', 'fastpay.iq'], rafidain: ['rafidain-bank.gov.iq', 'rb.gov.iq'],
  rasheed: ['rasheedbank.gov.iq'], ur: ['ur.gov.iq'], visa: ['visa.com'], mastercard: ['mastercard.com']
};
const LURE = /(login|log-in|signin|sign-in|verify|verification|secure|security|account|update|confirm|support|recovery|unlock|wallet|bonus|gift|free|prize|reward|claim|airdrop|password|auth|billing|payment|suspend|limited|help-?center|appeal|copyright|violation|trade|offer|giveaway|nitro|premium|prize|winner|lucky)/i;
const SECOND_LEVEL = new Set(['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'mil']);

const T = {
  ar: { blockedTitle: 'IBRA ANTIVIRUS أوقف موقع خطر', dlTitle: 'IBRA ANTIVIRUS أوقف ملف خطر', dlBody: (n, f) => `${n}\n${f}` },
  en: { blockedTitle: 'IBRA ANTIVIRUS blocked a dangerous site', dlTitle: 'IBRA ANTIVIRUS stopped a dangerous file', dlBody: (n, f) => `${n}\n${f}` }
};

// ------------------------------------------------------------------ helpers
const get = keys => chrome.storage.local.get(keys);
const set = obj => chrome.storage.local.set(obj);
async function settings() {
  const s = await chrome.storage.sync.get({ enabled: true, frame: true, phishingHeuristics: true, scanDownloads: true, lang: null });
  if (!s.lang) s.lang = (chrome.i18n.getUILanguage() || 'ar').startsWith('ar') ? 'ar' : 'en';
  return s;
}
function hostOf(u) { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, ''); } catch { return ''; } }
function registrable(host) {
  const p = host.split('.');
  if (p.length <= 2) return host;
  if (p[p.length - 1].length === 2 && SECOND_LEVEL.has(p[p.length - 2])) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}
function isIp(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':'); }
function isOfficial(host, list) { return list.some(d => host === d || host.endsWith('.' + d)); }

// Confusable characters used in fake domains (cyrillic/greek look-alikes, digit swaps)
function skeleton(s) {
  return s.replace(/[0]/g, 'o').replace(/[1|!]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/rn/g, 'm').replace(/vv/g, 'w');
}

/** Heuristic phishing check. Returns null or { level:'high'|'medium', reason, brand } */
function heuristic(url) {
  let u; try { u = new URL(url); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  if (!host || host === 'localhost' || /^127\.|^192\.168\.|^10\./.test(host)) return null;
  const reg = registrable(host);
  if (OWN.some(o => host === o)) return null;
  if (SHARED.has(reg) && !PER_USER.test(host)) return null;
  const labels = host === reg ? '' : host.slice(0, -(reg.length + 1));
  const sk = skeleton(host);

  // 1. punycode domain imitating a brand
  if (/xn--/.test(host)) {
    for (const b of Object.keys(BRANDS)) if (sk.includes(b) || host.includes(b.slice(0, 4))) return { level: 'high', reason: 'homograph', brand: b };
    return { level: 'medium', reason: 'punycode' };
  }
  // 2. brand name on a domain that is not the brand's
  for (const [b, official] of Object.entries(BRANDS)) {
    if (b.length < 4) continue;
    const edge = new RegExp('(^|[.-])' + b);
    const inHost = edge.test(host) || edge.test(sk) || ((host.includes(b) || sk.includes(b)) && LURE.test(host));
    if (!inHost || isOfficial(host, official)) continue;
    const lure = LURE.test(host) || LURE.test(u.pathname);
    if (!lure && !new RegExp(b + '([.-]|\\d|$)').test(host)) continue;   // e.g. "applebees.com" is not Apple
    const regHasBrand = reg.includes(b) || skeleton(reg).includes(b);
    if (lure || !regHasBrand || labels.includes(b)) return { level: 'high', reason: 'brand', brand: b };
    return { level: 'medium', reason: 'brand', brand: b };
  }
  // 3. raw IP address asking for a login
  if (isIp(host) && LURE.test(u.pathname + u.search)) return { level: 'high', reason: 'ip-login' };
  // 4. credentials hidden in the URL: https://facebook.com@evil.com
  if (u.username || /@/.test(url.split('?')[0].replace(/^https?:\/\//, '').split('/')[0])) return { level: 'high', reason: 'userinfo' };
  // 5. very long subdomain chains used to hide the real domain
  if (host.split('.').length >= 6 && LURE.test(host)) return { level: 'medium', reason: 'deep-subdomain' };
  return null;
}

// ------------------------------------------------------------------ block lists
function parseFeed(text, type) {
  const out = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line[0] === '#' || line[0] === '!') continue;
    let h = '';
    if (type === 'hosts') { const p = line.split(/\s+/); h = p[1] || p[0]; }
    else if (type === 'urls') h = hostOf(line.startsWith('http') ? line : 'http://' + line);
    else h = line.split(/\s+/)[0];
    h = h.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
    if (!h || h === 'localhost' || h.length > 253 || !/^[a-z0-9.-]+$/.test(h) || isIp(h)) continue;
    if (OWN.includes(h) || SHARED.has(h) || SHARED.has(registrable(h))) continue;
    if (PER_USER.test('.' + h) && h.split('.').length <= 2) continue;
    out.add(h);
  }
  return out;
}

async function updateLists(force) {
  const { listsUpdated = 0 } = await get('listsUpdated');
  if (!force && Date.now() - listsUpdated < 6 * 3600 * 1000) return { skipped: true };
  const reasons = {};
  const all = new Set();
  const sources = {};
  for (const f of FEEDS) {
    try {
      const r = await fetch(f.url, { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      const set1 = parseFeed(await r.text(), f.type);
      sources[f.id] = set1.size;
      for (const h of set1) { all.add(h); if (!reasons[h]) reasons[h] = f.reason; }
    } catch (e) { sources[f.id] = 'error'; }
  }
  if (!all.size) return { ok: false };
  const domains = [...all];
  const malware = domains.filter(d => reasons[d] === 'malware');
  const phishing = domains.filter(d => reasons[d] !== 'malware');
  await set({ listsUpdated: Date.now(), listCount: domains.length, listSources: sources });
  await applyRules(malware, phishing);
  return { ok: true, count: domains.length };
}

async function applyRules(malware, phishing) {
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = old.filter(r => r.id >= RULE_BASE_REDIRECT && r.id < 5000).map(r => r.id);
  const addRules = [];
  const warn = chrome.runtime.getURL('warning.html');
  let i = 0;
  const pushChunks = (list, reason) => {
    for (let k = 0; k < list.length && i < 2000; k += CHUNK, i++) {
      const chunk = list.slice(k, k + CHUNK);
      addRules.push({
        id: RULE_BASE_REDIRECT + i, priority: 1,
        action: { type: 'redirect', redirect: { regexSubstitution: `${warn}?r=${reason}#\\0` } },
        condition: { regexFilter: '^https?://.*', requestDomains: chunk, resourceTypes: ['main_frame'] }
      });
      addRules.push({
        id: RULE_BASE_BLOCK + i, priority: 1, action: { type: 'block' },
        condition: { requestDomains: chunk, resourceTypes: ['sub_frame', 'script', 'xmlhttprequest', 'object', 'media', 'websocket', 'other'] }
      });
    }
  };
  pushChunks(malware, 'malware');
  pushChunks(phishing, 'phishing');
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [] });
  // add in batches to stay inside per-call limits
  for (let k = 0; k < addRules.length; k += 200) {
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: addRules.slice(k, k + 200) });
  }
}

async function setEnabled(on) {
  // a top-priority allow-all session rule switches the block lists off
  const rule = { id: 1, priority: 1000, action: { type: 'allowAllRequests' }, condition: { urlFilter: '|http', resourceTypes: ['main_frame', 'sub_frame'] } };
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [1], addRules: on ? [] : [rule] });
  chrome.action.setIcon({ path: { 16: `icons/${on ? 'green' : 'orange'}-16.png`, 32: `icons/${on ? 'green' : 'orange'}-32.png` } });
}

// "Enter anyway": allow this site for the rest of the browser session
let nextAllowId = 10;
async function allowHost(host) {
  const s = await chrome.storage.session.get({ allowed: [] });
  if (!s.allowed.includes(host)) s.allowed.push(host);
  await chrome.storage.session.set({ allowed: s.allowed });
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [{ id: 100 + (nextAllowId++), priority: 500, action: { type: 'allow' }, condition: { requestDomains: [host], resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest', 'object', 'media', 'websocket', 'other', 'image', 'stylesheet', 'font'] } }]
  });
}
async function isAllowed(host) { const s = await chrome.storage.session.get({ allowed: [] }); return s.allowed.some(a => host === a || host.endsWith('.' + a)); }

// ------------------------------------------------------------------ stats + app bridge
async function bump(kind) {
  const day = new Date().toISOString().slice(0, 10);
  const s = await get({ stats: { day, today: 0, total: 0, downloads: 0 } });
  const st = s.stats.day === day ? s.stats : { day, today: 0, total: s.stats.total || 0, downloads: s.stats.downloads || 0 };
  if (kind === 'site') { st.today++; st.total++; } else st.downloads++;
  await set({ stats: st });
}
async function toApp(path, body) {
  try {
    const r = await fetch(APP + path, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json', 'X-IBRA': '1' }, body: body ? JSON.stringify(body) : undefined });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}
async function heartbeat() {
  const s = await get({ stats: {}, listCount: 0 });
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : navigator.brave ? 'Brave' : /Chrome\//.test(ua) ? 'Chrome' : 'Browser';
  const r = await toApp('/heartbeat', { browser, version: chrome.runtime.getManifest().version, stats: s.stats, listCount: s.listCount });
  await chrome.storage.session.set({ appConnected: !!r, appLang: r && r.lang });
  if (r && r.lang) { const cur = await chrome.storage.sync.get({ lang: null }); if (!cur.lang) await chrome.storage.sync.set({ lang: r.lang }); }
}

// ------------------------------------------------------------------ navigation guard (heuristics)
chrome.webNavigation.onBeforeNavigate.addListener(async d => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const s = await settings();
  if (!s.enabled || !s.phishingHeuristics) return;
  const h = heuristic(d.url);
  if (!h || h.level !== 'high') return;
  if (await isAllowed(hostOf(d.url))) return;
  const warn = chrome.runtime.getURL('warning.html') + `?r=${h.reason === 'brand' || h.reason === 'homograph' ? 'phishing' : 'suspicious'}&b=${encodeURIComponent(h.brand || '')}#` + d.url;
  chrome.tabs.update(d.tabId, { url: warn });
});

// ------------------------------------------------------------------ downloads → scanned by IBRA ANTIVIRUS app
chrome.downloads.onChanged.addListener(async delta => {
  if (!delta.state || delta.state.current !== 'complete') return;
  const s = await settings();
  if (!s.enabled || !s.scanDownloads) return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !item.filename) return;
  const r = await toApp('/scan', { path: item.filename, url: item.finalUrl || item.url });
  if (r && r.threat) {
    await bump('download');
    const L = T[s.lang] || T.ar;
    chrome.notifications.create({ type: 'basic', iconUrl: 'icons/red-128.png', title: L.dlTitle, message: L.dlBody(r.threat.name, item.filename.split(/[\\/]/).pop()), priority: 2 });
  }
});

// ------------------------------------------------------------------ messages from pages
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg.type === 'verdict') {
      const s = await settings();
      const url = msg.url || (sender.tab && sender.tab.url) || '';
      const h = s.phishingHeuristics ? heuristic(url) : null;
      const https = url.startsWith('https:');
      let level = 'safe';
      if (!s.enabled) level = 'off';
      else if (h || !https) level = 'warn';
      reply({ level, reason: h ? h.reason : https ? null : 'http', brand: h && h.brand, frame: s.frame && s.enabled, lang: s.lang });
    } else if (msg.type === 'blocked') {
      await bump('site');
      const s = await settings();
      toApp('/event', { type: 'blocked', url: msg.url, reason: msg.reason });
      reply({ lang: s.lang });
    } else if (msg.type === 'allow') {
      await allowHost(hostOf(msg.url));
      toApp('/event', { type: 'allowed', url: msg.url });
      reply({ ok: true });
    } else if (msg.type === 'status') {
      const s = await settings();
      const l = await get({ listsUpdated: 0, listCount: 0, stats: { today: 0, total: 0, downloads: 0 } });
      const ss = await chrome.storage.session.get({ appConnected: false });
      reply({ ...s, ...l, appConnected: ss.appConnected });
    } else if (msg.type === 'set') {
      await chrome.storage.sync.set({ [msg.key]: msg.value });
      if (msg.key === 'enabled') await setEnabled(msg.value);
      reply(await settings());
    } else if (msg.type === 'update-lists') {
      reply(await updateLists(true));
    } else if (msg.type === 'safe-exit') {
      if (sender.tab) chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab/' });
      reply({ ok: true });
    }
  })();
  return true;
});

// ------------------------------------------------------------------ lifecycle
async function boot() {
  const s = await settings();
  await setEnabled(s.enabled);
  chrome.alarms.create('lists', { periodInMinutes: 60 });
  chrome.alarms.create('heartbeat', { periodInMinutes: 1 });
  heartbeat();
  updateLists(false);
}
chrome.runtime.onInstalled.addListener(boot);
chrome.runtime.onStartup.addListener(boot);
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'lists') updateLists(false); if (a.name === 'heartbeat') heartbeat(); });
