// Loads the browser extension's detection code (bg.js + rules.js) so the desktop app judges links
// with exactly the same logic as the browser: scam-word domains, brand look-alikes, cloud reputation, page rules.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const P = require('./paths');

function extDir() {
  return [path.join(P.resRoot(), 'browser-extension'), path.join(__dirname, '..', '..', 'browser-extension')]
    .find(d => fs.existsSync(path.join(d, 'bg.js')));
}

// chrome.* stub: every property is a callable no-op, so bg.js top-level listener registrations are harmless
function stub() {
  const f = function () { return proxy; };
  const proxy = new Proxy(f, { get: (_, k) => (k === 'then' ? undefined : proxy), apply: () => proxy });
  return proxy;
}

let api = null;
function load() {
  if (api) return api;
  const dir = extDir();
  const ctx = {
    chrome: stub(), fetch, AbortController, setTimeout, clearTimeout, URL, URLSearchParams, console, Map, Set,
    navigator: { userAgent: '' }, Promise, JSON, Math, Date, RegExp, String, Number, Array, Object
  };
  ctx.self = ctx; ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(dir, 'rules.js'), 'utf8'), ctx, { filename: 'rules.js' });
  vm.runInContext(fs.readFileSync(path.join(dir, 'bg.js'), 'utf8') +
    '\n;this.__ibra = { heuristic, lureDomain, cloudCheck, hostOf, registrable, isIp, SHARED, PER_USER, OWN, FEEDS, parseFeed };', ctx, { filename: 'bg.js' });
  api = { ...ctx.__ibra, page: ctx.IBRA_PAGE };
  return api;
}

// The same global block lists the extension uses (URLhaus, OpenPhish, Phishing Army), kept on disk, refreshed every 6 h
let lists = null, loading = null;
function listFile() { return P.data('blocklists.json'); }
async function refreshLists(force) {
  const R = load();
  let cached = null;
  try { cached = JSON.parse(fs.readFileSync(listFile(), 'utf8')); } catch {}
  if (cached && !force && Date.now() - cached.at < 6 * 3600 * 1000) { lists = { hosts: new Set(cached.hosts), at: cached.at }; return lists; }
  if (loading) return loading;
  loading = (async () => {
    const hosts = new Set();
    for (const f of R.FEEDS) {
      try {
        const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 30000);
        const r = await fetch(f.url, { signal: ctl.signal }); clearTimeout(tm);
        if (r.ok) for (const h of R.parseFeed(await r.text(), f.type)) hosts.add(h);
      } catch {}
    }
    if (hosts.size) {
      lists = { hosts, at: Date.now() };
      try { fs.writeFileSync(listFile(), JSON.stringify({ at: lists.at, hosts: [...hosts] })); } catch {}
    } else if (cached) lists = { hosts: new Set(cached.hosts), at: cached.at };
    loading = null;
    return lists;
  })();
  return loading;
}
/** true when the host or one of its parent domains is on the block lists */
async function listed(host) {
  // first use: wait for the lists up to 8 s, never block a check longer than that
  if (!lists) { try { await Promise.race([refreshLists(false), new Promise(r => setTimeout(r, 8000))]); } catch {} }
  if (!lists || !host) return false;
  const parts = host.toLowerCase().replace(/^www\./, '').split('.');
  for (let i = 0; i < parts.length - 1; i++) if (lists.hosts.has(parts.slice(i).join('.'))) return true;
  return false;
}

module.exports = { load, refreshLists, listed };
