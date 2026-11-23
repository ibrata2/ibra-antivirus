// IBRA ANTIVIRUS — link checker for links received on WhatsApp / Instagram / Telegram / stories.
// Follows redirects and short links, checks every address (scam-word domains, look-alikes, cloud reputation),
// reads the final page (scam walls, fake "I'm not a robot" traps, hidden commands) and spots direct program downloads.
const urlrep = require('./urlrep');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const RISKY_FILE = /\.(exe|scr|msi|msix|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|hta|lnk|ps1|jar|zip|rar|7z|iso|img|vhd|vhdx|apk|appx|reg|cpl|dll)$/i;
const SHORTENERS = /(^|\.)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|buff\.ly|shorturl\.at|rb\.gy|t\.ly|s\.id|tiny\.cc|bl\.ink|lnkd\.in|linktr\.ee|shorte\.st|adf\.ly|ouo\.io|exe\.io|bitly\.com|qrco\.de|v\.gd|clck\.ru|surl\.li|u\.to|urlz\.fr|dub\.sh|l\.ead\.me|beacons\.ai|taplink\.cc)$/i;

function extractUrl(text) {
  if (!text) return null;
  const t = String(text).trim();
  let m = t.match(/https?:\/\/[^\s"'<>،]+/i);
  if (m) return m[0].replace(/[).,!؟?]+$/, '');
  m = t.match(/\b(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/[^\s"'<>]*)?/i);
  if (m && !/^\d+(\.\d+)+$/.test(m[0]) && t.length < 300) return 'https://' + m[0].replace(/[).,!؟?]+$/, '');
  return null;
}

// Wrapper links used by apps: Instagram/Facebook/Messenger/Google/YouTube put the real address in a parameter
function unwrap(u) {
  try {
    const x = new URL(u);
    const h = x.hostname.replace(/^www\./, '');
    const get = k => x.searchParams.get(k);
    if (/^(l|lm)\.(instagram|facebook)\.com$/.test(h) && get('u')) return get('u');
    if (h === 'facebook.com' && x.pathname === '/l.php' && get('u')) return get('u');
    if (/^google\.[a-z.]+$/.test(h) && x.pathname === '/url' && (get('q') || get('url'))) return get('q') || get('url');
    if (h === 'youtube.com' && x.pathname === '/redirect' && get('q')) return get('q');
    if (h === 'l.messenger.com' && get('u')) return get('u');
    if (/^(away\.vk\.com|vk\.com)$/.test(h) && x.pathname === '/away.php' && get('to')) return get('to');
  } catch {}
  return u;
}

async function fetchHop(url, readBody) {
  const ctl = new AbortController();
  const tm = setTimeout(() => ctl.abort(), 12000);
  try {
    const r = await fetch(url, { redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': UA, 'accept-language': 'ar,en;q=0.8', accept: 'text/html,application/xhtml+xml,*/*;q=0.8' } });
    const ctype = (r.headers.get('content-type') || '').toLowerCase();
    const cdisp = r.headers.get('content-disposition') || '';
    const location = r.headers.get('location');
    let body = '';
    if (readBody && r.status < 300 && /html|text\/plain|javascript/.test(ctype) && !/attachment/i.test(cdisp)) {
      const reader = r.body.getReader(); let size = 0; const dec = new TextDecoder();
      while (size < 1500000) { const { done, value } = await reader.read(); if (done) break; size += value.length; body += dec.decode(value, { stream: true }); }
      try { reader.cancel(); } catch {}
    } else { try { r.body && r.body.cancel(); } catch {} }
    return { status: r.status, ctype, cdisp, location, body };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : (e.cause && e.cause.code) || e.message };
  } finally { clearTimeout(tm); }
}

function htmlToText(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ').trim();
}

// commands hidden in the page's scripts (fake captcha pages keep the PowerShell/mshta command in a JS string)
function hiddenCommands(html, page) {
  const out = [];
  const re = /(powershell|pwsh|mshta|cmd(\.exe)?\s*\/[ck]|curl(\.exe)?\s|bitsadmin|certutil|rundll32|regsvr32|msiexec|conhost|finger(\.exe)?\s)(?:\\["']|[^"'`<>])*/gi;
  let m;
  while ((m = re.exec(html)) && out.length < 5) {
    const cmd = m[0].replace(/\\(["'\\/])/g, '$1');
    if (page.command(cmd) === 'block') out.push(cmd.slice(0, 220));
  }
  // base64 / char-code encoded payloads that decode to such a command
  const b64 = html.match(/["'`]([A-Za-z0-9+/]{60,}={0,2})["'`]/g) || [];
  for (const s of b64.slice(0, 40)) {
    try { const d = Buffer.from(s.slice(1, -1), 'base64').toString('utf8'); if (page.command(d) === 'block') { out.push('[base64] ' + d.slice(0, 200)); break; } } catch {}
  }
  return out;
}

/**
 * @param {string} input  link or a message that contains a link
 * @param {{deep?: boolean}} opts  deep=false: reputation only (no visit) — used for automatic clipboard checks
 */
async function check(input, opts = { deep: true }) {
  const R = urlrep.load();
  const started = Date.now();
  const first = extractUrl(input);
  if (!first) return { ok: false, error: 'no-url', input };
  const reasons = [];
  const chain = [];
  const add = (level, code, detail) => { if (!reasons.some(r => r.code === code && r.detail === detail)) reasons.push({ level, code, detail: detail || '' }); };
  let url = first;
  let pageText = '';
  let download = null;

  for (let hop = 0; hop < 10; hop++) {
    url = unwrap(url);
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch { add('medium', 'bad-url', url); break; }
    const step = { url, host };
    chain.push(step);
    if (/^http:/.test(url)) add('low', 'http', host);
    const h = R.heuristic(url);
    if (h) add(h.level === 'high' ? 'high' : 'medium', h.reason, h.brand || h.words || host);
    if (await urlrep.listed(R.hostOf(url))) add('high', 'listed', host);
    const c = await R.cloudCheck(R.hostOf(url));
    if (c) add(c.level === 'high' ? 'high' : 'medium', c.reason, host);
    const m = url.match(/\/([^/?#]+)(?:[?#]|$)/);
    const fname = m ? decodeURIComponent(m[1]) : '';
    if (RISKY_FILE.test(fname)) download = { name: fname, url };

    const isShort = SHORTENERS.test(host.replace(/^www\./, ''));
    if (!opts.deep && !isShort) break;            // automatic checks never open the page itself
    const res = await fetchHop(url, opts.deep);
    step.status = res.status || res.error;
    if (res.error) { if (opts.deep) add('info', 'unreachable', res.error); break; }
    if (res.status >= 300 && res.status < 400 && res.location) { url = new URL(res.location, url).href; step.redirect = true; continue; }
    if (!opts.deep) break;
    const cd = res.cdisp.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
    if (/attachment/i.test(res.cdisp) || /application\/(x-msdownload|x-msdos-program|vnd\.microsoft\.portable-executable|x-msi|java-archive|vnd\.android\.package-archive|x-rar|x-7z|zip|x-zip|octet-stream)/.test(res.ctype)) {
      download = { name: cd ? decodeURIComponent(cd[1]) : fname || '(file)', url, ctype: res.ctype };
      break;
    }
    if (res.body) {
      // JavaScript / meta-refresh redirects
      const jr = res.body.match(/(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.replace\(\s*["']([^"']+)["']|http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)/i);
      const jsTarget = jr && (jr[1] || jr[2] || jr[3]);
      pageText = htmlToText(res.body);
      const cmds = hiddenCommands(res.body, R.page);
      if (cmds.length) add('high', 'clickfix-cmd', cmds[0]);
      const sc = R.page.score(pageText.slice(0, 40000));
      if (sc.level) add(sc.level === 'high' ? 'high' : 'medium', 'page-' + sc.kind, '');
      if (/password\s*[:：]\s*\S{2,12}|كلمة\s*(السر|المرور)\s*[:：]/i.test(pageText) && /(download|تحميل|setup|crack|keygen|mod|cheat|hack)/i.test(pageText)) add('medium', 'zip-password', '');
      if (jsTarget && pageText.length < 1500 && hop < 9) {
        try { const next = new URL(jsTarget, url).href; if (next !== url && /^https?:/.test(next)) { url = next; step.redirect = 'js'; continue; } } catch {}
      }
    }
    break;
  }

  if (download) {
    const known = reasons.some(r => r.level === 'high');
    // "free cheats / cracks / hacks" programs are the main bait used to spread account-stealing malware
    const bait = /(crack|keygen|hack|cheat|activator|activation|injector|loader|spoofer|aimbot|unlocker|generator|free[-_ ]?(robux|uc|diamonds|coins|vbucks)|premium|patch)/i.test(download.name);
    add(known || bait ? 'high' : 'medium', bait ? 'download-bait' : 'download', download.name);
  }
  if (opts.deep && chain.length && !download && pageText.length < 40 && !reasons.some(r => r.code === 'unreachable')) add('info', 'empty-page', '');
  if (chain.length > 3) add('low', 'many-redirects', String(chain.length - 1));

  const order = { high: 3, medium: 2, low: 1, info: 0 };
  reasons.sort((a, b) => order[b.level] - order[a.level]);
  const top = reasons[0] ? reasons[0].level : 'safe';
  const verdict = top === 'high' ? 'danger' : top === 'medium' ? 'warn' : 'safe';
  return { ok: true, input: first, final: url, verdict, reasons, chain, download, deep: !!opts.deep, ms: Date.now() - started, date: Date.now() };
}

function command(text) { return urlrep.load().page.command(text); }

module.exports = { check, extractUrl, command, unwrap };
