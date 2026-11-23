// Cloud file reputation: asks Team Cymru's Malware Hash Registry (fed by dozens of antivirus engines)
// whether a file's fingerprint is known malware. Free, no key, sent over encrypted DNS (DoH); only the hash leaves the PC.
const crypto = require('crypto');
const fs = require('fs');

const cache = new Map();

function sha1(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha1');
    fs.createReadStream(file).on('data', d => h.update(d)).on('error', reject).on('end', () => resolve(h.digest('hex')));
  });
}

async function doh(name) {
  for (const base of ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve']) {
    try {
      const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 3000);
      const r = await fetch(`${base}?name=${encodeURIComponent(name)}&type=TXT`, { headers: { accept: 'application/dns-json' }, signal: ctl.signal });
      clearTimeout(tm);
      if (r.ok) return await r.json();
    } catch {}
  }
  return null;
}

/** Returns { detections: percent } when the file is known malware, null when unknown/clean. */
async function lookup(file, size) {
  try {
    if (size > 300 * 1048576) return null;
    const h = await sha1(file);
    if (cache.has(h)) return cache.get(h);
    const j = await doh(`${h}.malware.hash.cymru.com`);
    let v = null;
    const ans = j && (j.Answer || []).find(a => a.type === 16);
    if (ans) {
      const m = String(ans.data).replace(/"/g, '').trim().match(/^(\d+)\s+(\d+)/);   // "<last seen> <detection %>"
      if (m && +m[2] > 0) v = { detections: +m[2], sha1: h };
    }
    if (j) cache.set(h, v);
    if (cache.size > 20000) cache.clear();
    return v;
  } catch { return null; }
}

module.exports = { lookup, sha1 };
