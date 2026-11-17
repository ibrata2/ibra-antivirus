// Local bridge between the browser extension and the app (127.0.0.1 only).
// Only requests from our own extension ID with the X-IBRA header are accepted.
const http = require('http');
const EventEmitter = require('events');

const PORT = 47219;
const EXTENSION_ID = 'hbdgebnomhamlgjnhaiakofdfpciahkc';

class Bridge extends EventEmitter {
  constructor(handlers) {
    super();
    this.h = handlers;          // { lang(), scan(path) }
    this.browsers = {};         // name -> { lastSeen, version, stats, listCount }
    this.server = null;
  }
  start() {
    this.server = http.createServer((req, res) => this.handle(req, res));
    this.server.on('error', () => {});
    this.server.listen(PORT, '127.0.0.1');
  }
  allowed(req) {
    const o = req.headers.origin || '';
    return req.headers['x-ibra'] === '1' && (o === `chrome-extension://${EXTENSION_ID}` || o.startsWith('moz-extension://'));
  }
  send(res, code, obj) {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': `chrome-extension://${EXTENSION_ID}` });
    res.end(JSON.stringify(obj));
  }
  handle(req, res) {
    if (req.method === 'OPTIONS' || !this.allowed(req)) { res.writeHead(403); return res.end(); }
    let body = '';
    req.on('data', d => { body += d; if (body.length > 65536) req.destroy(); });
    req.on('end', async () => {
      let data = {};
      try { data = body ? JSON.parse(body) : {}; } catch { return this.send(res, 400, {}); }
      try {
        if (req.url === '/heartbeat') {
          const name = String(data.browser || 'Browser').slice(0, 20);
          this.browsers[name] = { lastSeen: Date.now(), version: data.version, stats: data.stats || {}, listCount: data.listCount || 0 };
          this.emit('change');
          return this.send(res, 200, { ok: true, lang: this.h.lang() });
        }
        if (req.url === '/event') {
          this.emit('event', { type: String(data.type || ''), url: String(data.url || '').slice(0, 2000), reason: String(data.reason || '') });
          return this.send(res, 200, { ok: true });
        }
        if (req.url === '/scan' && typeof data.path === 'string') {
          const threat = await this.h.scan(data.path, String(data.url || ''));
          return this.send(res, 200, { ok: true, threat });
        }
        return this.send(res, 404, {});
      } catch (e) { return this.send(res, 500, { error: String(e.message || e) }); }
    });
  }
  status() {
    const now = Date.now();
    return Object.entries(this.browsers).map(([name, b]) => ({ name, ...b, online: now - b.lastSeen < 3 * 60 * 1000 }));
  }
}

module.exports = { Bridge, PORT, EXTENSION_ID };
