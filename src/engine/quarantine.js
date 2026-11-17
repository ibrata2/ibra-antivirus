// Quarantine: dangerous files are encrypted and moved to a safe folder so they can't run.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY = crypto.createHash('sha256').update('IBRA-ANTIVIRUS-QUARANTINE-v1').digest();

class Quarantine {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.index = path.join(dir, 'index.json');
    try { this.items = JSON.parse(fs.readFileSync(this.index, 'utf8')); } catch { this.items = []; }
  }
  _save() { fs.writeFileSync(this.index, JSON.stringify(this.items, null, 2)); }
  list() { return this.items.slice(); }
  isQuarantineFile(p) { return path.resolve(p).toLowerCase().startsWith(path.resolve(this.dir).toLowerCase()); }

  /** Move a file into quarantine. Returns item or throws. */
  add(file, threat = {}) {
    const data = fs.readFileSync(file);
    const id = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const iv = crypto.randomBytes(16);
    const c = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    const enc = Buffer.concat([Buffer.from('IBRAQ1'), iv, c.update(data), c.final()]);
    const dest = path.join(this.dir, id + '.qtn');
    fs.writeFileSync(dest, enc);
    const sha256 = crypto.createHash('sha256').update(data).digest('hex');
    // remove the original (clear read-only / hidden attributes first)
    try { fs.chmodSync(file, 0o666); } catch {}
    try { fs.unlinkSync(file); } catch (e) { fs.unlinkSync(dest); throw e; }
    const item = { id, original: file, name: threat.name || 'Unknown', engine: threat.engine || '', size: data.length, sha256, date: new Date().toISOString() };
    this.items.unshift(item);
    this._save();
    return item;
  }

  restore(id, toPath) {
    const it = this.items.find(i => i.id === id);
    if (!it) throw new Error('not-found');
    const raw = fs.readFileSync(path.join(this.dir, id + '.qtn'));
    const iv = raw.subarray(6, 22);
    const d = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
    const data = Buffer.concat([d.update(raw.subarray(22)), d.final()]);
    const dest = toPath || it.original;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, data);
    this.remove(id);
    return dest;
  }

  remove(id) {
    try { fs.unlinkSync(path.join(this.dir, id + '.qtn')); } catch {}
    this.items = this.items.filter(i => i.id !== id);
    this._save();
  }

  clear() { for (const it of this.list()) this.remove(it.id); }
}

module.exports = Quarantine;
