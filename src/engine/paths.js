const path = require('path');
const fs = require('fs');
const { app } = require('electron');

function resRoot() {
  return app.isPackaged ? process.resourcesPath : path.join(__dirname, '..', '..');
}
function vendor(...p) { return path.join(resRoot(), 'vendor', ...p); }
function rules(...p) { return path.join(resRoot(), 'rules', ...p); }
function asset(...p) {
  const a = path.join(resRoot(), 'assets', ...p);
  return fs.existsSync(a) ? a : path.join(__dirname, '..', '..', 'assets', ...p);
}
function data(...p) { return path.join(app.getPath('userData'), ...p); }
function exists(p) { try { return fs.existsSync(p); } catch { return false; } }

module.exports = { resRoot, vendor, rules, asset, data, exists };
