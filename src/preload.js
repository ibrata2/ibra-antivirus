const { contextBridge, ipcRenderer, webUtils } = require('electron');

const on = ch => cb => { const f = (_, d) => cb(d); ipcRenderer.on(ch, f); return () => ipcRenderer.removeListener(ch, f); };

contextBridge.exposeInMainWorld('ibra', {
  state: () => ipcRenderer.invoke('state'),
  set: (k, v) => ipcRenderer.invoke('set', k, v),
  scan: req => ipcRenderer.invoke('scan', req),
  cancel: () => ipcRenderer.invoke('cancel'),
  pick: kind => ipcRenderer.invoke('pick', kind),
  threatAction: (p, a) => ipcRenderer.invoke('threat-action', p, a),
  threatsAll: a => ipcRenderer.invoke('threats-all', a),
  quarantineList: () => ipcRenderer.invoke('quarantine-list'),
  quarantineRestore: id => ipcRenderer.invoke('quarantine-restore', id),
  quarantineDelete: id => ipcRenderer.invoke('quarantine-delete', id),
  quarantineClear: () => ipcRenderer.invoke('quarantine-clear'),
  history: () => ipcRenderer.invoke('history'),
  historyClear: () => ipcRenderer.invoke('history-clear'),
  exclusionAdd: kind => ipcRenderer.invoke('exclusion-add', kind),
  exclusionRemove: p => ipcRenderer.invoke('exclusion-remove', p),
  dbUpdate: () => ipcRenderer.invoke('db-update'),
  openUrl: u => ipcRenderer.invoke('open-url', u),
  reveal: p => ipcRenderer.invoke('reveal', p),
  testEicar: () => ipcRenderer.invoke('test-eicar'),
  appUpdate: () => ipcRenderer.invoke('app-update'),
  appInstallUpdate: () => ipcRenderer.invoke('app-install-update'),
  pathForFile: f => { try { return webUtils.getPathForFile(f); } catch { return f.path; } },
  win: a => ipcRenderer.send('win', a),
  onState: on('state'), onProgress: on('progress'), onThreat: on('threat'), onScanDone: on('scan-done'),
  onDbProgress: on('db-progress'), onDbDone: on('db-done'), onRealtime: on('realtime-event'),
  onAppUpdate: on('app-update'), onWin: on('win')
});
