const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  status: () => ipcRenderer.invoke('status'),
  setup: (data) => ipcRenderer.invoke('setup', data),
  login: (data) => ipcRenderer.invoke('login', data),
  lock: () => ipcRenderer.invoke('lock'),
  list: () => ipcRenderer.invoke('list'),
  add: (data) => ipcRenderer.invoke('add', data),
  update: (data) => ipcRenderer.invoke('update', data),
  remove: (id) => ipcRenderer.invoke('remove', id),
  reveal: (data) => ipcRenderer.invoke('reveal', data),
  copy: (text) => ipcRenderer.invoke('copy', text),
  changeLoginPassword: (data) => ipcRenderer.invoke('change-login-password', data),
  changeRevealPass: (data) => ipcRenderer.invoke('change-reveal-pass', data),
  exportData: (data) => ipcRenderer.invoke('export-data', data),
  importData: (data) => ipcRenderer.invoke('import-data', data),
  resetVault: () => ipcRenderer.invoke('reset-vault'),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  downloadAndInstallUpdate: (assetUrl) => ipcRenderer.invoke('download-and-install-update', assetUrl),
  onUpdateProgress: (callback) => {
    ipcRenderer.removeAllListeners('update-download-progress');
    ipcRenderer.on('update-download-progress', (_e, data) => callback(data));
  },
  // File Locker
  flLock: (data) => ipcRenderer.invoke('fl-lock', data),
  flUnlock: (data) => ipcRenderer.invoke('fl-unlock', data),
  flGetPending: () => ipcRenderer.invoke('fl-get-pending'),
  flBrowse: (data) => ipcRenderer.invoke('fl-browse', data),
  flList: () => ipcRenderer.invoke('fl-list'),
  flAddRecord: (data) => ipcRenderer.invoke('fl-add-record', data),
  flRemoveRecord: (data) => ipcRenderer.invoke('fl-remove-record', data),
  onFlLockProgress: (callback) => {
    ipcRenderer.removeAllListeners('fl-lock-progress');
    ipcRenderer.on('fl-lock-progress', (_e, data) => callback(data));
  },
  onFlUnlockProgress: (callback) => {
    ipcRenderer.removeAllListeners('fl-unlock-progress');
    ipcRenderer.on('fl-unlock-progress', (_e, data) => callback(data));
  },
  onFlOpenLockFile: (callback) => {
    ipcRenderer.removeAllListeners('fl-open-lock-file');
    ipcRenderer.on('fl-open-lock-file', (_e, lockPath) => callback(lockPath));
  },
});
