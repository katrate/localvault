const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('unlockApi', {
  getLockPath: () => ipcRenderer.invoke('unlock-dialog-get-path'),
  unlock: (pass) => ipcRenderer.invoke('unlock-dialog-unlock', pass),
  cancel: () => ipcRenderer.send('unlock-dialog-cancel'),
  done: () => ipcRenderer.send('unlock-dialog-done'),
});
