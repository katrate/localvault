const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('lockApi', {
  getTargetPath: () => ipcRenderer.invoke('lock-dialog-get-path'),
  lock: (pass) => ipcRenderer.invoke('lock-dialog-lock', pass),
  cancel: () => ipcRenderer.send('lock-dialog-cancel'),
  done: () => ipcRenderer.send('lock-dialog-done'),
});
