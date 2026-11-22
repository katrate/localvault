const { app, BrowserWindow, ipcMain, clipboard, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');
const V = require('./vault');
const FL = require('./file-locker');

let win = null;
let unlockWin = null;         // small floating unlock dialog
let pendingUnlockPath = null; // .lvlock path pending in the dialog
let lockWin = null;           // small floating lock dialog
let pendingLockPath = null;   // path to lock via right-click context menu
let authed = false;
let authedLoginId = '';
let cfg = null;
let lastSecret = '';
let clipTimer = null;

// Track if app was opened by double-clicking a .lvlock file (used by main window)
let openedLockFile = null;

// Single instance lock — allows second-instance to send the .lvlock path to running instance
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
}

const cfgFile = () => path.join(app.getPath('userData'), 'config.json');
const dbFile = () => path.join(app.getPath('userData'), 'vault.json');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

const ok = (data = {}) => ({ ok: true, ...data });
const fail = (error) => ({ ok: false, error: String(error) });

function loadDb() {
  return readJson(dbFile()) || { entries: [] };
}

function saveDb(db) {
  writeJson(dbFile(), db);
}

function requireAuth() {
  if (!authed) throw new Error('Vault is locked.');
}

// The reveal pass is the real key: it unwraps the random master key that
// encrypts every stored password. Wrong pass => decryption fails.
function unwrapMaster(revealPass) {
  if (!cfg) cfg = readJson(cfgFile());
  if (!cfg) throw new Error('No profile has been created yet.');
  try {
    const key = V.scrypt(revealPass, cfg.revealSalt);
    return Buffer.from(V.decrypt(key, cfg.masterKeyEnc), 'hex');
  } catch {
    throw new Error('Wrong reveal pass.');
  }
}

function clearClipboardIfOurs() {
  if (clipTimer) {
    clearTimeout(clipTimer);
    clipTimer = null;
  }
  try {
    if (lastSecret && clipboard.readText() === lastSecret) {
      clipboard.clear();
    }
  } catch {
    /* ignore */
  }
  lastSecret = '';
}

function copySecret(text) {
  lastSecret = String(text || '');
  clipboard.writeText(lastSecret);
  if (clipTimer) clearTimeout(clipTimer);
  // Auto-clear from clipboard after 45 seconds for safety
  clipTimer = setTimeout(() => {
    clearClipboardIfOurs();
  }, 45000);
}

function lockVault() {
  authed = false;
  authedLoginId = '';
  clearClipboardIfOurs();
}

/* ------------------------------- IPC ------------------------------- */

ipcMain.handle('status', () => {
  cfg = readJson(cfgFile());
  return ok({ configured: !!cfg, dataPath: app.getPath('userData') });
});

ipcMain.handle('setup', (_e, d) => {
  try {
    if (!cfg) cfg = readJson(cfgFile());
    if (cfg) return fail('A profile already exists on this PC.');
    const loginId = String(d.loginId || '').trim();
    const loginPassword = String(d.loginPassword || '');
    const revealPass = String(d.revealPass || '');

    if (loginId.length < 3) return fail('Login ID must be at least 3 characters.');
    if (loginPassword.length < 6) return fail('Login password must be at least 6 characters.');
    if (revealPass.length < 4) return fail('Reveal pass must be at least 4 characters.');

    const saltLogin = crypto.randomBytes(16).toString('hex');
    const hashLogin = V.scrypt(loginId.toLowerCase() + '\u0000' + loginPassword, saltLogin);

    const revealSalt = crypto.randomBytes(16).toString('hex');
    const revealKey = V.scrypt(revealPass, revealSalt);
    const master = crypto.randomBytes(32);

    cfg = {
      v: 1,
      saltLogin,
      hashLogin,
      revealSalt,
      masterKeyEnc: V.encrypt(revealKey, master.toString('hex')),
    };
    writeJson(cfgFile(), cfg);
    if (!fs.existsSync(dbFile())) saveDb({ entries: [] });
    console.log('[Setup] Created new vault for user:', loginId);
    return ok();
  } catch (e) {
    console.error('[Setup] Error:', e.message);
    return fail(e.message);
  }
});

ipcMain.handle('login', (_e, d) => {
  try {
    if (!cfg) cfg = readJson(cfgFile());
    if (!cfg) return fail('No profile has been created yet.');
    const id = String(d.loginId || '').trim().toLowerCase();
    const pw = String(d.loginPassword || '');
    const hash = Buffer.from(V.scrypt(id + '\u0000' + pw, cfg.saltLogin), 'hex');
    const stored = Buffer.from(cfg.hashLogin, 'hex');
    const match = hash.length === stored.length && crypto.timingSafeEqual(hash, stored);
    if (!match) return fail('Incorrect login ID or password.');
    authed = true;
    authedLoginId = id;
    return ok({ loginId: id });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('lock', () => {
  lockVault();
  return ok();
});

ipcMain.handle('list', () => {
  try {
    requireAuth();
    const db = loadDb();
    // Never hand encrypted material (or passwords) to the renderer.
    const entries = db.entries.map(({ enc, ...rest }) => rest);
    return ok({ entries });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('add', (_e, d) => {
  try {
    requireAuth();
    const usedIn = String(d.usedIn || '').trim();
    const username = String(d.username || '').trim();
    const password = String(d.password || '');
    if (!usedIn) return fail('Enter where this password is used.');
    if (!password) return fail('Password cannot be empty.');

    const master = unwrapMaster(String(d.revealPass || ''));
    const db = loadDb();
    const now = Date.now();
    db.entries.push({
      id: crypto.randomUUID(),
      usedIn,
      username,
      enc: V.encrypt(master, password),
      createdAt: now,
      updatedAt: now,
    });
    saveDb(db);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('update', (_e, d) => {
  try {
    requireAuth();
    const db = loadDb();
    const entry = db.entries.find((x) => x.id === d.id);
    if (!entry) return fail('Entry not found.');

    const usedIn = String(d.usedIn || '').trim();
    const username = String(d.username || '').trim();
    const password = String(d.password || '');
    if (!usedIn) return fail('Enter where this password is used.');

    entry.usedIn = usedIn;
    entry.username = username;
    if (password) {
      // Changing the stored secret needs the reveal pass again.
      const master = unwrapMaster(String(d.revealPass || ''));
      entry.enc = V.encrypt(master, password);
    }
    entry.updatedAt = Date.now();
    saveDb(db);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('remove', (_e, id) => {
  try {
    requireAuth();
    const db = loadDb();
    const before = db.entries.length;
    db.entries = db.entries.filter((x) => x.id !== id);
    if (db.entries.length === before) return fail('Entry not found.');
    saveDb(db);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('reveal', (_e, d) => {
  try {
    requireAuth();
    const master = unwrapMaster(String(d.revealPass || ''));
    const db = loadDb();
    const entry = db.entries.find((x) => x.id === d.id);
    if (!entry) return fail('Entry not found.');
    return ok({ password: V.decrypt(master, entry.enc) });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('copy', (_e, text) => {
  try {
    requireAuth();
    copySecret(text);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('change-login-password', (_e, d) => {
  try {
    requireAuth();
    if (!cfg) cfg = readJson(cfgFile());
    if (!cfg) return fail('No profile has been created yet.');

    const currentPw = String(d.currentPassword || '');
    const newPw = String(d.newPassword || '');
    if (newPw.length < 6) return fail('New login password must be at least 6 characters.');

    const hash = Buffer.from(V.scrypt(authedLoginId + '\u0000' + currentPw, cfg.saltLogin), 'hex');
    const stored = Buffer.from(cfg.hashLogin, 'hex');
    const match = hash.length === stored.length && crypto.timingSafeEqual(hash, stored);
    if (!match) return fail('Current login password is incorrect.');

    const newSalt = crypto.randomBytes(16).toString('hex');
    cfg.saltLogin = newSalt;
    cfg.hashLogin = V.scrypt(authedLoginId + '\u0000' + newPw, newSalt);
    writeJson(cfgFile(), cfg);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('change-reveal-pass', (_e, d) => {
  try {
    requireAuth();
    if (!cfg) cfg = readJson(cfgFile());
    if (!cfg) return fail('No profile has been created yet.');

    const currentPass = String(d.currentPass || '');
    const newPass = String(d.newPass || '');
    if (newPass.length < 4) return fail('New reveal pass must be at least 4 characters.');

    // Unwrapping verifies currentPass; throws if wrong
    const master = unwrapMaster(currentPass);

    // Re-wrap master key with new reveal key
    const newRevealSalt = crypto.randomBytes(16).toString('hex');
    const newRevealKey = V.scrypt(newPass, newRevealSalt);
    cfg.revealSalt = newRevealSalt;
    cfg.masterKeyEnc = V.encrypt(newRevealKey, master.toString('hex'));
    writeJson(cfgFile(), cfg);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('export-data', async (_e, d) => {
  try {
    requireAuth();
    const master = unwrapMaster(String(d.revealPass || ''));
    const db = loadDb();
    const decryptedEntries = db.entries.map((entry) => ({
      usedIn: entry.usedIn,
      username: entry.username || '',
      password: V.decrypt(master, entry.enc),
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt || entry.createdAt,
    }));

    const dateStr = new Date().toISOString().slice(0, 10);
    const { filePath, canceled } = await dialog.showSaveDialog(win, {
      title: 'Export Vault Backup',
      defaultPath: `localvault-backup-${dateStr}.json`,
      filters: [{ name: 'JSON Backup (*.json)', extensions: ['json'] }],
    });

    if (canceled || !filePath) return ok({ canceled: true });

    const exportPayload = {
      app: 'LocalVault',
      version: 1,
      exportedAt: new Date().toISOString(),
      entriesCount: decryptedEntries.length,
      entries: decryptedEntries,
    };

    fs.writeFileSync(filePath, JSON.stringify(exportPayload, null, 2), 'utf8');
    return ok({ exported: true, count: decryptedEntries.length, filePath });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('import-data', async (_e, d) => {
  try {
    requireAuth();
    const master = unwrapMaster(String(d.revealPass || ''));

    const { filePaths, canceled } = await dialog.showOpenDialog(win, {
      title: 'Import Vault Backup',
      filters: [{ name: 'JSON Backup (*.json)', extensions: ['json'] }],
      properties: ['openFile'],
    });

    if (canceled || !filePaths || filePaths.length === 0) return ok({ canceled: true });

    const raw = fs.readFileSync(filePaths[0], 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return fail('Invalid JSON backup file.');
    }

    const importList = Array.isArray(parsed) ? parsed : (parsed.entries || []);
    if (!Array.isArray(importList) || importList.length === 0) {
      return fail('No entries found in this backup file.');
    }

    const db = loadDb();
    let importedCount = 0;
    const now = Date.now();
    for (const item of importList) {
      const usedIn = String(item.usedIn || item.website || item.title || '').trim();
      const username = String(item.username || item.login || item.email || '').trim();
      const password = String(item.password || '');
      if (!usedIn || !password) continue;

      db.entries.push({
        id: crypto.randomUUID(),
        usedIn,
        username,
        enc: V.encrypt(master, password),
        createdAt: item.createdAt || now,
        updatedAt: item.updatedAt || now,
      });
      importedCount++;
    }

    saveDb(db);
    return ok({ imported: true, count: importedCount });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.handle('reset-vault', () => {
  try {
    lockVault();
    cfg = null;
    const cPath = cfgFile();
    const dPath = dbFile();
    if (fs.existsSync(cPath)) fs.unlinkSync(cPath);
    if (fs.existsSync(dPath)) fs.unlinkSync(dPath);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

/* --------------------------- File Locker IPC --------------------------- */

// Lock a file or folder
ipcMain.handle('fl-lock', async (_e, { targetPath, revealPass }) => {
  try {
    if (!targetPath) return fail('No path provided.');
    if (!revealPass) return fail('Reveal pass is required.');
    if (!fs.existsSync(targetPath)) return fail('Path does not exist: ' + targetPath);

    const lockPath = FL.lockItem(targetPath, revealPass, (progress) => {
      if (win && !win.isDestroyed()) {
        win.webContents.send('fl-lock-progress', progress);
      }
    });

    return ok({ lockPath });
  } catch (e) {
    return fail(e.message);
  }
});

// Unlock a .lvlock file — used both from vault UI and from shell open
ipcMain.handle('fl-unlock', async (_e, { lockPath, revealPass }) => {
  try {
    if (!lockPath) return fail('No .lvlock path provided.');
    if (!revealPass) return fail('Reveal pass is required.');
    if (!fs.existsSync(lockPath)) return fail('File not found: ' + lockPath);

    const restoredPath = FL.unlockItem(lockPath, revealPass, (progress) => {
      if (win && !win.isDestroyed()) {
        win.webContents.send('fl-unlock-progress', progress);
      }
    });

    return ok({ restoredPath });
  } catch (e) {
    return fail(e.message);
  }
});

// Let renderer ask for the pending lock file (opened via double-click)
ipcMain.handle('fl-get-pending', () => {
  const p = openedLockFile;
  openedLockFile = null; // consume it
  return ok({ lockPath: p });
});

// Open a native browse dialog for file or folder
ipcMain.handle('fl-browse', async (_e, { mode }) => {
  try {
    const properties = mode === 'folder'
      ? ['openDirectory']
      : ['openFile'];
    const res = await dialog.showOpenDialog(win, {
      title: mode === 'folder' ? 'Select a folder to lock' : 'Select a file to lock',
      properties,
    });
    if (res.canceled || !res.filePaths.length) return ok({ canceled: true });
    return ok({ filePath: res.filePaths[0] });
  } catch (e) {
    return fail(e.message);
  }
});

// Get locked items list from db
ipcMain.handle('fl-list', () => {
  try {
    requireAuth();
    const db = loadDb();
    return ok({ items: db.lockedFiles || [] });
  } catch (e) {
    return fail(e.message);
  }
});

// Save a locked item record to db
ipcMain.handle('fl-add-record', (_e, { lockPath, originalName, kind, lockedAt }) => {
  try {
    requireAuth();
    const db = loadDb();
    if (!db.lockedFiles) db.lockedFiles = [];
    db.lockedFiles.push({ id: crypto.randomUUID(), lockPath, originalName, kind, lockedAt });
    saveDb(db);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

// Remove a locked item record from db
ipcMain.handle('fl-remove-record', (_e, { id }) => {
  try {
    requireAuth();
    const db = loadDb();
    db.lockedFiles = (db.lockedFiles || []).filter((x) => x.id !== id);
    saveDb(db);
    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

// Register .lvlock shell association in Windows registry (run on app start)
function registerShellAssociation() {
  if (process.platform !== 'win32') return;
  try {
    const isPackaged = app.isPackaged;
    const exePath = process.execPath;

    // Open command for .lvlock double-click (unlock dialog)
    const openCmd = isPackaged
      ? `"${exePath}" "%1"`
      : `"${exePath}" "${path.resolve(__dirname)}" "%1"`;

    // Lock command for right-click context menu (lock dialog)
    // Use --lock-path="%1" (= style) so Electron can't inject flags between --lock and the path
    const lockCmd = isPackaged
      ? `"${exePath}" "--lock-path=%1"`
      : `"${exePath}" "${path.resolve(__dirname)}" "--lock-path=%1"`;

    const reg = (args) => require('child_process').spawnSync('reg', args, { stdio: 'pipe' });

    // --- .lvlock file type association (double-click to unlock) ---
    reg(['add', 'HKCU\\Software\\Classes\\.lvlock', '/ve', '/d', 'LocalVault.Lock', '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\LocalVault.Lock', '/ve', '/d', 'LocalVault Encrypted File', '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\LocalVault.Lock\\shell\\open\\command', '/ve', '/d', openCmd, '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\LocalVault.Lock\\DefaultIcon', '/ve', '/d', `"${exePath}",0`, '/f']);

    // --- Right-click context menu: "Lock with LocalVault" for all files ---
    reg(['add', 'HKCU\\Software\\Classes\\*\\shell\\LockWithLocalVault', '/ve', '/d', 'Lock with LocalVault', '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\*\\shell\\LockWithLocalVault', '/v', 'Icon', '/d', `"${exePath}",0`, '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\*\\shell\\LockWithLocalVault\\command', '/ve', '/d', lockCmd, '/f']);

    // --- Right-click context menu: "Lock with LocalVault" for folders ---
    reg(['add', 'HKCU\\Software\\Classes\\Directory\\shell\\LockWithLocalVault', '/ve', '/d', 'Lock with LocalVault', '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\Directory\\shell\\LockWithLocalVault', '/v', 'Icon', '/d', `"${exePath}",0`, '/f']);
    reg(['add', 'HKCU\\Software\\Classes\\Directory\\shell\\LockWithLocalVault\\command', '/ve', '/d', lockCmd, '/f']);

    console.log('[Shell] Registered .lvlock association + right-click context menu.');
  } catch (e) {
    console.error('[Shell] Could not register shell association:', e.message);
  }
}

/* --------------------------- Auto-Update IPC --------------------------- */

const GITHUB_REPO = 'katrate/localvault';

function compareVersions(v1, v2) {
  // Strip non-version characters like 'v'
  const clean1 = (v1 || '').replace(/^[^\d]*/, '').split('.').map((n) => parseInt(n, 10) || 0);
  const clean2 = (v2 || '').replace(/^[^\d]*/, '').split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(clean1.length, clean2.length); i++) {
    const num1 = clean1[i] || 0;
    const num2 = clean2[i] || 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }
  return 0;
}

function fetchHttps(urlStr, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const req = https.get(
      {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        headers: {
          'User-Agent': 'LocalVault-App-Updater',
          ...headers,
        },
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return fetchHttps(res.headers.location, headers).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP status ${res.statusCode}`));
        }
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.setTimeout(8000, () => {
      req.destroy();
      reject(new Error('Update check request timed out'));
    });
  });
}

ipcMain.handle('check-for-updates', async () => {
  try {
    const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
    const dataStr = await fetchHttps(apiUrl);
    const release = JSON.parse(dataStr);
    if (!release || !release.tag_name) {
      return { ok: false, error: 'No releases found.' };
    }

    const latestVersion = release.tag_name.replace(/^v/, '');
    const currentVersion = app.getVersion();

    // Check if latest version is greater than current
    if (compareVersions(latestVersion, currentVersion) > 0) {
      // Find .exe asset
      const exeAsset = (release.assets || []).find((a) => a.name && a.name.toLowerCase().endsWith('.exe'));
      if (exeAsset && exeAsset.browser_download_url) {
        return {
          ok: true,
          updateAvailable: true,
          latestVersion: release.tag_name,
          currentVersion: 'v' + currentVersion,
          assetUrl: exeAsset.browser_download_url,
          releaseNotes: release.body || '',
        };
      }
    }

    return {
      ok: true,
      updateAvailable: false,
      latestVersion: release.tag_name,
      currentVersion: 'v' + currentVersion,
    };
  } catch (e) {
    // Graceful offline fail: if offline or no repo/release yet, don't interrupt user
    return { ok: false, error: e.message };
  }
});

function downloadFileWithRedirects(fileUrl, destPath, onProgress) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    function get(currentUrl) {
      const parsed = new URL(currentUrl);
      https
        .get(
          {
            hostname: parsed.hostname,
            path: parsed.pathname + parsed.search,
            headers: { 'User-Agent': 'LocalVault-App-Updater' },
          },
          (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              return get(res.headers.location);
            }
            if (res.statusCode !== 200) {
              return reject(new Error(`Failed to download: HTTP ${res.statusCode}`));
            }

            const totalBytes = parseInt(res.headers['content-length'] || '0', 10);
            let downloadedBytes = 0;

            res.on('data', (chunk) => {
              downloadedBytes += chunk.length;
              file.write(chunk);
              if (totalBytes > 0 && typeof onProgress === 'function') {
                onProgress({
                  downloaded: downloadedBytes,
                  total: totalBytes,
                  percent: (downloadedBytes / totalBytes) * 100,
                });
              }
            });

            res.on('end', () => {
              file.end(() => resolve(destPath));
            });
          }
        )
        .on('error', (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
    }
    get(fileUrl);
  });
}

ipcMain.handle('download-and-install-update', async (_e, assetUrl) => {
  try {
    if (!assetUrl) return fail('No download URL provided');
    const tempDir = app.getPath('temp');
    const installerPath = path.join(tempDir, `LocalVault-Update-${Date.now()}.exe`);

    await downloadFileWithRedirects(assetUrl, installerPath, (progress) => {
      if (win && !win.isDestroyed()) {
        win.webContents.send('update-download-progress', progress);
      }
    });

    // Launch the downloaded installer detached and quit app
    const child = spawn(installerPath, [], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();

    setTimeout(() => {
      app.quit();
    }, 800);

    return ok();
  } catch (e) {
    return fail(e.message);
  }
});

/* ------------------------------ Unlock Dialog Window ------------------------------ */

function createUnlockDialog(lockFilePath) {
  if (unlockWin && !unlockWin.isDestroyed()) {
    // Already open — update the pending path and re-focus
    pendingUnlockPath = lockFilePath;
    unlockWin.focus();
    return;
  }

  pendingUnlockPath = lockFilePath;
  const iconPath = path.join(__dirname, 'assets', 'logo.png');

  unlockWin = new BrowserWindow({
    width: 390,
    height: 300,
    resizable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    show: false,
    backgroundColor: '#0f172a',
    title: 'Unlock File — LocalVault',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    frame: true,
    alwaysOnTop: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload-unlock.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  unlockWin.removeMenu();
  unlockWin.loadFile(path.join(__dirname, 'renderer', 'unlock-dialog.html'));
  unlockWin.once('ready-to-show', () => unlockWin.show());

  // Block external navigation
  unlockWin.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  unlockWin.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });

  unlockWin.on('closed', () => {
    unlockWin = null;
    pendingUnlockPath = null;
    // If this was the only window and no main win, quit
    if (!win || win.isDestroyed()) {
      app.quit();
    }
  });
}

// IPC handlers for the unlock dialog
ipcMain.handle('unlock-dialog-get-path', () => pendingUnlockPath);

ipcMain.handle('unlock-dialog-unlock', async (_e, revealPass) => {
  try {
    if (!pendingUnlockPath) return fail('No file path set.');
    if (!revealPass) return fail('Password is required.');
    if (!fs.existsSync(pendingUnlockPath)) return fail('File not found.');

    const restoredPath = FL.unlockItem(pendingUnlockPath, revealPass, () => {});

    // Also remove from locked records DB if present (best-effort, no auth needed here)
    try {
      const db = loadDb();
      if (db.lockedFiles) {
        db.lockedFiles = db.lockedFiles.filter((x) => x.lockPath !== pendingUnlockPath);
        saveDb(db);
      }
    } catch { /* ignore */ }

    return ok({ restoredPath });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.on('unlock-dialog-cancel', () => {
  if (unlockWin && !unlockWin.isDestroyed()) unlockWin.close();
});

ipcMain.on('unlock-dialog-done', () => {
  if (unlockWin && !unlockWin.isDestroyed()) unlockWin.close();
});

/* ------------------------------ Lock Dialog Window ------------------------------ */

function createLockDialog(targetPath) {
  if (lockWin && !lockWin.isDestroyed()) {
    pendingLockPath = targetPath;
    lockWin.focus();
    return;
  }

  pendingLockPath = targetPath;
  const iconPath = path.join(__dirname, 'assets', 'logo.png');

  lockWin = new BrowserWindow({
    width: 420,
    height: 360,
    resizable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    show: false,
    backgroundColor: '#0f172a',
    title: 'Lock with LocalVault',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    frame: true,
    alwaysOnTop: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload-lock.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  lockWin.removeMenu();
  lockWin.loadFile(path.join(__dirname, 'renderer', 'lock-dialog.html'));
  lockWin.once('ready-to-show', () => lockWin.show());

  lockWin.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  lockWin.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });

  lockWin.on('closed', () => {
    lockWin = null;
    pendingLockPath = null;
    if (!win || win.isDestroyed()) {
      app.quit();
    }
  });
}

// IPC handlers for the lock dialog
ipcMain.handle('lock-dialog-get-path', () => pendingLockPath);

ipcMain.handle('lock-dialog-lock', async (_e, revealPass) => {
  try {
    if (!pendingLockPath) return fail('No file path set.');
    if (!revealPass) return fail('Password is required.');
    if (!fs.existsSync(pendingLockPath)) return fail('File or folder not found: ' + pendingLockPath);

    const lockPath = FL.lockItem(pendingLockPath, revealPass, () => {});
    return ok({ lockPath });
  } catch (e) {
    return fail(e.message);
  }
});

ipcMain.on('lock-dialog-cancel', () => {
  if (lockWin && !lockWin.isDestroyed()) lockWin.close();
});

ipcMain.on('lock-dialog-done', () => {
  if (lockWin && !lockWin.isDestroyed()) lockWin.close();
});

/* ------------------------------ Main Window ------------------------------ */

function createWindow(lockFilePath) {
  const iconPath = path.join(__dirname, 'assets', 'logo.png');
  win = new BrowserWindow({
    width: 1080,
    height: 740,
    minWidth: 800,
    minHeight: 560,
    show: false,
    backgroundColor: '#0f172a',
    title: 'LocalVault',
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  if (lockFilePath) {
    openedLockFile = lockFilePath;
  }

  win.webContents.on('console-message', (_e, level, message, line, sourceId) => {
    console.log(`[Renderer] (${line}): ${message}`);
  });

  win.removeMenu();
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());

  // Hard offline guarantee: no external navigation, no popups.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });

  win.on('closed', () => {
    lockVault();
    win = null;
  });
}

// Find the target path for --lock flag, skipping any --electron-flags injected by Electron
function findLockTarget(args) {
  const idx = args.indexOf('--lock');
  if (idx === -1) {
    // Also support --lock-path=C:\path\file style (more robust, avoids flag injection)
    const eq = args.find((a) => a.startsWith('--lock-path='));
    return eq ? eq.slice(12) : null;
  }
  // Skip any --flags Electron injects after --lock; return first real path arg
  for (let i = idx + 1; i < args.length; i++) {
    if (!args[i].startsWith('-')) return args[i];
  }
  return null;
}

app.whenReady().then(() => {
  const args = process.argv.slice(app.isPackaged ? 1 : 2);
  const lockArg = args.find((a) => a.endsWith('.lvlock') && fs.existsSync(a));
  const lockFileArg = findLockTarget(args);

  registerShellAssociation();

  if (lockFileArg) {
    // Launched from right-click "Lock with LocalVault" — show lock dialog only
    createLockDialog(lockFileArg);
  } else if (lockArg) {
    // Launched by double-clicking a .lvlock file — show unlock dialog only
    createUnlockDialog(lockArg);
  } else {
    // Normal launch — open the full app
    createWindow(null);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Second-instance: another file double-clicked or right-clicked while app is already running
app.on('second-instance', (_e, argv) => {
  const args = argv.slice(app.isPackaged ? 1 : 2);
  const lockArg = args.find((a) => a.endsWith('.lvlock') && fs.existsSync(a));
  const lockFileArg = findLockTarget(args);

  if (lockFileArg) {
    // Right-click lock from Explorer while app is running
    createLockDialog(lockFileArg);
  } else if (lockArg) {
    // Double-click .lvlock while app is running
    createUnlockDialog(lockArg);
  } else if (win) {
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});

app.on('window-all-closed', () => {
  lockVault();
  if (process.platform !== 'darwin') app.quit();
});
