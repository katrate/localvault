const { app, BrowserWindow, ipcMain, clipboard, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');
const V = require('./vault');

let win = null;
let authed = false; // session flag: has the login ID/password been entered?
let authedLoginId = ''; // lowercase login ID of authenticated session
let cfg = null; // config.json contents (hashes + wrapped master key)
let lastSecret = ''; // last password copied, so we can wipe the clipboard
let clipTimer = null; // clipboard auto-clear timer

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

/* ------------------------------ window ------------------------------ */

function createWindow() {
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

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  lockVault();
  if (process.platform !== 'darwin') app.quit();
});
