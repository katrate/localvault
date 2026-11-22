/**
 * file-locker.js — AES-256-GCM file & folder encryption for LocalVault
 *
 * Lock:   file/folder → encrypted .lvlock bundle (original deleted securely)
 * Unlock: .lvlock bundle → original file/folder restored
 *
 * .lvlock format (JSON):
 * {
 *   v: 1,
 *   kind: 'file' | 'folder',
 *   originalName: string,          // original basename
 *   originalExt: string,           // original extension ('' for folders)
 *   salt: hex,                     // 16-byte scrypt salt
 *   iv: hex,                       // 12-byte AES-GCM IV
 *   tag: hex,                      // 16-byte GCM auth tag
 *   data: hex,                     // encrypted payload (file bytes OR tar-like archive)
 *   lockedAt: number,              // timestamp ms
 *   lockedPath: string,            // original absolute path at time of locking
 * }
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function deriveKey(pass, saltHex) {
  return crypto.scryptSync(String(pass), Buffer.from(saltHex, 'hex'), 32, SCRYPT_PARAMS);
}

/* ------------------------------------------------------------------ */
/* Minimal tar-like archive for folders                                */
/* Entry format: [4 bytes path len][path utf8][8 bytes data len][data] */
/* ------------------------------------------------------------------ */

function packFolder(dirPath, onProgress) {
  const chunks = [];
  let total = 0;
  let done = 0;

  // First pass: count total bytes for progress
  function countDir(d) {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        countDir(full);
      } else if (entry.isFile()) {
        total += fs.statSync(full).size;
      }
    }
  }
  countDir(dirPath);

  function packDir(d, relBase) {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      const rel = relBase ? relBase + '/' + entry.name : entry.name;

      if (entry.isDirectory()) {
        // Write a directory marker (empty data)
        const pathBuf = Buffer.from(rel + '/', 'utf8');
        const hdr = Buffer.alloc(4);
        hdr.writeUInt32BE(pathBuf.length, 0);
        const lenBuf = Buffer.alloc(8);
        lenBuf.writeBigUInt64BE(BigInt(0), 0);
        chunks.push(hdr, pathBuf, lenBuf);
        packDir(full, rel);
      } else if (entry.isFile()) {
        const data = fs.readFileSync(full);
        const pathBuf = Buffer.from(rel, 'utf8');
        const hdr = Buffer.alloc(4);
        hdr.writeUInt32BE(pathBuf.length, 0);
        const lenBuf = Buffer.alloc(8);
        lenBuf.writeBigUInt64BE(BigInt(data.length), 0);
        chunks.push(hdr, pathBuf, lenBuf, data);
        done += data.length;
        if (typeof onProgress === 'function' && total > 0) {
          onProgress({ percent: (done / total) * 100, phase: 'reading' });
        }
      }
    }
  }

  packDir(dirPath, '');
  return Buffer.concat(chunks);
}

function unpackFolder(buf, destParent, onProgress) {
  let pos = 0;
  const totalLen = buf.length;

  while (pos < buf.length) {
    // Read path length
    if (pos + 4 > buf.length) break;
    const pathLen = buf.readUInt32BE(pos);
    pos += 4;
    if (pos + pathLen > buf.length) break;
    const relPath = buf.slice(pos, pos + pathLen).toString('utf8');
    pos += pathLen;

    // Read data length
    if (pos + 8 > buf.length) break;
    const dataLen = Number(buf.readBigUInt64BE(pos));
    pos += 8;

    const fullDest = path.join(destParent, relPath);

    if (relPath.endsWith('/')) {
      // Directory marker
      fs.mkdirSync(fullDest, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(fullDest), { recursive: true });
      const data = buf.slice(pos, pos + dataLen);
      fs.writeFileSync(fullDest, data);
    }
    pos += dataLen;

    if (typeof onProgress === 'function' && totalLen > 0) {
      onProgress({ percent: (pos / totalLen) * 100, phase: 'writing' });
    }
  }
}

/* ------------------------------------------------------------------ */
/* Secure delete — overwrite with zeros then unlink                    */
/* ------------------------------------------------------------------ */

function secureDeleteFile(filePath) {
  try {
    const size = fs.statSync(filePath).size;
    if (size > 0) {
      const zeros = Buffer.alloc(Math.min(size, 64 * 1024));
      const fd = fs.openSync(filePath, 'r+');
      let written = 0;
      while (written < size) {
        const chunk = Math.min(zeros.length, size - written);
        fs.writeSync(fd, zeros, 0, chunk, written);
        written += chunk;
      }
      fs.closeSync(fd);
    }
  } catch { /* best-effort */ }
  fs.unlinkSync(filePath);
}

function secureDeleteDir(dirPath) {
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      secureDeleteDir(full);
    } else {
      secureDeleteFile(full);
    }
  }
  fs.rmdirSync(dirPath);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Lock a file or folder.
 * @param {string} targetPath  Absolute path to file or folder
 * @param {string} revealPass  User's reveal pass (the master key)
 * @param {function} onProgress ({ percent, phase })
 * @returns {string} Path to the created .lvlock file
 */
function lockItem(targetPath, revealPass, onProgress) {
  const stat = fs.statSync(targetPath);
  const isDir = stat.isDirectory();
  const kind = isDir ? 'folder' : 'file';
  const originalName = path.basename(targetPath);
  const originalExt = isDir ? '' : path.extname(originalName);

  if (typeof onProgress === 'function') onProgress({ percent: 0, phase: 'reading' });

  // Read payload
  let plainBuf;
  if (isDir) {
    plainBuf = packFolder(targetPath, (p) => {
      if (typeof onProgress === 'function') onProgress({ percent: p.percent * 0.4, phase: 'reading' });
    });
  } else {
    plainBuf = fs.readFileSync(targetPath);
    if (typeof onProgress === 'function') onProgress({ percent: 40, phase: 'read' });
  }

  // Encrypt
  if (typeof onProgress === 'function') onProgress({ percent: 45, phase: 'encrypting' });
  const saltHex = crypto.randomBytes(16).toString('hex');
  const key = deriveKey(revealPass, saltHex);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encParts = [cipher.update(plainBuf), cipher.final()];
  const encData = Buffer.concat(encParts);
  const tag = cipher.getAuthTag();

  if (typeof onProgress === 'function') onProgress({ percent: 70, phase: 'writing' });

  // Build .lvlock bundle
  const bundle = {
    v: 1,
    kind,
    originalName,
    originalExt,
    salt: saltHex,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encData.toString('hex'),
    lockedAt: Date.now(),
    lockedPath: targetPath,
  };

  // Write .lvlock next to original
  const lockPath = targetPath + '.lvlock';
  fs.writeFileSync(lockPath, JSON.stringify(bundle), 'utf8');

  if (typeof onProgress === 'function') onProgress({ percent: 85, phase: 'deleting' });

  // Secure-delete original
  if (isDir) {
    secureDeleteDir(targetPath);
  } else {
    secureDeleteFile(targetPath);
  }

  if (typeof onProgress === 'function') onProgress({ percent: 100, phase: 'done' });

  return lockPath;
}

/**
 * Unlock a .lvlock file.
 * @param {string} lockPath   Absolute path to the .lvlock file
 * @param {string} revealPass User's reveal pass
 * @param {function} onProgress ({ percent, phase })
 * @returns {string} Path to the restored file or folder
 */
function unlockItem(lockPath, revealPass, onProgress) {
  if (typeof onProgress === 'function') onProgress({ percent: 5, phase: 'reading' });

  const bundleStr = fs.readFileSync(lockPath, 'utf8');
  const bundle = JSON.parse(bundleStr);

  if (!bundle || bundle.v !== 1) throw new Error('Invalid or corrupted .lvlock file.');

  if (typeof onProgress === 'function') onProgress({ percent: 20, phase: 'decrypting' });

  const key = deriveKey(revealPass, bundle.salt);
  const iv = Buffer.from(bundle.iv, 'hex');
  const tag = Buffer.from(bundle.tag, 'hex');
  const encData = Buffer.from(bundle.data, 'hex');

  let plainBuf;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    plainBuf = Buffer.concat([decipher.update(encData), decipher.final()]);
  } catch {
    throw new Error('Wrong reveal pass or file is corrupted.');
  }

  if (typeof onProgress === 'function') onProgress({ percent: 60, phase: 'writing' });

  // Determine restore path: use original path if possible, else next to .lvlock
  const lockDir = path.dirname(lockPath);
  let restorePath = bundle.lockedPath || path.join(lockDir, bundle.originalName);

  // If restore path already exists (edge case), put it next to the .lvlock
  if (fs.existsSync(restorePath)) {
    restorePath = path.join(lockDir, bundle.originalName);
    // If still exists, add suffix
    if (fs.existsSync(restorePath)) {
      const base = path.basename(bundle.originalName, bundle.originalExt);
      restorePath = path.join(lockDir, base + '_unlocked' + bundle.originalExt);
    }
  }

  if (bundle.kind === 'folder') {
    fs.mkdirSync(restorePath, { recursive: true });
    unpackFolder(plainBuf, restorePath, (p) => {
      if (typeof onProgress === 'function') onProgress({ percent: 60 + p.percent * 0.3, phase: 'writing' });
    });
  } else {
    fs.mkdirSync(path.dirname(restorePath), { recursive: true });
    fs.writeFileSync(restorePath, plainBuf);
  }

  if (typeof onProgress === 'function') onProgress({ percent: 95, phase: 'cleanup' });

  // Remove the .lvlock file
  fs.unlinkSync(lockPath);

  if (typeof onProgress === 'function') onProgress({ percent: 100, phase: 'done' });

  return restorePath;
}

module.exports = { lockItem, unlockItem };
