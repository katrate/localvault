# LocalVault — Offline Password Manager

A lightweight, secure, **100% local and offline** password manager built with Electron. No cloud, no external servers, no network requests, and no telemetry.

---

## Quick Start

```powershell
# Navigate to the project directory
cd password-manager

# Start the application
npm start
# or: npm.cmd start (if PowerShell script execution policy restricts npm)
```

---

## Security & Architecture

### Dual-Credential Protection

| Credential | Purpose | Storage & Crypto |
|---|---|---|
| **Login ID + Login Password** | Opens and unlocks the application UI | Salted `scrypt` (N=16384, r=8, p=1) with 16-byte random salt. Checked via constant-time comparison (`crypto.timingSafeEqual`). |
| **Reveal Pass** | Decrypts individual passwords, encrypts new/updated entries, exports backup | Used to derive an AES-256-GCM key (`scrypt`) that unwraps a random 32-byte master key. **Cannot be recovered if lost.** |

### Cryptographic Details

- **Envelope Encryption**: Each stored password in `vault.json` is encrypted using AES-256-GCM with a unique 12-byte random IV and 16-byte authentication tag, keyed by a 256-bit random master key.
- **Master Key Wrapping**: The master key is stored in `config.json` encrypted with an AES-256-GCM key derived from your reveal pass and a unique 16-byte salt. Changing your reveal pass re-wraps the master key without needing to re-encrypt individual entries.
- **Strict Isolation**: Passwords are never sent in bulk to the renderer process. Only decrypted on-demand when requested with the correct reveal pass.
- **Memory & Display Hygiene**: Revealed passwords automatically hide after 10 seconds and the instant the window loses focus (`blur` event).
- **Clipboard Protection**: Copied passwords automatically wipe from the system clipboard after 45 seconds or immediately when the vault is locked.
- **Zero Network Guarantee**: Electron window runs with `contextIsolation: true`, `sandbox: true`, disabled Node integration in the renderer, blocked popups, and blocked external navigations.

---

## Features

- **Password Generation**: Built-in cryptographically secure random password generator with customizable length (8–64 characters), uppercase, lowercase, numbers, symbols, and ambiguous character filtering.
- **Password Strength Meter**: Real-time password strength evaluation for entries.
- **Show/Hide Input Toggles**: Eye toggle buttons (`👁` / `🙈`) on all password fields.
- **Quick Copy**: Click any revealed password cell or the copy button to copy directly to clipboard.
- **Instant Search & Sort**: Real-time filtering by site/app or username, plus sortable columns (Website, Username, Date Added).
- **Auto-Lock on Inactivity**: Automatically locks the vault after a configurable idle time (1 min, 5 min, 15 min, 30 min, or disabled).
- **Settings & Credential Management**:
  - Change Login Password
  - Change Reveal Pass
  - Inactivity auto-lock preferences
- **Backup & Restore**:
  - **Export to JSON**: Creates a decrypted backup file (protected by reveal pass verification).
  - **Import from JSON**: Restores or merges credentials from a backup file.
- **Vault Reset / Fresh Start**: Option to reset the vault from settings or from the login screen if locked out.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| <kbd>Ctrl</kbd> + <kbd>N</kbd> | Open New Entry modal |
| <kbd>Ctrl</kbd> + <kbd>F</kbd> | Focus search box |
| <kbd>Ctrl</kbd> + <kbd>G</kbd> | Open Password Generator |
| <kbd>Ctrl</kbd> + <kbd>L</kbd> | Lock the vault |
| <kbd>Esc</kbd> | Close any active modal |

---

## File Structure

```
password-manager/
├── main.js        # Electron main process (IPC, window lifecycle, crypto orchestration, dialogs)
├── preload.js     # Secure contextBridge API exposed to renderer
├── vault.js       # Core crypto helpers (scrypt derivation, AES-256-GCM encrypt/decrypt)
├── renderer/
│   ├── index.html # App markup, modal dialogs, and responsive layouts
│   ├── renderer.js# Frontend logic, event handling, generator, sorting, timers
│   └── style.css  # Dark slate theme, password meters, controls, animations
└── package.json   # Electron configuration and dependencies
```

---

## Local Storage Locations

- **Configuration (`config.json`)**: `%APPDATA%\local-password-manager\config.json`
- **Encrypted Vault (`vault.json`)**: `%APPDATA%\local-password-manager\vault.json`

