(() => {
const api = window.api || {
  status: async () => ({ configured: false, dataPath: '' }),
  setup: async () => ({ ok: false, error: 'API bridge not connected' }),
  login: async () => ({ ok: false, error: 'API bridge not connected' }),
  lock: async () => ({ ok: true }),
  list: async () => ({ ok: true, entries: [] }),
  add: async () => ({ ok: false, error: 'API bridge not connected' }),
  update: async () => ({ ok: false, error: 'API bridge not connected' }),
  remove: async () => ({ ok: false, error: 'API bridge not connected' }),
  reveal: async () => ({ ok: false, error: 'API bridge not connected' }),
  copy: async () => ({ ok: false, error: 'API bridge not connected' }),
  changeLoginPassword: async () => ({ ok: false, error: 'API bridge not connected' }),
  changeRevealPass: async () => ({ ok: false, error: 'API bridge not connected' }),
  exportData: async () => ({ ok: false, error: 'API bridge not connected' }),
  importData: async () => ({ ok: false, error: 'API bridge not connected' }),
  resetVault: async () => ({ ok: false, error: 'API bridge not connected' }),
  checkForUpdates: async () => ({ ok: false }),
  downloadAndInstallUpdate: async () => ({ ok: false }),
  onUpdateProgress: () => {},
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const REVEAL_MS = 10000;

function safeGetStorage(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

function safeSetStorage(key, val) {
  try {
    localStorage.setItem(key, String(val));
  } catch {
    /* ignore */
  }
}

// State
let entries = [];
let loginId = '';
const revealed = new Map(); // id -> { password, exp }
let pendingReveal = null; // { id, intent }
let entryMode = 'add'; // 'add' | 'edit'
let editingId = null;

let sortCol = 'usedIn';
let sortDir = 'asc';

let autoLockMs = parseInt(safeGetStorage('lv_autolock', '300000'), 10);
let lastActivityTime = Date.now();
let generatorCaller = null; // 'entry' | 'top'
let pendingBackupIntent = null; // 'export' | 'import'
let pendingConfirmCallback = null;

/* ------------------------------ helpers ------------------------------ */

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const icon = (name, cls = '') =>
  `<svg class="icon ${cls}"><use href="#icon-${name}"></use></svg>`;

function show(screenId) {
  $$('.screen').forEach((s) => s.classList.toggle('hidden', s.id !== screenId));
}

function openModal(id) {
  $(id).classList.remove('hidden');
  const input = $(id + ' input:not([type="range"]):not([type="checkbox"])');
  if (input) setTimeout(() => input.focus(), 50);
}

function closeModal(id) {
  $(id).classList.add('hidden');
  const err = $(id + ' .error');
  if (err) err.textContent = '';
}

function closeAllModals() {
  $$('.overlay').forEach((ov) => closeModal('#' + ov.id));
}

let toastTimer = null;
function toast(msg, kind = '') {
  const el = $('#toast');
  const ic = kind === 'good' ? icon('check', 'sm') : kind === 'err' ? icon('alert-triangle', 'sm') : '';
  el.innerHTML = `${ic}<span>${esc(msg)}</span>`;
  el.className = 'toast ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3200);
}

const fmtDate = (ts) =>
  new Date(ts).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

/* ------------------------------ boot ------------------------------ */

async function init() {
  try {
    bindEvents();
  } catch (e) {
    console.error('bindEvents error:', e);
  }
  try {
    initAutoLock();
  } catch (e) {
    console.error('initAutoLock error:', e);
  }
  try {
    initPasswordToggles();
  } catch (e) {
    console.error('initPasswordToggles error:', e);
  }
  try {
    initGenerator();
  } catch (e) {
    console.error('initGenerator error:', e);
  }
  try {
    initSettings();
  } catch (e) {
    console.error('initSettings error:', e);
  }

  try {
    bindUpdateEvents();
  } catch (e) {
    console.error('bindUpdateEvents error:', e);
  }

  try {
    initFileLock();
  } catch (e) {
    console.error('initFileLock error:', e);
  }

  // On startup, check if opened with a .lvlock file
  setTimeout(async () => {
    try {
      const pending = await api.flGetPending();
      if (pending && pending.ok && pending.lockPath) {
        openFileUnlockModal(pending.lockPath);
      }
    } catch { /* ignore */ }
  }, 500);

  // Check for auto-update silently on startup
  setTimeout(checkAppUpdate, 1500);

  try {
    const status = await api.status();
    if (status && status.configured) {
      const pathEl = $('#login-path');
      if (pathEl) pathEl.textContent = 'Vault data: ' + (status.dataPath || '');
      show('screen-login');
      const loginIdInput = $('#login-id');
      if (loginIdInput) setTimeout(() => loginIdInput.focus(), 50);
    } else {
      show('screen-setup');
      const setupIdInput = $('#setup-id');
      if (setupIdInput) setTimeout(() => setupIdInput.focus(), 50);
    }
  } catch (err) {
    console.error('Status check error:', err);
    show('screen-setup');
  }
}

function bindEvents() {
  // Forms
  $('#form-setup').addEventListener('submit', onSetup);
  $('#form-login').addEventListener('submit', onLogin);
  $('#form-reveal').addEventListener('submit', onRevealSubmit);
  $('#form-entry').addEventListener('submit', onEntrySubmit);
  $('#form-backup-prompt').addEventListener('submit', onBackupPromptSubmit);

  // Buttons
  $('#btn-add').addEventListener('click', () => openEntry('add'));
  $('#btn-add-empty').addEventListener('click', () => openEntry('add'));
  $('#btn-lock').addEventListener('click', lock);
  $('#btn-settings').addEventListener('click', openSettings);
  $('#btn-generator-top').addEventListener('click', () => openGenerator('top'));
  $('#entry-gen-btn').addEventListener('click', () => openGenerator('entry'));
  $('#btn-login-reset').addEventListener('click', confirmResetVault);

  // Search & Sorting
  $('#search').addEventListener('input', renderTable);
  $('#btn-clear-search').addEventListener('click', () => {
    $('#search').value = '';
    renderTable();
  });

  $$('thead th.sortable').forEach((th) => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortCol === col) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortCol = col;
        sortDir = 'asc';
      }
      renderTable();
    });
  });

  // Table clicks
  $('#rows').addEventListener('click', onRowClick);

  // Entry password live strength & reveal toggle
  $('#entry-pw').addEventListener('input', onEntryPasswordInput);

  // Modals close triggers
  $$('[data-close]').forEach((b) => {
    b.addEventListener('click', () => {
      const overlay = b.closest('.overlay');
      if (overlay) closeModal('#' + overlay.id);
    });
  });

  $$('.overlay').forEach((ov) => {
    ov.addEventListener('mousedown', (e) => {
      if (e.target === ov) closeModal('#' + ov.id);
    });
  });

  // Confirm modal buttons
  $('#confirm-btn-cancel').addEventListener('click', () => {
    closeModal('#modal-confirm');
    pendingConfirmCallback = null;
  });
  $('#confirm-btn-ok').addEventListener('click', () => {
    closeModal('#modal-confirm');
    if (typeof pendingConfirmCallback === 'function') {
      pendingConfirmCallback();
      pendingConfirmCallback = null;
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAllModals();
      return;
    }

    // Ctrl+N / Cmd+N -> New Entry (only when inside vault)
    if ((e.ctrlKey || e.metaKey) && (e.key === 'n' || e.key === 'N')) {
      if (!$('#screen-vault').classList.contains('hidden')) {
        e.preventDefault();
        openEntry('add');
      }
    }

    // Ctrl+F -> Search
    if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
      if (!$('#screen-vault').classList.contains('hidden')) {
        e.preventDefault();
        $('#search').focus();
        $('#search').select();
      }
    }

    // Ctrl+G -> Generator
    if ((e.ctrlKey || e.metaKey) && (e.key === 'g' || e.key === 'G')) {
      if (!$('#screen-vault').classList.contains('hidden')) {
        e.preventDefault();
        openGenerator('top');
      }
    }

    // Ctrl+L -> Lock
    if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L')) {
      if (!$('#screen-vault').classList.contains('hidden')) {
        e.preventDefault();
        lock();
      }
    }
  });

  // Safety: hide all revealed passwords on window blur
  window.addEventListener('blur', hideAllRevealed);

  // Tick for countdown timer on open passwords
  setInterval(tick, 250);
}

/* ------------------------------ setup / login / lock ------------------------------ */

async function onSetup(e) {
  e.preventDefault();
  const err = $('#setup-error');
  err.textContent = '';

  const id = $('#setup-id').value.trim();
  const pw = $('#setup-pw').value;
  const pw2 = $('#setup-pw2').value;
  const rv = $('#setup-reveal').value;
  const rv2 = $('#setup-reveal2').value;

  if (pw !== pw2) return (err.textContent = 'Login passwords do not match.');
  if (rv !== rv2) return (err.textContent = 'Reveal passes do not match.');

  const res = await api.setup({ loginId: id, loginPassword: pw, revealPass: rv });
  if (!res.ok) {
    if (res.error && res.error.includes('already exists')) {
      // Profile exists, switch directly to login screen
      show('screen-login');
      $('#login-id').value = id;
      $('#login-pw').focus();
      toast('A vault already exists. Please unlock with your password.', 'good');
      return;
    }
    return (err.textContent = res.error);
  }

  // Auto-login directly into the vault — no need to re-enter credentials!
  const loginRes = await api.login({ loginId: id, loginPassword: pw });
  if (loginRes.ok) {
    loginId = loginRes.loginId;
    $('#who').textContent = loginId;
    $('#form-setup').reset();
    lastActivityTime = Date.now();
    show('screen-vault');
    await refresh();
    toast('Vault created successfully! Welcome to LocalVault.', 'good');
  } else {
    // Fallback: switch to login screen
    $('#form-setup').reset();
    $('#login-id').value = id;
    show('screen-login');
    $('#login-pw').focus();
    toast('Vault created. Please enter your login password.', 'good');
  }
}

async function onLogin(e) {
  e.preventDefault();
  const err = $('#login-error');
  err.textContent = '';

  const res = await api.login({
    loginId: $('#login-id').value,
    loginPassword: $('#login-pw').value,
  });
  if (!res.ok) return (err.textContent = res.error);

  loginId = res.loginId;
  $('#login-pw').value = '';
  $('#who').textContent = loginId;
  lastActivityTime = Date.now();
  show('screen-vault');
  await refresh();
}

async function lock() {
  hideAllRevealed();
  await api.lock();
  loginId = '';
  $('#form-login').reset();
  closeAllModals();
  show('screen-login');
  $('#login-pw').focus();
  toast('Vault locked.', 'good');
}

async function refresh() {
  const res = await api.list();
  if (!res.ok) return lock();
  entries = res.entries;
  renderTable();
}

/* ------------------------------ table & search ------------------------------ */

function renderTable() {
  const q = $('#search').value.trim().toLowerCase();
  let list = entries.filter(
    (e) =>
      !q ||
      (e.usedIn && e.usedIn.toLowerCase().includes(q)) ||
      (e.username && e.username.toLowerCase().includes(q))
  );

  // Sorting
  list.sort((a, b) => {
    let va = a[sortCol] || '';
    let vb = b[sortCol] || '';
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();

    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  // Update sort indicators in header
  $$('thead th.sortable').forEach((th) => {
    const col = th.dataset.sort;
    const iconEl = $(`#sort-${col}`);
    if (col === sortCol) {
      iconEl.innerHTML = sortDir === 'asc' ? icon('arrow-up', 'sm') : icon('arrow-down', 'sm');
      iconEl.style.opacity = '1';
    } else {
      iconEl.innerHTML = icon('arrow-up-down', 'sm');
      iconEl.style.opacity = '0.5';
    }
  });

  // Badge count & search hints
  $('#count-badge').textContent = entries.length;
  if (q) {
    $('#search-count').textContent = `${list.length}/${entries.length}`;
  } else {
    $('#search-count').textContent = '';
  }

  const tableEl = $('#vault-table');
  const emptyEl = $('#empty');
  const noResultsEl = $('#no-results');

  if (entries.length === 0) {
    tableEl.classList.add('hidden');
    emptyEl.classList.remove('hidden');
    noResultsEl.classList.add('hidden');
    return;
  }

  if (list.length === 0 && q) {
    tableEl.classList.add('hidden');
    emptyEl.classList.add('hidden');
    noResultsEl.classList.remove('hidden');
    $('#no-results-msg').textContent = `No passwords match "${q}".`;
    return;
  }

  tableEl.classList.remove('hidden');
  emptyEl.classList.add('hidden');
  noResultsEl.classList.add('hidden');

  $('#rows').innerHTML = list
    .map((e, i) => {
      const rev = revealed.get(e.id);
      const pwHtml = rev
        ? `<span class="pw open" data-pw="${e.id}" title="Click to copy password">${esc(rev.password)}
             <span class="timer" data-timer="${e.id}">${Math.max(0, Math.ceil((rev.exp - Date.now()) / 1000))}s</span>
           </span>`
        : `<button class="pw locked" data-reveal="${e.id}" title="Click to reveal">${icon('lock', 'sm')} ••••••••</button>`;

      return `<tr>
        <td class="col-num">${i + 1}</td>
        <td class="used">${esc(e.usedIn)}</td>
        <td class="user">${esc(e.username || '—')}</td>
        <td>${pwHtml}</td>
        <td class="col-date">${fmtDate(e.createdAt)}</td>
        <td class="col-actions">
          <div class="actions">
            <button class="btn icon ${rev ? 'active' : ''}" data-reveal="${e.id}" title="${rev ? 'Hide password' : 'View password'}">${rev ? icon('eye-off', 'sm') : icon('eye', 'sm')}</button>
            <button class="btn icon" data-copy="${e.id}" title="Copy password">${icon('copy', 'sm')}</button>
            <button class="btn icon" data-edit="${e.id}" title="Edit entry">${icon('pencil', 'sm')}</button>
            <button class="btn icon danger" data-del="${e.id}" title="Delete entry">${icon('trash-2', 'sm')}</button>
          </div>
        </td>
      </tr>`;
    })
    .join('');
}

function tick() {
  let changed = false;
  for (const [id, rev] of revealed) {
    const left = Math.max(0, Math.ceil((rev.exp - Date.now()) / 1000));
    const el = document.querySelector(`[data-timer="${id}"]`);
    if (el) el.textContent = left + 's';
    if (left <= 0) {
      revealed.delete(id);
      changed = true;
    }
  }
  if (changed) renderTable();
}

function hideAllRevealed() {
  if (!revealed.size) return;
  revealed.clear();
  renderTable();
}

function onRowClick(e) {
  const t = e.target.closest('[data-reveal],[data-copy],[data-edit],[data-del],[data-pw]');
  if (!t) return;

  // Direct click on open password copies it
  if (t.dataset.pw) {
    const rev = revealed.get(t.dataset.pw);
    if (rev) {
      api.copy(rev.password).then((res) => {
        if (res.ok) toast('Password copied to clipboard!', 'good');
      });
    }
    return;
  }

  // View / Hide button or locked cell click
  if (t.dataset.reveal) {
    const id = t.dataset.reveal;
    if (revealed.has(id)) {
      // Toggle off if already visible
      revealed.delete(id);
      renderTable();
      return;
    }
    return askReveal(id, 'view');
  }

  // Copy button click
  if (t.dataset.copy) {
    const id = t.dataset.copy;
    if (revealed.has(id)) {
      // Already decrypted in memory! Copy immediately
      const rev = revealed.get(id);
      api.copy(rev.password).then((res) => {
        if (res.ok) toast('Password copied — clipboard clears in 45s or on lock.', 'good');
        else toast(res.error, 'err');
      });
      return;
    }
    return askReveal(id, 'copy');
  }

  // Edit button click
  if (t.dataset.edit) {
    const entry = entries.find((x) => x.id === t.dataset.edit);
    if (entry) openEntry('edit', entry);
    return;
  }

  // Delete button click
  if (t.dataset.del) {
    const entry = entries.find((x) => x.id === t.dataset.del);
    if (!entry) return;
    showConfirm(
      'Delete Entry',
      `Are you sure you want to delete the entry for "${entry.usedIn}"? This cannot be undone.`,
      () => {
        api.remove(entry.id).then((res) => {
          if (!res.ok) return toast(res.error, 'err');
          revealed.delete(entry.id);
          refresh();
          toast('Entry deleted.', 'good');
        });
      }
    );
  }
}

/* ------------------------------ reveal modal ------------------------------ */

function askReveal(id, intent) {
  const entry = entries.find((x) => x.id === id);
  if (!entry) return;
  pendingReveal = { id, intent };
  $('#reveal-target').textContent =
    (intent === 'copy' ? 'Copy password for ' : 'Show password for ') + entry.usedIn;
  $('#reveal-pass').value = '';
  $('#reveal-submit').textContent = intent === 'copy' ? 'Copy password' : 'Show password';
  openModal('#modal-reveal');
}

async function onRevealSubmit(e) {
  e.preventDefault();
  const err = $('#reveal-error');
  err.textContent = '';

  const res = await api.reveal({
    id: pendingReveal.id,
    revealPass: $('#reveal-pass').value,
  });
  if (!res.ok) return (err.textContent = res.error);

  const { id, intent } = pendingReveal;
  revealed.set(id, { password: res.password, exp: Date.now() + REVEAL_MS });

  if (intent === 'copy') {
    const copy = await api.copy(res.password);
    if (!copy.ok) return (err.textContent = copy.error);
    toast('Password copied — clipboard clears in 45s or on lock.', 'good');
  }

  $('#reveal-pass').value = '';
  closeModal('#modal-reveal');
  renderTable();
}

/* ------------------------------ entry modal (add / edit) ------------------------------ */

function openEntry(mode, entry = null) {
  entryMode = mode;
  editingId = entry ? entry.id : null;

  $('#entry-title').textContent = mode === 'add' ? 'New entry' : 'Edit entry';
  $('#entry-subtitle').textContent =
    mode === 'add'
      ? 'Fill in the details to securely store credentials.'
      : 'Update details. Leave password blank to keep current secret.';
  $('#entry-used').value = entry ? entry.usedIn : '';
  $('#entry-user').value = entry ? entry.username || '' : '';
  $('#entry-pw').value = '';
  $('#entry-pw').placeholder =
    mode === 'add' ? 'Password' : 'Leave blank to keep existing password';
  $('#entry-reveal').value = '';
  $('#entry-error').textContent = '';

  // In add mode, reveal pass is always needed to encrypt
  // In edit mode, reveal pass is only needed if new password is entered
  updateEntryRevealVisibility();
  evaluatePasswordStrength('');

  openModal('#modal-entry');
}

function updateEntryRevealVisibility() {
  const isEdit = entryMode === 'edit';
  const hasPwInput = $('#entry-pw').value.length > 0;
  const showReveal = !isEdit || hasPwInput;

  $('#entry-reveal-group').classList.toggle('hidden', !showReveal);
  $('#entry-reveal-label').textContent = isEdit
    ? '(required to change encrypted password)'
    : '(required to encrypt password)';
}

function onEntryPasswordInput() {
  const pw = $('#entry-pw').value;
  evaluatePasswordStrength(pw);
  updateEntryRevealVisibility();
}

async function onEntrySubmit(e) {
  e.preventDefault();
  const err = $('#entry-error');
  err.textContent = '';

  const usedIn = $('#entry-used').value.trim();
  const username = $('#entry-user').value.trim();
  const password = $('#entry-pw').value;
  const revealPass = $('#entry-reveal').value;

  if (!usedIn) return (err.textContent = 'Enter where this password is used.');

  let res;
  if (entryMode === 'add') {
    if (!password) return (err.textContent = 'Enter a password.');
    if (!revealPass) return (err.textContent = 'Enter your reveal pass to encrypt it.');
    res = await api.add({ usedIn, username, password, revealPass });
  } else {
    const changingPassword = password.length > 0;
    if (changingPassword && !revealPass)
      return (err.textContent = 'Enter your reveal pass to update the password.');
    res = await api.update({ id: editingId, usedIn, username, password, revealPass });
  }

  if (!res.ok) return (err.textContent = res.error);

  closeModal('#modal-entry');
  await refresh();
  toast(entryMode === 'add' ? 'Entry saved and encrypted.' : 'Entry updated.', 'good');
}

/* ------------------------------ password strength evaluator ------------------------------ */

function evaluatePasswordStrength(pw) {
  const wrap = $('#entry-strength-wrap');
  const txt = $('#str-text');
  wrap.className = 'strength-meter-wrap';

  if (!pw) {
    wrap.classList.add('hidden');
    return;
  }
  wrap.classList.remove('hidden');

  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw)) score++;

  if (score <= 1) {
    wrap.classList.add('str-weak');
    txt.textContent = 'Weak';
  } else if (score === 2) {
    wrap.classList.add('str-fair');
    txt.textContent = 'Fair';
  } else if (score === 3) {
    wrap.classList.add('str-good');
    txt.textContent = 'Good';
  } else {
    wrap.classList.add('str-strong');
    txt.textContent = 'Strong';
  }
}

/* ------------------------------ password generator ------------------------------ */

function initGenerator() {
  $('#gen-len-range').addEventListener('input', (e) => {
    $('#gen-len-label').textContent = e.target.value;
    generatePassword();
  });

  $$('#modal-generator input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener('change', generatePassword);
  });

  $('#gen-btn-refresh').addEventListener('click', generatePassword);

  $('#gen-btn-copy').addEventListener('click', async () => {
    const pw = $('#gen-pw-display').textContent;
    if (!pw || pw.startsWith('•')) return;
    const res = await api.copy(pw);
    if (res.ok) toast('Password copied to clipboard!', 'good');
  });

  $('#gen-btn-use').addEventListener('click', () => {
    const pw = $('#gen-pw-display').textContent;
    $('#entry-pw').value = pw;
    evaluatePasswordStrength(pw);
    updateEntryRevealVisibility();
    closeModal('#modal-generator');
    toast('Generated password inserted.', 'good');
  });
}

function openGenerator(caller = 'top') {
  generatorCaller = caller;
  $('#gen-btn-use').classList.toggle('hidden', caller !== 'entry');
  generatePassword();
  openModal('#modal-generator');
}

function generatePassword() {
  const len = parseInt($('#gen-len-range').value, 10);
  const upper = $('#gen-opt-upper').checked;
  const lower = $('#gen-opt-lower').checked;
  const digits = $('#gen-opt-digits').checked;
  const symbols = $('#gen-opt-symbols').checked;
  const noAmbig = $('#gen-opt-no-ambig').checked;

  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let digitChars = '0123456789';
  let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (noAmbig) {
    upperChars = upperChars.replace(/[IO]/g, '');
    lowerChars = lowerChars.replace(/[lo]/g, '');
    digitChars = digitChars.replace(/[01]/g, '');
  }

  let pool = '';
  const required = [];

  if (upper) {
    pool += upperChars;
    required.push(upperChars[getRandomInt(upperChars.length)]);
  }
  if (lower) {
    pool += lowerChars;
    required.push(lowerChars[getRandomInt(lowerChars.length)]);
  }
  if (digits) {
    pool += digitChars;
    required.push(digitChars[getRandomInt(digitChars.length)]);
  }
  if (symbols) {
    pool += symbolChars;
    required.push(symbolChars[getRandomInt(symbolChars.length)]);
  }

  if (!pool) {
    $('#gen-pw-display').textContent = 'Select at least one character type';
    return;
  }

  const result = [...required];
  while (result.length < len) {
    result.push(pool[getRandomInt(pool.length)]);
  }

  // Cryptographic shuffle
  for (let i = result.length - 1; i > 0; i--) {
    const j = getRandomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  $('#gen-pw-display').textContent = result.join('');
}

function getRandomInt(max) {
  const arr = new Uint32Array(1);
  window.crypto.getRandomValues(arr);
  return arr[0] % max;
}

/* ------------------------------ show / hide password toggles ------------------------------ */

function initPasswordToggles() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-toggle-pw');
    if (!btn) return;
    const wrap = btn.closest('.pw-input-wrap');
    if (!wrap) return;
    const input = wrap.querySelector('input');
    if (!input) return;

    if (input.type === 'password') {
      input.type = 'text';
      btn.innerHTML = icon('eye-off', 'sm');
    } else {
      input.type = 'password';
      btn.innerHTML = icon('eye', 'sm');
    }
  });
}

/* ------------------------------ settings & backup ------------------------------ */

function initSettings() {
  // Tab switching
  $$('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.tab-btn').forEach((b) => b.classList.remove('active'));
      $$('.tab-pane').forEach((p) => p.classList.add('hidden'));
      btn.classList.add('active');
      $('#' + btn.dataset.tab).classList.remove('hidden');
    });
  });

  // Change Login Password form
  $('#form-change-login-pw').addEventListener('submit', onChangeLoginPw);

  // Change Reveal Pass form
  $('#form-change-reveal-pass').addEventListener('submit', onChangeRevealPass);

  // Auto-lock select
  $('#select-autolock').value = String(autoLockMs);
  $('#select-autolock').addEventListener('change', (e) => {
    autoLockMs = parseInt(e.target.value, 10);
    safeSetStorage('lv_autolock', autoLockMs);
    toast('Auto-lock setting updated.', 'good');
  });

  // Export / Import buttons
  $('#btn-export-backup').addEventListener('click', () => promptBackupAuth('export'));
  $('#btn-import-backup').addEventListener('click', () => promptBackupAuth('import'));

  // Danger zone reset
  $('#btn-reset-vault').addEventListener('click', confirmResetVault);
}

function openSettings() {
  // Reset tab to security
  $$('.tab-btn').forEach((b, i) => b.classList.toggle('active', i === 0));
  $$('.tab-pane').forEach((p, i) => p.classList.toggle('hidden', i !== 0));
  $('#form-change-login-pw').reset();
  $('#form-change-reveal-pass').reset();
  $('#chg-login-error').textContent = '';
  $('#chg-reveal-error').textContent = '';
  openModal('#modal-settings');
}

async function onChangeLoginPw(e) {
  e.preventDefault();
  const err = $('#chg-login-error');
  err.textContent = '';

  const curr = $('#chg-login-curr').value;
  const n1 = $('#chg-login-new').value;
  const n2 = $('#chg-login-new2').value;

  if (n1 !== n2) return (err.textContent = 'New login passwords do not match.');
  if (n1.length < 6) return (err.textContent = 'Password must be at least 6 characters.');

  const res = await api.changeLoginPassword({ currentPassword: curr, newPassword: n1 });
  if (!res.ok) return (err.textContent = res.error);

  $('#form-change-login-pw').reset();
  toast('Login password changed successfully.', 'good');
}

async function onChangeRevealPass(e) {
  e.preventDefault();
  const err = $('#chg-reveal-error');
  err.textContent = '';

  const curr = $('#chg-reveal-curr').value;
  const n1 = $('#chg-reveal-new').value;
  const n2 = $('#chg-reveal-new2').value;

  if (n1 !== n2) return (err.textContent = 'New reveal passes do not match.');
  if (n1.length < 4) return (err.textContent = 'Reveal pass must be at least 4 characters.');

  const res = await api.changeRevealPass({ currentPass: curr, newPass: n1 });
  if (!res.ok) return (err.textContent = res.error);

  $('#form-change-reveal-pass').reset();
  toast('Reveal pass changed successfully.', 'good');
}

function promptBackupAuth(intent) {
  pendingBackupIntent = intent;
  $('#backup-prompt-title').textContent =
    intent === 'export' ? '📤 Export Vault Backup' : '📥 Import Vault Backup';
  $('#backup-prompt-desc').textContent =
    intent === 'export'
      ? 'Enter your reveal pass to decrypt and export your entries.'
      : 'Enter your reveal pass to encrypt and import entries into your vault.';
  $('#backup-prompt-pass').value = '';
  $('#backup-prompt-error').textContent = '';
  $('#backup-prompt-btn').textContent = intent === 'export' ? 'Export…' : 'Import…';
  openModal('#modal-backup-prompt');
}

async function onBackupPromptSubmit(e) {
  e.preventDefault();
  const err = $('#backup-prompt-error');
  err.textContent = '';
  const revealPass = $('#backup-prompt-pass').value;

  if (pendingBackupIntent === 'export') {
    const res = await api.exportData({ revealPass });
    if (!res.ok) return (err.textContent = res.error);
    if (res.canceled) {
      closeModal('#modal-backup-prompt');
      return;
    }
    closeModal('#modal-backup-prompt');
    toast(`Exported ${res.count} entries successfully.`, 'good');
  } else if (pendingBackupIntent === 'import') {
    const res = await api.importData({ revealPass });
    if (!res.ok) return (err.textContent = res.error);
    if (res.canceled) {
      closeModal('#modal-backup-prompt');
      return;
    }
    closeModal('#modal-backup-prompt');
    await refresh();
    toast(`Imported ${res.count} entries successfully.`, 'good');
  }
}

function confirmResetVault() {
  showConfirm(
    'Reset Vault & Delete All Data?',
    'This will permanently delete your vault and all encrypted passwords on this PC. This action is completely irreversible. Are you absolutely sure?',
    async () => {
      const res = await api.resetVault();
      if (!res.ok) return toast(res.error, 'err');
      loginId = '';
      entries = [];
      revealed.clear();
      closeAllModals();
      show('screen-setup');
      $('#form-setup').reset();
      toast('Vault has been reset. You can now create a new profile.', 'good');
    }
  );
}

/* ------------------------------ confirmation modal ------------------------------ */

function showConfirm(title, msg, onOk) {
  $('#confirm-title').textContent = title;
  $('#confirm-msg').textContent = msg;
  pendingConfirmCallback = onOk;
  openModal('#modal-confirm');
}

/* ------------------------------ inactivity auto-lock ------------------------------ */

function initAutoLock() {
  const resetActivity = () => {
    lastActivityTime = Date.now();
  };

  ['mousemove', 'mousedown', 'keydown', 'touchstart'].forEach((evt) => {
    window.addEventListener(evt, resetActivity, { passive: true });
  });

  setInterval(() => {
    if (!loginId || autoLockMs <= 0) return;
    if (Date.now() - lastActivityTime >= autoLockMs) {
      lock();
      toast('Vault auto-locked due to inactivity.', 'good');
    }
  }, 2000);
}

/* ------------------------------ file locker UI ------------------------------ */

let flSelectedPath = null;
let flLockedItems = [];

function initFileLock() {
  // Open file lock modal from topbar button
  $('#btn-filelock').addEventListener('click', () => {
    openFileLockModal();
  });

  // Tab switching inside file lock modal
  $$('[data-filetab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('[data-filetab]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const tabId = btn.dataset.filetab;
      $$('#modal-filelock .tab-pane').forEach((p) => {
        p.classList.toggle('active', p.id === tabId);
        p.classList.toggle('hidden', p.id !== tabId);
      });
      if (tabId === 'fl-tab-locked') renderLockedList();
    });
  });

  // Browse file button
  $('#fl-browse-btn').addEventListener('click', async () => {
    const res = await api.flBrowse({ mode: 'file' });
    if (!res.ok || res.canceled) return;
    setFlSelectedPath(res.filePath);
  });

  // Drag & drop onto dropzone
  const dropzone = $('#fl-dropzone');
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    const item = e.dataTransfer.files[0];
    if (item) setFlSelectedPath(item.path);
  });

  // Manual path input
  $('#fl-path-input').addEventListener('input', () => {
    const val = $('#fl-path-input').value.trim();
    if (val) {
      setFlSelectedPath(val, false); // don't set input field again
    } else {
      flSelectedPath = null;
      $('#fl-selected-preview').classList.add('hidden');
      $('#fl-lock-btn').disabled = true;
    }
  });

  // Clear selection
  $('#fl-clear-selection').addEventListener('click', () => {
    flSelectedPath = null;
    $('#fl-path-input').value = '';
    $('#fl-selected-preview').classList.add('hidden');
    $('#fl-lock-btn').disabled = true;
    $('#fl-lock-error').textContent = '';
  });

  // Lock button
  $('#fl-lock-btn').addEventListener('click', onFileLock);

  // Unlock modal — cancel button
  $('#btn-file-unlock-cancel').addEventListener('click', () => {
    closeModal('#modal-file-unlock');
    $('#file-unlock-pass').value = '';
    $('#file-unlock-error').textContent = '';
  });

  // Unlock modal — submit
  $('#btn-file-unlock-submit').addEventListener('click', onFileUnlock);
  $('#file-unlock-pass').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') onFileUnlock();
  });

  // Listen for shell-opened .lvlock file (from second-instance or startup)
  api.onFlOpenLockFile((lockPath) => {
    openFileUnlockModal(lockPath);
  });

  // Set up lock/unlock progress listeners
  api.onFlLockProgress((data) => {
    const bar = $('#fl-lock-bar');
    const status = $('#fl-lock-status');
    if (bar) bar.style.width = Math.min(100, Math.round(data.percent || 0)) + '%';
    if (status) status.textContent = data.phase === 'done' ? 'Locked!' : `Encrypting… ${Math.round(data.percent || 0)}%`;
  });

  api.onFlUnlockProgress((data) => {
    const bar = $('#fl-unlock-bar');
    const status = $('#fl-unlock-status');
    if (bar) bar.style.width = Math.min(100, Math.round(data.percent || 0)) + '%';
    if (status) status.textContent = data.phase === 'done' ? 'Unlocked!' : `Decrypting… ${Math.round(data.percent || 0)}%`;
  });
}

function setFlSelectedPath(p, updateInput = true) {
  flSelectedPath = p;
  const name = p.split(/[\\/]/).pop() || p;
  const isFolder = !name.includes('.');
  $('#fl-preview-icon').innerHTML = `<use href="${isFolder ? '#icon-folder-lock' : '#icon-file-lock'}"></use>`;
  $('#fl-preview-name').textContent = name;
  $('#fl-selected-preview').classList.remove('hidden');
  if (updateInput) $('#fl-path-input').value = p;
  $('#fl-lock-btn').disabled = false;
  $('#fl-lock-error').textContent = '';
}

async function openFileLockModal() {
  // Check vault is unlocked
  if (!loginId) {
    toast('Please unlock the vault first to use File Lock.', 'err');
    return;
  }
  // Reset state
  flSelectedPath = null;
  $('#fl-path-input').value = '';
  $('#fl-selected-preview').classList.add('hidden');
  $('#fl-lock-btn').disabled = true;
  $('#fl-lock-error').textContent = '';
  $('#fl-lock-pass').value = '';
  $('#fl-lock-progress').classList.add('hidden');
  $('#fl-lock-bar').style.width = '0%';
  // Switch to Lock tab
  $$('[data-filetab]').forEach((b) => b.classList.toggle('active', b.dataset.filetab === 'fl-tab-lock'));
  $$('#modal-filelock .tab-pane').forEach((p) => {
    p.classList.toggle('active', p.id === 'fl-tab-lock');
    p.classList.toggle('hidden', p.id !== 'fl-tab-lock');
  });
  openModal('#modal-filelock');
}

async function onFileLock() {
  const err = $('#fl-lock-error');
  err.textContent = '';
  const pass = $('#fl-lock-pass').value;
  if (!flSelectedPath) return (err.textContent = 'Select a file or folder first.');
  if (!pass) return (err.textContent = 'Enter your reveal pass.');

  $('#fl-lock-btn').disabled = true;
  $('#fl-lock-progress').classList.remove('hidden');
  $('#fl-lock-status').textContent = 'Starting encryption…';
  $('#fl-lock-bar').style.width = '0%';

  const res = await api.flLock({ targetPath: flSelectedPath, revealPass: pass });
  if (!res.ok) {
    err.textContent = res.error;
    $('#fl-lock-btn').disabled = false;
    $('#fl-lock-progress').classList.add('hidden');
    return;
  }

  // Save record
  const name = flSelectedPath.split(/[\\/]/).pop();
  await api.flAddRecord({
    lockPath: res.lockPath,
    originalName: name,
    kind: res.lockPath.includes('.') ? 'file' : 'folder',
    lockedAt: Date.now(),
  });

  $('#fl-lock-status').textContent = '✓ Locked successfully!';
  $('#fl-lock-bar').style.width = '100%';
  $('#fl-lock-pass').value = '';
  flSelectedPath = null;

  toast(`"${name}" locked → ${res.lockPath.split(/[\\/]/).pop()}`, 'good');

  setTimeout(() => {
    closeModal('#modal-filelock');
    $('#fl-lock-progress').classList.add('hidden');
    $('#fl-lock-btn').disabled = false;
  }, 1200);
}

async function renderLockedList() {
  const res = await api.flList();
  flLockedItems = (res.ok && res.items) ? res.items : [];
  const container = $('#fl-locked-list');
  const noLocked = $('#fl-no-locked');

  if (!flLockedItems.length) {
    if (noLocked) noLocked.classList.remove('hidden');
    container.innerHTML = '<p class="muted small-text" id="fl-no-locked">No locked items yet.</p>';
    return;
  }

  container.innerHTML = flLockedItems.map((item) => `
    <div class="fl-locked-item" data-id="${esc(item.id)}">
      <svg class="icon sm" style="color: var(--accent); flex-shrink:0;"><use href="#icon-${item.kind === 'folder' ? 'folder-lock' : 'file-lock'}"></use></svg>
      <div class="fl-locked-info">
        <div class="fl-locked-name">${esc(item.originalName)}</div>
        <div class="fl-locked-path muted small-text">${esc(item.lockPath)}</div>
        <div class="fl-locked-date muted small-text">${fmtDate(item.lockedAt)}</div>
      </div>
      <div class="fl-locked-actions">
        <button class="btn icon" data-fl-unlock="${esc(item.id)}" title="Unlock & restore">
          ${icon('lock-open', 'sm')}
        </button>
        <button class="btn icon danger" data-fl-forget="${esc(item.id)}" title="Remove from list (file stays locked on disk)">
          ${icon('trash-2', 'sm')}
        </button>
      </div>
    </div>
  `).join('');

  // Bind unlock / forget buttons
  $$('[data-fl-unlock]', container).forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = flLockedItems.find((x) => x.id === btn.dataset.flUnlock);
      if (item) openFileUnlockModal(item.lockPath, item.id);
    });
  });
  $$('[data-fl-forget]', container).forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.flForget;
      await api.flRemoveRecord({ id });
      toast('Removed from list (file stays locked on disk).', 'good');
      renderLockedList();
    });
  });
}

// Pending unlock state
let pendingUnlockLockPath = null;
let pendingUnlockRecordId = null;

function openFileUnlockModal(lockPath, recordId = null) {
  pendingUnlockLockPath = lockPath;
  pendingUnlockRecordId = recordId;
  const name = (lockPath || '').split(/[\\/]/).pop();
  $('#file-unlock-name').textContent = `File: ${name}`;
  $('#file-unlock-pass').value = '';
  $('#file-unlock-error').textContent = '';
  $('#fl-unlock-progress').classList.add('hidden');
  $('#fl-unlock-bar').style.width = '0%';
  openModal('#modal-file-unlock');
  setTimeout(() => $('#file-unlock-pass').focus(), 60);
}

async function onFileUnlock() {
  const err = $('#file-unlock-error');
  err.textContent = '';
  const pass = $('#file-unlock-pass').value;
  if (!pass) return (err.textContent = 'Enter your reveal pass.');
  if (!pendingUnlockLockPath) return;

  $('#btn-file-unlock-submit').disabled = true;
  $('#fl-unlock-progress').classList.remove('hidden');
  $('#fl-unlock-status').textContent = 'Decrypting…';
  $('#fl-unlock-bar').style.width = '0%';

  const res = await api.flUnlock({ lockPath: pendingUnlockLockPath, revealPass: pass });
  if (!res.ok) {
    err.textContent = res.error;
    $('#btn-file-unlock-submit').disabled = false;
    $('#fl-unlock-progress').classList.add('hidden');
    return;
  }

  $('#fl-unlock-bar').style.width = '100%';
  $('#fl-unlock-status').textContent = '✓ Unlocked!';

  // Remove db record if we have it
  if (pendingUnlockRecordId) {
    await api.flRemoveRecord({ id: pendingUnlockRecordId });
  }

  const restoredName = res.restoredPath.split(/[\\/]/).pop();
  toast(`Unlocked → "${restoredName}" restored.`, 'good');

  setTimeout(() => {
    closeModal('#modal-file-unlock');
    $('#btn-file-unlock-submit').disabled = false;
    $('#fl-unlock-progress').classList.add('hidden');
    // Re-render locked list if modal is open
    if (!$('#fl-tab-locked').classList.contains('hidden')) renderLockedList();
  }, 900);
}

/* ------------------------------ auto-updater ------------------------------ */
let pendingUpdateAssetUrl = null;

async function checkAppUpdate() {
  try {
    const res = await api.checkForUpdates();
    if (res && res.updateAvailable) {
      pendingUpdateAssetUrl = res.assetUrl;
      $('#update-msg').innerHTML = `A new version <strong>${esc(res.latestVersion)}</strong> is available (current: ${esc(res.currentVersion)}).<br>Would you like to download and install it now?`;
      openModal('#modal-update');
    }
  } catch (err) {
    console.log('Update check error (ignored):', err);
  }
}

function bindUpdateEvents() {
  const btnNow = $('#btn-update-now');
  if (btnNow) {
    btnNow.addEventListener('click', async () => {
      if (!pendingUpdateAssetUrl) return;
      $('#update-actions').classList.add('hidden');
      $('#update-progress-wrap').classList.remove('hidden');
      $('#update-status-text').textContent = 'Starting download...';

      api.onUpdateProgress((data) => {
        const percent = Math.min(100, Math.round(data.percent || 0));
        $('#update-progress-bar').style.width = percent + '%';
        $('#update-status-text').textContent = `Downloading update: ${percent}%`;
      });

      const res = await api.downloadAndInstallUpdate(pendingUpdateAssetUrl);
      if (!res.ok) {
        $('#update-status-text').textContent = 'Update failed: ' + (res.error || 'Unknown error');
        $('#update-actions').classList.remove('hidden');
        $('#btn-update-now').textContent = 'Retry';
      } else {
        $('#update-status-text').textContent = 'Update downloaded! Launching installer...';
      }
    });
  }
}

// Safety error handler
window.addEventListener('error', (e) => {
  console.error('Unhandled UI error:', e.error || e.message);
  if ($$('.screen:not(.hidden)').length === 0) {
    show('screen-setup');
  }
});

// Start
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
})();
