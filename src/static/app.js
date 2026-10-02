// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  wif: null,
  pubkeyHex: null,
  p2pkh: null,
  p2sh_p2wpkh: null,
  p2wpkh: null,
  walletType: 'p2pkh',   // active wallet type
  address: null,         // derived from walletType

  utxos: [],
  selected: new Set(),   // "txid:vout" keys of UTXOs chosen as inputs
  recipient: null,       // last /address/validate result for the recipient field
  feeRates: null,
  txid: null,
  rawTxHex: null,
  utxoPollInterval: null,
  confPollInterval: null,
  labAddress: null,
  activeSidebarStep: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const fmt = n => Number(n).toLocaleString();
const utxoKey = u => `${u.txid}:${u.vout}`;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

let toastTimer = null;
function showToast(msg, type = 'error') {
  const t = $('toast');
  t.textContent = msg;
  t.className = `toast ${type}`;
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 4000);
}

function unlockStep(n) {
  const el = document.getElementById(`step-${n}`);
  el.classList.remove('locked');
  el.classList.add('active');
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (window.innerWidth >= 900) openSidebar(n);
  updateStepper();
}

function copyToClipboard(targetId) {
  const el = $(targetId);
  if (!el) { showToast('Copy failed'); return; }
  const text = el.textContent.trim();

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text)
      .then(() => showToast('Copied!', 'success'))
      .catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  const ok = document.execCommand('copy');
  document.body.removeChild(ta);
  ok ? showToast('Copied!', 'success') : showToast('Copy failed');
}

async function apiFetch(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ── Theme ─────────────────────────────────────────────────────────────────────
const THEME_KEY = 'wallet_lab_theme';

function currentTheme() {
  return document.documentElement.dataset.theme
    || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}

function updateThemeButton() {
  const next = currentTheme() === 'light' ? 'dark' : 'light';
  const btn = $('btn-theme');
  btn.textContent = next === 'light' ? '☀ Light' : '☾ Dark';
  btn.setAttribute('aria-label', `Switch to ${next} theme`);
}

$('btn-theme').addEventListener('click', () => {
  const next = currentTheme() === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch { /* storage unavailable */ }
  updateThemeButton();
});
updateThemeButton();

// ── Progress stepper ──────────────────────────────────────────────────────────
function updateStepper() {
  const unlocked = [1, 2, 3, 4, 5].filter(n => !$(`step-${n}`).classList.contains('locked'));
  const current = Math.max(...unlocked);
  const demoDone = !$('demo-result').classList.contains('hidden');

  document.querySelectorAll('.stepper li').forEach(li => {
    const n = parseInt(li.dataset.step, 10);
    const btn = li.querySelector('button');
    const done = n < current || (n === 5 && demoDone);
    li.classList.toggle('done', done);
    li.classList.toggle('current', n === current && !done);
    li.classList.toggle('locked', n > current);
    btn.disabled = n > current;
    if (n === current) btn.setAttribute('aria-current', 'step');
    else btn.removeAttribute('aria-current');
  });
}

document.querySelectorAll('.stepper button').forEach(btn => {
  btn.addEventListener('click', () => {
    const n = btn.closest('li').dataset.step;
    $(`step-${n}`).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

$('btn-reset').addEventListener('click', () => {
  const msg = state.wif
    ? 'Reset the lab? This deletes the saved wallet key from this browser. ' +
      'Any testnet coins still on it are lost unless you copied or downloaded the key.'
    : 'Reset the lab?';
  if (!confirm(msg)) return;
  try { localStorage.removeItem(STORAGE_KEY); } catch { /* storage unavailable */ }
  location.reload();
});

// ── Wallet type helpers ───────────────────────────────────────────────────────
const TYPE_LABELS = {
  p2pkh:       { name: 'Legacy P2PKH',       badge: 'P2PKH',      cls: 'p2pkh'  },
  p2sh_p2wpkh: { name: 'Nested SegWit',      badge: 'P2SH-P2WPKH', cls: 'nested' },
  p2wpkh:      { name: 'Native SegWit',      badge: 'P2WPKH',     cls: 'native' },
};

const KIND_LABELS = {
  p2pkh:  'Legacy (P2PKH)',
  p2sh:   'Script hash (P2SH)',
  p2wpkh: 'Native SegWit (P2WPKH)',
};

function activeAddress() {
  return state[state.walletType];
}

function updateWalletTypeUI() {
  const type   = state.walletType;
  const label  = TYPE_LABELS[type];
  const addr   = activeAddress();

  // Update address badge
  const badge = $('addr-type-badge');
  badge.textContent = label.badge;
  badge.className   = `label-tag ${label.cls}`;

  // Update displayed address
  if (addr) {
    $('wallet-address').textContent = addr;
    state.address = addr;
  }

  // QR code for whichever address type is active
  const qrSection = $('qr-section');
  if (addr) {
    qrSection.classList.remove('hidden');
    renderQr(addr);
  } else {
    qrSection.classList.add('hidden');
  }

  // Update tab active state
  document.querySelectorAll('.wallet-type-tabs .tab').forEach(btn => {
    const active = btn.dataset.type === type;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', String(active));
  });

  // Open sidebar with step-1 info when type changes (desktop only)
  if (window.innerWidth >= 900) openSidebar(1);
}

function renderQr(text) {
  const container = $('qr-code');
  container.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    // Dark-on-white in both themes: some scanners can't read inverted codes.
    new QRCode(container, {
      text,
      width: 180,
      height: 180,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M,
    });
  }
}

// ── Wallet type tab clicks ────────────────────────────────────────────────────
document.querySelectorAll('.wallet-type-tabs .tab').forEach(btn => {
  btn.addEventListener('click', () => {
    // Coins are already being received at the chosen address; switching type
    // now would sign for an address the coins don't belong to.
    if (!$('step-2').classList.contains('locked') && btn.dataset.type !== state.walletType) {
      showToast('Wallet type is fixed once you start receiving. Use "Reset lab" to start over.');
      return;
    }
    state.walletType = btn.dataset.type;
    updateWalletTypeUI();
    updateFeeEstimate();
    if (state.wif) {
      const saved = loadWallet();
      if (saved) { saved.wallet_type = state.walletType; saveWallet(saved); }
    }
  });
});

// ── localStorage persistence ──────────────────────────────────────────────────
const STORAGE_KEY = 'bitcoin_wallet_lab';

function saveWallet(w) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(w)); } catch { /* storage unavailable */ }
}

function loadWallet() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved ? JSON.parse(saved) : null;
  } catch { return null; }
}

function showWallet(w) {
  state.wif         = w.wif;
  state.pubkeyHex   = w.pubkey_hex;
  state.p2pkh       = w.p2pkh;
  state.p2sh_p2wpkh = w.p2sh_p2wpkh;
  state.p2wpkh      = w.p2wpkh;
  state.address     = activeAddress() || w.p2pkh;

  $('wallet-wif').textContent    = w.wif;
  $('wallet-pubkey').textContent = w.pubkey_hex;
  $('addr-p2pkh').textContent    = w.p2pkh;
  $('addr-p2sh').textContent     = w.p2sh_p2wpkh || '—';
  $('addr-p2wpkh').textContent   = w.p2wpkh || '—';

  $('wallet-result').classList.remove('hidden');
  $('btn-to-step2').classList.remove('hidden');
  $('btn-generate').textContent = 'Regenerate';

  updateWalletTypeUI();
}

function restoreWalletUI(w) {
  // Handle old localStorage format (had only `address`, not the three typed keys)
  state.walletType = w.wallet_type || 'p2pkh';
  showWallet({ ...w, p2pkh: w.p2pkh || w.address || '' });
}

// ── Lab Wallet ────────────────────────────────────────────────────────────────
async function loadLabInfo() {
  try {
    const info = await apiFetch('/lab/info');
    if (info.address) state.labAddress = info.address;
  } catch { /* lab wallet not configured */ }
}
loadLabInfo();

// ── Info Sidebar ──────────────────────────────────────────────────────────────
const SIDEBAR_TITLES = {
  1: 'Wallet Types & Keys',
  2: 'UTXOs & Receiving',
  3: 'Transactions',
  4: 'Blocks & Confirmations',
  5: 'Signature Malleability',
};

function openSidebar(step) {
  const sidebar  = $('info-sidebar');
  const title    = $('sidebar-title');
  const content  = $('sidebar-content');
  const template = document.getElementById(`info-step-${step}`);
  if (!template) return;

  if (state.activeSidebarStep === step && sidebar.classList.contains('visible')) {
    closeSidebar(); return;
  }

  title.textContent = SIDEBAR_TITLES[step] || 'Learn';
  content.innerHTML = '';
  content.appendChild(template.content.cloneNode(true));
  sidebar.classList.add('visible');
  state.activeSidebarStep = step;

  document.querySelectorAll('.btn-info').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-expanded', 'false');
  });
  const btn = document.querySelector(`.btn-info[data-step="${step}"]`);
  if (btn) {
    btn.classList.add('active');
    btn.setAttribute('aria-expanded', 'true');
  }

  if (window.innerWidth < 900) {
    $('sidebar-backdrop').classList.add('visible');
    $('btn-sidebar-close').focus();
  }
}

function closeSidebar() {
  $('info-sidebar').classList.remove('visible');
  $('sidebar-backdrop').classList.remove('visible');
  state.activeSidebarStep = null;
  document.querySelectorAll('.btn-info').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-expanded', 'false');
  });
}

document.querySelectorAll('.btn-info').forEach(btn => {
  btn.addEventListener('click', () => openSidebar(parseInt(btn.dataset.step, 10)));
});
$('btn-sidebar-close').addEventListener('click', closeSidebar);
$('sidebar-backdrop').addEventListener('click', closeSidebar);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && $('info-sidebar').classList.contains('visible')) closeSidebar();
});

window.addEventListener('DOMContentLoaded', () => {
  if (window.innerWidth >= 900) {
    const activeSteps = [...document.querySelectorAll('.step.active')];
    if (activeSteps.length > 0) {
      const last = activeSteps[activeSteps.length - 1];
      openSidebar(parseInt(last.dataset.step, 10));
    }
  }
});

// ── Step 1: Create Wallet ─────────────────────────────────────────────────────
$('btn-generate').addEventListener('click', async () => {
  const btn = $('btn-generate');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  try {
    const w = await apiFetch('/wallet/create', { method: 'POST', body: '{}' });
    showWallet(w);
    btn.disabled = false;

    saveWallet({
      wif: w.wif, pubkey_hex: w.pubkey_hex,
      p2pkh: w.p2pkh, p2sh_p2wpkh: w.p2sh_p2wpkh, p2wpkh: w.p2wpkh,
      wallet_type: state.walletType,
    });
  } catch (e) {
    showToast(e.message);
    btn.textContent = state.p2pkh ? 'Regenerate' : 'Generate Wallet';
    btn.disabled = false;
  }
});

// WIF show/hide toggle
document.querySelectorAll('.btn-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = $(btn.dataset.target);
    const isBlurred = target.classList.contains('blurred');
    target.classList.toggle('blurred', !isBlurred);
    target.classList.toggle('revealed', isBlurred);
    btn.textContent = isBlurred ? 'Hide' : 'Show';
    btn.setAttribute('aria-pressed', String(isBlurred));
  });
});

$('toggle-pubkey').addEventListener('click', () => {
  const el = $('wallet-pubkey');
  el.classList.toggle('hidden');
  $('toggle-pubkey').textContent = el.classList.contains('hidden') ? 'show' : 'hide';
});

// Download the key as a text backup
$('btn-export-key').addEventListener('click', () => {
  if (!state.wif) return;
  const text = [
    'Bitcoin Wallet Lab — TESTNET4 key backup',
    'Testnet only. Never use this key on mainnet.',
    '',
    `WIF private key: ${state.wif}`,
    `Public key:      ${state.pubkeyHex}`,
    `P2PKH:           ${state.p2pkh}`,
    `P2SH-P2WPKH:     ${state.p2sh_p2wpkh}`,
    `P2WPKH:          ${state.p2wpkh}`,
    '',
  ].join('\n');
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'wallet-lab-testnet-key.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

document.addEventListener('click', e => {
  if (e.target.classList.contains('btn-copy')) copyToClipboard(e.target.dataset.target);
});

// Advance to step 2
$('btn-to-step2').addEventListener('click', () => {
  const addr = activeAddress();
  state.address = addr;
  $('receive-address').textContent = addr;
  const label = TYPE_LABELS[state.walletType];
  $('step2-type-label').textContent = label.name;
  $('step2-addr-label').textContent = `${label.badge} Address`;
  unlockStep(2);
  startUtxoPolling();
});

// ── Step 2: Receive Coins ─────────────────────────────────────────────────────
function startUtxoPolling() {
  clearInterval(state.utxoPollInterval);
  pollUtxos();
  state.utxoPollInterval = setInterval(pollUtxos, 5000);
}

async function pollUtxos() {
  if (!state.address) return;
  try {
    const utxos = await apiFetch(`/utxo/${encodeURIComponent(state.address)}`);
    state.utxos = utxos;
    renderUtxoTable(utxos);
    const hasConfirmed = utxos.some(u => u.status?.confirmed);
    if (hasConfirmed && state.utxoPollInterval) {
      clearInterval(state.utxoPollInterval);
      state.utxoPollInterval = null;
      const status = $('utxo-polling-status');
      status.style.display = '';
      status.innerHTML = '<span style="color:var(--green)">✓ Coins received!</span>';
      $('btn-to-step3').classList.remove('hidden');
    }
  } catch { /* silently retry */ }
}

function renderUtxoTable(utxos) {
  if (utxos.length === 0) return;
  $('utxo-polling-status').style.display = utxos.some(u => u.status?.confirmed) ? '' : 'none';
  $('utxo-table').classList.remove('hidden');
  const tbody = $('utxo-tbody');
  tbody.innerHTML = '';
  utxos.forEach(u => {
    const confirmed = u.status?.confirmed;
    const blockHeight = u.status?.block_height;
    const txid = escapeHtml(u.txid);
    const statusCell = confirmed
      ? `<span class="status-badge status-confirmed">&#10003; Confirmed</span><br><small class="status-detail">Block #${escapeHtml(blockHeight)}</small>`
      : `<span class="status-badge status-pending"><span class="spinner-small"></span> Pending</span><br><small class="status-detail">In mempool — not yet in a block</small>`;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><a href="https://mempool.space/testnet4/tx/${txid}" target="_blank" rel="noopener">${txid.slice(0,10)}…${txid.slice(-6)}</a></td>
      <td>#${escapeHtml(u.vout)}</td>
      <td>${fmt(u.value)}</td>
      <td>${statusCell}</td>
    `;
    tbody.appendChild(tr);
  });

  const hasPending = utxos.some(u => !u.status?.confirmed);
  $('utxo-status-legend').classList.toggle('hidden', !hasPending);
}

// Advance to step 3
$('btn-to-step3').addEventListener('click', () => {
  const confirmedUtxos = state.utxos.filter(u => u.status?.confirmed);
  if (confirmedUtxos.length === 0) { showToast('No confirmed UTXOs yet.'); return; }
  state.selected = new Set(confirmedUtxos.map(utxoKey));
  renderCoinTable();
  if (state.labAddress && !$('recipient').value) {
    $('recipient').value = state.labAddress;
    $('lab-wallet-notice').classList.remove('hidden');
    validateRecipient();
  }
  unlockStep(3);
  loadFeeRates();
  updateFeeEstimate();
});

// ── Step 3: Coin control ──────────────────────────────────────────────────────
function selectedUtxos() {
  return state.utxos.filter(u => u.status?.confirmed && state.selected.has(utxoKey(u)));
}

function renderCoinTable() {
  const tbody = $('coin-tbody');
  tbody.innerHTML = '';
  state.utxos.forEach((u, i) => {
    const key = utxoKey(u);
    const confirmed = u.status?.confirmed;
    const id = `coin-${i}`;
    const txid = escapeHtml(u.txid);
    const tr = document.createElement('tr');
    if (!confirmed) tr.className = 'unconfirmed';
    tr.innerHTML = `
      <td><input type="checkbox" id="${id}" data-key="${escapeHtml(key)}" ${state.selected.has(key) ? 'checked' : ''} ${confirmed ? '' : 'disabled'} /></td>
      <td><label for="${id}">${txid.slice(0,10)}…${txid.slice(-6)}:${escapeHtml(u.vout)}</label>${confirmed ? '' : ' <small class="status-detail">pending — wait for a block</small>'}</td>
      <td>${fmt(u.value)}</td>
    `;
    tbody.appendChild(tr);
  });
  updateFeeEstimate();
}

$('coin-tbody').addEventListener('change', e => {
  if (e.target.type !== 'checkbox') return;
  const key = e.target.dataset.key;
  e.target.checked ? state.selected.add(key) : state.selected.delete(key);
  updateFeeEstimate();
});

$('btn-select-all').addEventListener('click', () => {
  const confirmed = state.utxos.filter(u => u.status?.confirmed).map(utxoKey);
  const allSelected = confirmed.every(k => state.selected.has(k));
  state.selected = allSelected ? new Set() : new Set(confirmed);
  renderCoinTable();
});

$('btn-refresh-utxos').addEventListener('click', async () => {
  const btn = $('btn-refresh-utxos');
  btn.disabled = true;
  try {
    const utxos = await apiFetch(`/utxo/${encodeURIComponent(state.address)}`);
    const known = new Set(state.utxos.map(utxoKey));
    state.utxos = utxos;
    // Keep the user's choices; select newly confirmed coins by default.
    const live = new Set(utxos.filter(u => u.status?.confirmed).map(utxoKey));
    state.selected = new Set([...state.selected].filter(k => live.has(k)));
    live.forEach(k => { if (!known.has(k)) state.selected.add(k); });
    renderCoinTable();
    showToast('UTXOs refreshed', 'success');
  } catch (e) {
    showToast(e.message);
  } finally {
    btn.disabled = false;
  }
});

// ── Step 3: Recipient validation ──────────────────────────────────────────────
let recipientTimer = null;
let recipientSeq = 0;

async function validateRecipient() {
  const addr = $('recipient').value.trim();
  const hint = $('recipient-hint');
  const input = $('recipient');
  const seq = ++recipientSeq;
  if (!addr) {
    state.recipient = null;
    hint.textContent = '';
    hint.className = 'input-hint';
    input.classList.remove('invalid');
    input.removeAttribute('aria-invalid');
    updateFeeEstimate();
    return;
  }
  try {
    const info = await apiFetch(`/address/${encodeURIComponent(addr)}/validate`);
    if (seq !== recipientSeq) return; // a newer keystroke won
    state.recipient = info;
    if (info.valid) {
      hint.textContent = `✓ ${KIND_LABELS[info.kind]} · testnet · dust limit ${fmt(info.dust_limit)} sat`;
      hint.className = 'input-hint ok';
      input.classList.remove('invalid');
      input.removeAttribute('aria-invalid');
    } else {
      hint.textContent = `✗ ${info.error || 'Invalid address'}`;
      hint.className = 'input-hint bad';
      input.classList.add('invalid');
      input.setAttribute('aria-invalid', 'true');
    }
  } catch {
    if (seq !== recipientSeq) return;
    state.recipient = null;
    hint.textContent = 'Could not check the address right now.';
    hint.className = 'input-hint';
  }
  updateFeeEstimate();
}

$('recipient').addEventListener('input', () => {
  $('lab-wallet-notice').classList.toggle('hidden', $('recipient').value.trim() !== state.labAddress);
  clearTimeout(recipientTimer);
  recipientTimer = setTimeout(validateRecipient, 300);
});

// ── Step 3: Fee rates ─────────────────────────────────────────────────────────
const FEE_PRESETS = [
  { key: 'economyFee',   label: 'Economy' },
  { key: 'hourFee',      label: '~1 hour' },
  { key: 'halfHourFee',  label: '~30 min' },
  { key: 'fastestFee',   label: 'Next block' },
];
// Keep at 1 sat/vB: some testnet4 nodes still enforce the old minimum relay fee.
const MIN_FEE_RATE = 1;

async function loadFeeRates() {
  const box = $('fee-presets');
  const status = $('fee-presets-status');
  try {
    const rates = await apiFetch('/fees');
    state.feeRates = rates;
    status.remove();
    box.querySelectorAll('.fee-preset').forEach(b => b.remove());
    FEE_PRESETS.forEach(p => {
      const rate = Math.max(MIN_FEE_RATE, rates[p.key]);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'fee-preset';
      btn.dataset.rate = rate;
      btn.innerHTML = `${p.label}<small>${rate} sat/vB</small>`;
      btn.addEventListener('click', () => {
        $('fee-rate').value = rate;
        updateFeeEstimate();
      });
      box.appendChild(btn);
    });
    updateFeeEstimate();
  } catch {
    status.textContent = 'unavailable — enter a rate manually';
  }
}

$('fee-rate').addEventListener('input', updateFeeEstimate);
$('amount').addEventListener('input', updateFeeEstimate);

// ── Step 3: Size & fee estimation ─────────────────────────────────────────────
// Weight units per input, by the type of the coin being spent. Assumes a
// 72-byte DER signature + sighash byte and a 33-byte compressed pubkey.
//   P2PKH:       (32+4+1+107+4) × 4                   = 592
//   P2SH-P2WPKH: (32+4+1+23+4) × 4 + 108 witness      = 364
//   P2WPKH:      (32+4+1+4) × 4 + 108 witness         = 272
const INPUT_WEIGHT = { p2pkh: 592, p2sh_p2wpkh: 364, p2wpkh: 272 };
// Output size in bytes: 8 amount + 1 script length + script
const OUTPUT_BYTES = { p2pkh: 34, p2sh: 32, p2wpkh: 31 };
// Bitcoin Core's default dust thresholds
const DUST = { p2pkh: 546, p2sh: 540, p2wpkh: 294 };
// Change goes back to the wallet's own address type
const CHANGE_KIND = { p2pkh: 'p2pkh', p2sh_p2wpkh: 'p2sh', p2wpkh: 'p2wpkh' };

function estimateVbytes(nInputs, outputKinds) {
  const segwit = state.walletType !== 'p2pkh';
  // version + input count + output count + locktime, plus marker/flag for SegWit
  let weight = (4 + 1 + 1 + 4) * 4 + (segwit ? 2 : 0);
  weight += nInputs * INPUT_WEIGHT[state.walletType];
  weight += outputKinds.reduce((sum, k) => sum + OUTPUT_BYTES[k] * 4, 0);
  return Math.ceil(weight / 4);
}

/// Work out the transaction the form describes. Mirrors the server's dust rule.
function computePlan() {
  const inputs = selectedUtxos();
  const total = inputs.reduce((s, u) => s + u.value, 0);
  const rate = parseFloat($('fee-rate').value);
  const amount = parseInt($('amount').value, 10);
  const changeKind = CHANGE_KIND[state.walletType];
  const recipKind = state.recipient?.valid ? state.recipient.kind : changeKind;

  const plan = { inputs, total, rate, amount, ok: false, error: null };
  if (!(rate >= MIN_FEE_RATE)) {
    plan.error = `Fee rate must be at least ${MIN_FEE_RATE} sat/vB.`;
    return plan;
  }

  const vNoChange = estimateVbytes(inputs.length, [recipKind]);
  const feeNoChange = Math.ceil(rate * vNoChange);
  plan.maxAmount = total - feeNoChange;

  const vWithChange = estimateVbytes(inputs.length, [recipKind, changeKind]);
  const feeWithChange = Math.ceil(rate * vWithChange);
  Object.assign(plan, { vbytes: vWithChange, fee: feeWithChange, change: null });

  if (inputs.length === 0) { plan.error = 'Select at least one coin to spend.'; return plan; }
  if (!(amount > 0)) return plan;
  if (amount < DUST[recipKind]) {
    plan.error = `Amount is below the ${DUST[recipKind]} sat dust limit for this address type.`;
    return plan;
  }

  const change = total - amount - feeWithChange;
  if (change >= DUST[changeKind]) {
    Object.assign(plan, { ok: true, change, dustToFee: 0 });
    return plan;
  }

  // Change would be dust: drop the change output and let the leftover go to the miner.
  const leftover = total - amount - feeNoChange;
  if (leftover < 0) {
    plan.error = `Not enough funds: need ${fmt(amount + feeNoChange)} sat, selected ${fmt(total)} sat.`;
    Object.assign(plan, { vbytes: vNoChange, fee: feeNoChange });
    return plan;
  }
  Object.assign(plan, {
    ok: true, vbytes: vNoChange, fee: feeNoChange + leftover, change: 0, dustToFee: leftover,
  });
  return plan;
}

function updateFeeEstimate() {
  if ($('step-3').classList.contains('locked')) return;
  const plan = computePlan();

  $('balance-display').textContent = `${fmt(plan.total)} sat`;
  $('selected-count').textContent = `(${plan.inputs.length} of ${state.utxos.filter(u => u.status?.confirmed).length} coins)`;
  $('bd-input-count').textContent = plan.inputs.length;
  $('bd-inputs').textContent = `${fmt(plan.total)} sat`;
  $('bd-amount').textContent = plan.amount > 0 ? `${fmt(plan.amount)} sat` : '—';
  $('bd-rate').textContent = plan.rate >= MIN_FEE_RATE ? plan.rate : '—';
  $('est-vbytes').textContent = plan.vbytes ?? '—';
  $('est-fee').textContent = plan.fee != null ? `${fmt(plan.fee)} sat` : '—';
  $('bd-change').textContent = plan.change == null ? '—' : plan.change > 0 ? `${fmt(plan.change)} sat` : 'none';
  $('fee').value = plan.ok ? plan.fee : '';

  const note = $('bd-note');
  if (plan.error) {
    note.textContent = plan.error;
    note.className = 'bd-note bad';
  } else if (plan.ok && plan.dustToFee > 0) {
    note.textContent = `Change of ${fmt(plan.dustToFee)} sat would be dust, so no change output is created — it goes to the miner as extra fee.`;
    note.className = 'bd-note';
  } else {
    note.className = 'bd-note hidden';
  }

  document.querySelectorAll('.fee-preset').forEach(b => {
    b.classList.toggle('active', parseFloat(b.dataset.rate) === plan.rate);
  });

  $('btn-max').disabled = !(plan.maxAmount > 0);
  if (!$('btn-send').textContent.startsWith('Sent')) {
    $('btn-send').disabled = !plan.ok || state.recipient?.valid === false;
  }
}

$('btn-max').addEventListener('click', () => {
  const plan = computePlan();
  if (plan.maxAmount > 0) {
    $('amount').value = plan.maxAmount;
    updateFeeEstimate();
  }
});

// ── Step 3: Send Payment ──────────────────────────────────────────────────────
$('send-form').addEventListener('submit', async e => {
  e.preventDefault();
  const plan = computePlan();
  const recipient = $('recipient').value.trim();
  if (!recipient) { showToast('Enter a recipient address.'); return; }
  if (state.recipient?.valid === false) { showToast(state.recipient.error || 'Invalid recipient address.'); return; }
  if (!plan.ok) { showToast(plan.error || 'Enter an amount.'); return; }

  const btn = $('btn-send');
  btn.disabled = true;
  btn.textContent = 'Broadcasting...';

  const body = {
    wif: state.wif,
    inputs: plan.inputs.map(u => ({ txid: u.txid, vout: u.vout, value: u.value })),
    recipient_address: recipient,
    send_amount: plan.amount,
    fee: plan.fee,
    sender_address: state.address,
    wallet_type: state.walletType,
  };

  try {
    const result = await apiFetch('/tx/build-and-send', { method: 'POST', body: JSON.stringify(body) });
    state.txid     = result.txid;
    state.rawTxHex = result.raw_tx_hex;
    $('sent-txid').textContent    = result.txid;
    $('sent-raw-hex').textContent = result.raw_tx_hex;
    const segwit = result.wtxid && result.wtxid !== result.txid;
    $('sent-wtxid-field').classList.toggle('hidden', !segwit);
    $('sent-wtxid').textContent = segwit ? result.wtxid : '';
    $('sent-stats').innerHTML = [
      `Inputs: <strong>${fmt(result.input_count)}</strong>`,
      `Size: <strong>${fmt(result.vsize)} vB</strong> (${fmt(result.weight)} WU)`,
      `Fee: <strong>${fmt(result.fee)} sat</strong>`,
      `Rate: <strong>${result.fee_rate.toFixed(2)} sat/vB</strong>`,
      `Change: <strong>${result.change > 0 ? fmt(result.change) + ' sat' : 'none'}</strong>`,
    ].map(x => `<span>${x}</span>`).join('');
    $('tx-result').classList.remove('hidden');
    $('btn-to-step4').classList.remove('hidden');
    btn.textContent = 'Sent!';
  } catch (e) {
    showToast(e.message);
    btn.textContent = 'Build & Broadcast Transaction';
    btn.disabled = false;
  }
});

// Advance to step 4
$('btn-to-step4').addEventListener('click', () => {
  $('track-txid').textContent = state.txid;
  $('explorer-link').href = `https://mempool.space/testnet4/tx/${encodeURIComponent(state.txid)}`;
  setTimelineStage(1);
  unlockStep(4);
  startConfirmationPolling();
});

// ── Step 4: Track Confirmation ────────────────────────────────────────────────
const FINAL_CONFIRMATIONS = 6;
const TIMELINE_STAGES = ['broadcast', 'mempool', 'conf1', 'conf6'];

/// Mark stages before `activeIndex` done and highlight the active one.
function setTimelineStage(activeIndex) {
  document.querySelectorAll('#conf-timeline li').forEach(li => {
    const i = TIMELINE_STAGES.indexOf(li.dataset.stage);
    li.classList.toggle('done', i < activeIndex);
    li.classList.toggle('active', i === activeIndex);
  });
}

function startConfirmationPolling() {
  clearInterval(state.confPollInterval);
  pollConfirmation();
  state.confPollInterval = setInterval(pollConfirmation, 15000);
}

async function pollConfirmation() {
  if (!state.txid) return;
  try {
    const info      = await apiFetch(`/tx/${encodeURIComponent(state.txid)}/status`);
    const confirmed = info.status?.confirmed;
    const confs     = info.confirmations || 0;
    const tip       = info.tip_height;
    const badge = $('confirmation-status');
    const count = $('confirmation-count');
    if (confirmed) {
      badge.className   = 'conf-badge confirmed';
      badge.textContent = confs >= FINAL_CONFIRMATIONS ? 'Final' : 'Confirmed';
      count.textContent = `${fmt(confs)} confirmation${confs === 1 ? '' : 's'} · block #${fmt(info.status.block_height)}`
        + (tip ? ` · tip #${fmt(tip)}` : '');
      $('tl-conf1-detail').textContent = `Mined in block #${fmt(info.status.block_height)}`;
      if (confs >= FINAL_CONFIRMATIONS) {
        setTimelineStage(TIMELINE_STAGES.length); // all done
        $('tl-conf6-detail').textContent = 'Reached — reorgs this deep are practically impossible';
        $('conf-spinner').style.display = 'none';
        clearInterval(state.confPollInterval);
      } else {
        setTimelineStage(3);
        const left = FINAL_CONFIRMATIONS - confs;
        $('tl-conf6-detail').textContent = `${left} more block${left === 1 ? '' : 's'} to go (~${left * 10} min)`;
      }
    } else {
      badge.className   = 'conf-badge unconfirmed';
      badge.textContent = 'Unconfirmed';
      count.textContent = 'In the mempool, waiting for a block...' + (tip ? ` · tip #${fmt(tip)}` : '');
      setTimelineStage(2);
    }
  } catch { /* silently retry */ }
}

// ── Step 5: Malleability Demo ─────────────────────────────────────────────────
$('btn-to-step5').addEventListener('click', () => unlockStep(5));

$('btn-run-demo').addEventListener('click', async () => {
  const btn = $('btn-run-demo');
  btn.disabled = true;
  btn.textContent = 'Running...';
  try {
    const result = await apiFetch('/demo/malleability', {
      method: 'POST',
      body: JSON.stringify({ raw_tx_hex: state.rawTxHex }),
    });
    $('orig-txid').textContent  = result.original_txid;
    $('orig-wtxid').textContent = result.original_wtxid;
    $('orig-s').textContent     = result.original_s_hex;
    $('orig-der').textContent   = result.original_sig_der_hex;
    $('mall-txid').textContent  = result.malleable_txid;
    $('mall-wtxid').textContent = result.malleable_wtxid;
    $('mall-s').textContent     = result.malleable_s_hex;
    $('mall-der').textContent   = result.malleable_sig_der_hex;

    // SegWit: TXID stays put (green), WTXID changes. Legacy: TXID changes.
    document.querySelectorAll('.wtxid-row').forEach(el => el.classList.toggle('hidden', !result.segwit));
    $('mall-txid').classList.toggle('highlight-diff', result.txid_changed);
    $('mall-txid').classList.toggle('same-id', !result.txid_changed);
    $('verdict-headline').textContent = result.txid_changed
      ? 'Same coins moved. Same inputs and outputs. Two different TXIDs.'
      : 'Same coins moved. The signature changed — but the TXID did not.';
    $('verdict-explanation').textContent = result.explanation;

    $('demo-result').classList.remove('hidden');
    btn.textContent = 'Done';
    updateStepper();
  } catch (e) {
    showToast(e.message);
    btn.textContent = 'Run Demo';
    btn.disabled = false;
  }
});

// Restore last: restoring opens the sidebar, which needs everything above defined.
const savedWallet = loadWallet();
// Wrap in try-catch so a bad localStorage entry never breaks the page
try {
  if (savedWallet) restoreWalletUI(savedWallet);
} catch (e) {
  try { localStorage.removeItem(STORAGE_KEY); } catch { /* storage unavailable */ }
}

updateStepper();
