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
  selectedUtxo: null,
  txid: null,
  rawTxHex: null,
  utxoPollInterval: null,
  confPollInterval: null,
  labAddress: null,
  activeSidebarStep: null,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function showToast(msg, type = 'error') {
  const t = $('toast');
  t.textContent = msg;
  t.className = `toast ${type}`;
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 4000);
}

function unlockStep(n) {
  const el = document.getElementById(`step-${n}`);
  el.classList.remove('locked');
  el.classList.add('active');
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (window.innerWidth >= 900) openSidebar(n);
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

// ── Wallet type helpers ───────────────────────────────────────────────────────
const TYPE_LABELS = {
  p2pkh:       { name: 'Legacy P2PKH',       badge: 'P2PKH',      cls: 'p2pkh'  },
  p2sh_p2wpkh: { name: 'Nested SegWit',      badge: 'P2SH-P2WPKH', cls: 'nested' },
  p2wpkh:      { name: 'Native SegWit',      badge: 'P2WPKH',     cls: 'native' },
};

function activeAddress() {
  return state[state.walletType === 'p2sh_p2wpkh' ? 'p2sh_p2wpkh' : state.walletType];
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

  // Show QR code only for native SegWit
  const qrSection = $('qr-section');
  if (type === 'p2wpkh' && addr) {
    qrSection.classList.remove('hidden');
    renderQr(addr);
  } else {
    qrSection.classList.add('hidden');
  }

  // Update tab active state
  document.querySelectorAll('.wallet-type-tabs .tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.type === type);
  });

  // Open sidebar with step-1 info when type changes (desktop only)
  if (window.innerWidth >= 900) openSidebar(1);
}

function renderQr(text) {
  const container = $('qr-code');
  container.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(container, {
      text,
      width: 180,
      height: 180,
      colorDark: '#e2e8f0',
      colorLight: '#0d0f18',
      correctLevel: QRCode.CorrectLevel.M,
    });
  }
}

// ── Wallet type tab clicks ────────────────────────────────────────────────────
document.querySelectorAll('.wallet-type-tabs .tab').forEach(btn => {
  btn.addEventListener('click', () => {
    state.walletType = btn.dataset.type;
    updateWalletTypeUI();
  });
});

// ── localStorage persistence ──────────────────────────────────────────────────
const STORAGE_KEY = 'bitcoin_wallet_lab';

function saveWallet(w) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(w));
}

function loadWallet() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved ? JSON.parse(saved) : null;
  } catch { return null; }
}

function restoreWalletUI(w) {
  // Handle old localStorage format (had only `address`, not the three typed keys)
  const p2pkh = w.p2pkh || w.address || '';

  state.wif         = w.wif;
  state.pubkeyHex   = w.pubkey_hex;
  state.p2pkh       = p2pkh;
  state.p2sh_p2wpkh = w.p2sh_p2wpkh || '';
  state.p2wpkh      = w.p2wpkh || '';
  state.walletType  = w.wallet_type || 'p2pkh';
  state.address     = activeAddress() || p2pkh;

  $('wallet-wif').textContent    = w.wif;
  $('wallet-pubkey').textContent = w.pubkey_hex;
  $('addr-p2pkh').textContent    = p2pkh;
  $('addr-p2sh').textContent     = w.p2sh_p2wpkh || '—';
  $('addr-p2wpkh').textContent   = w.p2wpkh || '—';

  $('wallet-result').classList.remove('hidden');
  $('btn-to-step2').classList.remove('hidden');
  $('btn-generate').textContent = 'Regenerate';

  updateWalletTypeUI();
}

const savedWallet = loadWallet();
// Wrap in try-catch so a bad localStorage entry never blocks event listener registration
try {
  if (savedWallet) restoreWalletUI(savedWallet);
} catch (e) {
  localStorage.removeItem(STORAGE_KEY); // clear corrupted data
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

  document.querySelectorAll('.btn-info').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector(`.btn-info[data-step="${step}"]`);
  if (btn) btn.classList.add('active');

  if (window.innerWidth < 900) {
    $('sidebar-backdrop').classList.add('visible');
  }
}

function closeSidebar() {
  $('info-sidebar').classList.remove('visible');
  $('sidebar-backdrop').classList.remove('visible');
  state.activeSidebarStep = null;
  document.querySelectorAll('.btn-info').forEach(b => b.classList.remove('active'));
}

document.querySelectorAll('.btn-info').forEach(btn => {
  btn.addEventListener('click', () => openSidebar(parseInt(btn.dataset.type || btn.dataset.step)));
});
$('btn-sidebar-close').addEventListener('click', closeSidebar);

$('sidebar-backdrop').addEventListener('click', closeSidebar);

window.addEventListener('DOMContentLoaded', () => {
  if (window.innerWidth >= 900) {
    const activeSteps = [...document.querySelectorAll('.step.active')];
    if (activeSteps.length > 0) {
      const last = activeSteps[activeSteps.length - 1];
      openSidebar(parseInt(last.dataset.step));
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

    state.wif         = w.wif;
    state.pubkeyHex   = w.pubkey_hex;
    state.p2pkh       = w.p2pkh;
    state.p2sh_p2wpkh = w.p2sh_p2wpkh;
    state.p2wpkh      = w.p2wpkh;
    state.address     = activeAddress();

    $('wallet-wif').textContent    = w.wif;
    $('wallet-pubkey').textContent = w.pubkey_hex;
    $('addr-p2pkh').textContent    = w.p2pkh;
    $('addr-p2sh').textContent     = w.p2sh_p2wpkh;
    $('addr-p2wpkh').textContent   = w.p2wpkh;

    $('wallet-result').classList.remove('hidden');
    $('btn-to-step2').classList.remove('hidden');
    btn.textContent = 'Regenerate';
    btn.disabled = false;

    updateWalletTypeUI();

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
  });
});

$('toggle-pubkey').addEventListener('click', () => {
  const el = $('wallet-pubkey');
  el.classList.toggle('hidden');
  $('toggle-pubkey').textContent = el.classList.contains('hidden') ? 'show' : 'hide';
});

document.addEventListener('click', e => {
  if (e.target.classList.contains('btn-copy')) copyToClipboard(e.target.dataset.target);
});

// Save wallet_type when tab is switched and wallet exists
document.querySelectorAll('.wallet-type-tabs .tab').forEach(btn => {
  btn.addEventListener('click', () => {
    if (state.wif) {
      const saved = loadWallet();
      if (saved) { saved.wallet_type = state.walletType; saveWallet(saved); }
    }
  });
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
  pollUtxos();
  state.utxoPollInterval = setInterval(pollUtxos, 5000);
}

async function pollUtxos() {
  if (!state.address) return;
  try {
    const utxos = await apiFetch(`/utxo/${state.address}`);
    state.utxos = utxos;
    renderUtxoTable(utxos);
    const hasConfirmed = utxos.some(u => u.status?.confirmed);
    if (hasConfirmed && state.utxoPollInterval) {
      clearInterval(state.utxoPollInterval);
      state.utxoPollInterval = null;
      $('utxo-polling-status').innerHTML = '<span style="color:var(--green)">✓ Coins received!</span>';
      $('btn-to-step3').classList.remove('hidden');
    }
  } catch { /* silently retry */ }
}

function renderUtxoTable(utxos) {
  if (utxos.length === 0) return;
  $('utxo-polling-status').style.display = 'none';
  $('utxo-table').classList.remove('hidden');
  const tbody = $('utxo-tbody');
  tbody.innerHTML = '';
  utxos.forEach(u => {
    const confirmed = u.status?.confirmed;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${u.txid.slice(0,12)}...${u.txid.slice(-8)}</td>
      <td>#${u.vout}</td>
      <td>${u.value.toLocaleString()}</td>
      <td class="${confirmed ? 'confirmed-yes' : 'confirmed-no'}">${confirmed ? 'Confirmed' : 'Pending'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Advance to step 3
$('btn-to-step3').addEventListener('click', () => {
  const confirmedUtxos = state.utxos.filter(u => u.status?.confirmed);
  if (confirmedUtxos.length === 0) { showToast('No confirmed UTXOs yet.'); return; }
  state.selectedUtxo = confirmedUtxos[0];
  const balance = confirmedUtxos.reduce((sum, u) => sum + u.value, 0);
  $('balance-display').textContent = `${balance.toLocaleString()} sat`;
  if (state.labAddress) {
    $('recipient').value = state.labAddress;
    $('lab-wallet-notice').classList.remove('hidden');
  }
  unlockStep(3);
});

// ── Step 3: Send Payment ──────────────────────────────────────────────────────
$('send-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('btn-send');
  btn.disabled = true;
  btn.textContent = 'Broadcasting...';

  const utxo = state.selectedUtxo;
  const body = {
    wif: state.wif,
    utxo_txid: utxo.txid,
    utxo_vout: utxo.vout,
    utxo_value: utxo.value,
    recipient_address: $('recipient').value.trim(),
    send_amount: parseInt($('amount').value, 10),
    fee: parseInt($('fee').value, 10),
    sender_address: state.address,
    wallet_type: state.walletType,
  };

  try {
    const result = await apiFetch('/tx/build-and-send', { method: 'POST', body: JSON.stringify(body) });
    state.txid     = result.txid;
    state.rawTxHex = result.raw_tx_hex;
    $('sent-txid').textContent    = result.txid;
    $('sent-raw-hex').textContent = result.raw_tx_hex;
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
  $('explorer-link').href = `https://mempool.space/testnet4/tx/${state.txid}`;
  unlockStep(4);
  startConfirmationPolling();
});

// ── Step 4: Track Confirmation ────────────────────────────────────────────────
function startConfirmationPolling() {
  pollConfirmation();
  state.confPollInterval = setInterval(pollConfirmation, 10000);
}

async function pollConfirmation() {
  if (!state.txid) return;
  try {
    const info      = await apiFetch(`/tx/${state.txid}/status`);
    const confirmed = info.status?.confirmed;
    const badge = $('confirmation-status');
    const count = $('confirmation-count');
    if (confirmed) {
      badge.className   = 'conf-badge confirmed';
      badge.textContent = 'Confirmed';
      count.textContent = `Block ${info.status.block_height}`;
      $('conf-spinner').style.display = 'none';
      clearInterval(state.confPollInterval);
    } else {
      badge.className   = 'conf-badge unconfirmed';
      badge.textContent = 'Unconfirmed';
      count.textContent = 'Waiting for block...';
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
    $('orig-txid').textContent = result.original_txid;
    $('orig-s').textContent    = result.original_s_hex;
    $('orig-der').textContent  = result.original_sig_der_hex;
    $('mall-txid').textContent = result.malleable_txid;
    $('mall-s').textContent    = result.malleable_s_hex;
    $('mall-der').textContent  = result.malleable_sig_der_hex;
    $('demo-result').classList.remove('hidden');
    btn.textContent = 'Done';
  } catch (e) {
    showToast(e.message);
    btn.textContent = 'Run Demo';
    btn.disabled = false;
  }
});
