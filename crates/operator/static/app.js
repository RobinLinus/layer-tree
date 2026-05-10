// Layer Tree Wallet — BIP-340 Schnorr signing via @noble/secp256k1
import * as secp from 'https://esm.sh/@noble/secp256k1@2.1.0';

const API = '';  // Same origin

// --- Crypto Helpers ---

async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

function uint64LE(n) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(n), true);
  return new Uint8Array(buf);
}

function concat(...arrays) {
  const result = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0));
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

const textEncode = s => new TextEncoder().encode(s);

// --- Signing (matches auth.rs exactly) ---
// Transfer:   SHA256(to_pubkey_hex_ascii || amount_le8 || nonce_le8)
// Withdrawal: SHA256(dest_address_ascii  || amount_le8 || nonce_le8)

async function signTransfer(secret, toHex, amount, nonce) {
  const msg = concat(textEncode(toHex), uint64LE(amount), uint64LE(nonce));
  const hash = await sha256(msg);
  return bytesToHex(secp.schnorr.sign(hash, secret));
}

async function signWithdrawal(secret, destAddress, amount, nonce) {
  const msg = concat(textEncode(destAddress), uint64LE(amount), uint64LE(nonce));
  const hash = await sha256(msg);
  return bytesToHex(secp.schnorr.sign(hash, secret));
}

// --- Key Management (localStorage) ---

function getKeypair() {
  const stored = localStorage.getItem('layer_tree_keypair');
  if (!stored) return null;
  const parsed = JSON.parse(stored);
  return { secret: hexToBytes(parsed.secret), pubkey: parsed.pubkey };
}

function generateKeypair() {
  const secret = secp.utils.randomPrivateKey();
  const pubkey = bytesToHex(secp.schnorr.getPublicKey(secret));
  localStorage.setItem('layer_tree_keypair', JSON.stringify({
    secret: bytesToHex(secret),
    pubkey,
  }));
  return { secret, pubkey };
}

// --- Nonce Management ---

let nextNonce = Date.now();
function getNextNonce() { return nextNonce++; }

// --- API Helpers ---

async function apiGet(path) {
  return (await fetch(API + path)).json();
}

async function apiPost(path, body) {
  return (await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })).json();
}

// --- UI Helpers ---

function showSections() {
  for (const id of ['dashboard-section', 'send-section', 'deposit-section', 'withdraw-section']) {
    document.getElementById(id).style.display = '';
  }
}

async function refreshBalance() {
  const kp = getKeypair();
  if (!kp) return;
  const data = await apiGet(`/api/balance/${kp.pubkey}`);
  document.getElementById('balance-amount').textContent = data.balance_sats || 0;
}

async function loadInfo() {
  try {
    const info = await apiGet('/api/info');
    document.getElementById('operator-info').textContent = JSON.stringify(info, null, 2);
    document.getElementById('status').textContent = `Connected (${info.chain})`;
    document.getElementById('status').className = 'status connected';
  } catch {
    document.getElementById('operator-info').textContent = 'Failed to connect';
    document.getElementById('status').textContent = 'Disconnected';
    document.getElementById('status').className = 'status disconnected';
  }
}

function showResult(id, result) {
  const el = document.getElementById(id);
  el.className = (result.status === 'ok' || result.status === 'pending') ? 'result success' : 'result error';
  el.textContent = result.message || JSON.stringify(result);
}

// --- Init (modules are deferred, DOM is ready) ---

const kp = getKeypair();
if (kp) {
  document.getElementById('no-key').style.display = 'none';
  document.getElementById('has-key').style.display = '';
  document.getElementById('pubkey-display').textContent = kp.pubkey;
  showSections();
  refreshBalance();
}

document.getElementById('generate-key-btn').addEventListener('click', () => {
  const kp = generateKeypair();
  document.getElementById('no-key').style.display = 'none';
  document.getElementById('has-key').style.display = '';
  document.getElementById('pubkey-display').textContent = kp.pubkey;
  showSections();
});

document.getElementById('refresh-balance-btn').addEventListener('click', refreshBalance);

document.getElementById('send-btn').addEventListener('click', async () => {
  const kp = getKeypair();
  const to = document.getElementById('send-to').value.trim();
  const amount = parseInt(document.getElementById('send-amount').value);
  if (!to || !amount) {
    return showResult('send-result', { status: 'error', message: 'Fill in all fields' });
  }
  const nonce = getNextNonce();
  const signature = await signTransfer(kp.secret, to, amount, nonce);
  const result = await apiPost('/api/transfer', {
    from: kp.pubkey, to, amount_sats: amount, nonce, signature,
  });
  showResult('send-result', result);
  if (result.status === 'pending') refreshBalance();
});

document.getElementById('deposit-btn').addEventListener('click', async () => {
  const kp = getKeypair();
  const outpoint = document.getElementById('deposit-outpoint').value.trim();
  const amount = parseInt(document.getElementById('deposit-amount').value);
  if (!outpoint || !amount) {
    return showResult('deposit-result', { status: 'error', message: 'Fill in all fields' });
  }
  const result = await apiPost('/api/deposit', {
    pubkey: kp.pubkey, outpoint, amount_sats: amount,
  });
  showResult('deposit-result', result);
});

document.getElementById('withdraw-btn').addEventListener('click', async () => {
  const kp = getKeypair();
  const dest = document.getElementById('withdraw-address').value.trim();
  const amount = parseInt(document.getElementById('withdraw-amount').value);
  if (!dest || !amount) {
    return showResult('withdraw-result', { status: 'error', message: 'Fill in all fields' });
  }
  const nonce = getNextNonce();
  const signature = await signWithdrawal(kp.secret, dest, amount, nonce);
  const result = await apiPost('/api/withdrawal', {
    pubkey: kp.pubkey, amount_sats: amount, dest_address: dest, nonce, signature,
  });
  showResult('withdraw-result', result);
  if (result.status === 'pending') refreshBalance();
});

loadInfo();
setInterval(refreshBalance, 10000);
