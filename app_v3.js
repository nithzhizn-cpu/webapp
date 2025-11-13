// Simple IndexedDB wrapper to store private key JWK
const DB_NAME = 'secure_messenger_keys';
const STORE = 'keys_v1';

function idbPut(key, value) {
  return new Promise((res, rej) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => { open.result.createObjectStore(STORE); };
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => { res(true); db.close(); };
      tx.onerror = (e) => rej(e);
    };
    open.onerror = (e) => rej(e);
  });
}
function idbGet(key) {
  return new Promise((res, rej) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => { open.result.createObjectStore(STORE); };
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => { res(req.result); db.close(); };
      req.onerror = (e) => rej(e);
    };
    open.onerror = (e) => rej(e);
  });
}

async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey({name:"RSA-OAEP", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"}, true, ["encrypt","decrypt"]);
  const pub = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const priv = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
  // store private JWK in IndexedDB
  await idbPut('privateKey', priv);
  // return public PEM as base64 PEM string
  const b64 = arrayBufferToBase64(pub);
  const pem = '-----BEGIN PUBLIC KEY-----\\n' + chunkString(b64,64).join('\\n') + '\\n-----END PUBLIC KEY-----';
  return pem;
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i=0;i<bytes.byteLength;i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function chunkString(str, length) {
  const arr = [];
  for (let i=0;i<str.length;i+=length) arr.push(str.slice(i,i+length));
  return arr;
}

async function importPublicKeyFromPem(pem) {
  const b64 = pem.replace(/-----.*-----/g,"").replace(/\s+/g,'');
  const ab = base64ToArrayBuffer(b64);
  return await window.crypto.subtle.importKey("spki", ab, {name:"RSA-OAEP", hash:"SHA-256"}, true, ["encrypt"]);
}

async function encryptForRecipient(recipientPubPem, plaintext) {
  const recipientPub = await importPublicKeyFromPem(recipientPubPem);
  // generate AES key
  const aesKey = await window.crypto.subtle.generateKey({name:"AES-GCM", length:128}, true, ["encrypt","decrypt"]);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = await window.crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, new TextEncoder().encode(plaintext));
  // export aes key raw and encrypt it with recipient RSA pub
  const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
  const encKey = await window.crypto.subtle.encrypt({name:"RSA-OAEP"}, recipientPub, rawAes);
  return {
    enc_key_b64: arrayBufferToBase64(encKey),
    nonce_b64: arrayBufferToBase64(iv),
    ciphertext_b64: arrayBufferToBase64(enc)
  };
}

async function decryptOwnMessage(enc_key_b64, nonce_b64, ciphertext_b64) {
  // load private JWK from IDB and import
  const jwk = await idbGet('privateKey');
  if (!jwk) throw new Error('No private key stored');
  const priv = await window.crypto.subtle.importKey('jwk', jwk, {name:"RSA-OAEP", hash:"SHA-256"}, true, ['decrypt']);
  const encKey = base64ToArrayBuffer(enc_key_b64);
  const rawAes = await window.crypto.subtle.decrypt({name:"RSA-OAEP"}, priv, encKey);
  const aesKey = await window.crypto.subtle.importKey('raw', rawAes, {name:"AES-GCM"}, true, ['decrypt']);
  const iv = base64ToArrayBuffer(nonce_b64);
  const ct = base64ToArrayBuffer(ciphertext_b64);
  const pt = await window.crypto.subtle.decrypt({name:"AES-GCM", iv:new Uint8Array(iv)}, aesKey, ct);
  return new TextDecoder().decode(pt);
}

// UI and network
async function registerPublicKeyOnServer(publicPem) {
  const res = await fetch('/api/register_key', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user_id: parseInt(window._SM_USER_ID||0), username: window._SM_USERNAME||'guest', public_pem: publicPem})});
  return res.json();
}

async function sendMessageModeA(recipientId, plaintext) {
  // fetch recipient public key
  const r = await fetch('/api/get_public_key?user_id=' + encodeURIComponent(recipientId));
  const jd = await r.json();
  if (!jd.public_pem) { alert('Recipient has no public key registered'); return; }
  const enc = await encryptForRecipient(jd.public_pem, plaintext);
  await fetch('/api/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user_id: parseInt(window._SM_USER_ID||0), username: window._SM_USERNAME||'guest', mode:'A', enc_key_b64: enc.enc_key_b64, nonce_b64: enc.nonce_b64, ciphertext_b64: enc.ciphertext_b64})});
}

async function sendMessageModeB(plaintext) {
  await fetch('/api/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({user_id: parseInt(window._SM_USER_ID||0), username: window._SM_USERNAME||'guest', mode:'B', plaintext})});
}

async function loadAndRenderMessages() {
  const res = await fetch('/api/get_encrypted_messages');
  const arr = await res.json();
  const container = document.getElementById('messages');
  container.innerHTML = '';
  for (const m of arr) {
    const div = document.createElement('div');
    if (m.mode === 'A') {
      // try decrypt locally
      try {
        const pt = await decryptOwnMessage(m.enc_key_b64, m.nonce_b64, m.ciphertext_b64);
        div.textContent = (m.username || 'User') + ': ' + pt;
        div.className = 'message me';
      } catch (e) {
        div.textContent = (m.username || 'User') + ': 🔐 (encrypted)';
        div.className = 'message';
      }
    } else {
      // server-encrypted: cannot decrypt client-side; show placeholder
      div.textContent = (m.username || 'User') + ': 🔒 (server-encrypted)';
      div.className = 'message';
    }
    container.appendChild(div);
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  // minimal user identity (in Telegram, WebApp SDK would set this)
  window._SM_USER_ID = 0;
  window._SM_USERNAME = 'Guest';
  // UI hooks
  document.getElementById('genKeyBtn').addEventListener('click', async () => {
    const pem = await generateKeyPair();
    alert('Key pair generated and private key stored in IndexedDB. Public key PEM length: ' + pem.length);
  });
  document.getElementById('regKeyBtn').addEventListener('click', async () => {
    const priv = await idbGet('privateKey');
    if (!priv) { alert('No private key — generate first'); return; }
    // export public from private JWK by re-importing private and exporting public is complex; instead ask user to regenerate key and capture PEM from generateKeyPair result
    // For simplicity in demo, generate a fresh pair and register its public key
    const pem = await generateKeyPair();
    await registerPublicKeyOnServer(pem);
    alert('Public key registered on server');
  });
  document.getElementById('sendBtn').addEventListener('click', async () => {
    const mode = document.getElementById('modeSelect').value;
    const recip = document.getElementById('recipientId').value || '0';
    const txt = document.getElementById('messageInput').value || '';
    if (!txt) return alert('Enter message');
    if (mode === 'A') {
      await sendMessageModeA(parseInt(recip), txt);
    } else {
      await sendMessageModeB(txt);
    }
    document.getElementById('messageInput').value = '';
    await loadAndRenderMessages();
  });

  // initial load
  await loadAndRenderMessages();
  setInterval(loadAndRenderMessages, 3000);
});
