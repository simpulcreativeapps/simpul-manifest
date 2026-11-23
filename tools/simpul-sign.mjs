#!/usr/bin/env node
// simpul-sign — buat kunci, validasi, tanda tangani, dan verifikasi manifest Simpul Creative Apps.
// Tanpa dependensi: hanya modul bawaan Node.js (v18+).
//
//   node tools/simpul-sign.mjs keygen  [--out <folder-kunci-privat>]
//   node tools/simpul-sign.mjs validate [manifest.json]
//   node tools/simpul-sign.mjs sign    --key <file-kunci-privat> [manifest.json]
//   node tools/simpul-sign.mjs verify  [manifest.json]
//
// Kunci privat TIDAK PERNAH disimpan di folder repo ini. Bawaannya ditulis ke ~/.simpul-keys.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PUBKEY_DIR = join(REPO, 'public-keys');
const STATUSES = ['green', 'yellow', 'red'];
// Host yang boleh muncul di URL unduhan. Harus sama dengan ALLOWED_HOSTS di simpul-guard.
const ALLOWED_HOSTS = ['github.com', 'apps.simpulproject.com'];

/* ------------------------------------------------------------------ util */
const die = (msg) => { console.error('✗ ' + msg); process.exit(1); };
const ok = (msg) => console.log('✓ ' + msg);
const arg = (name) => { const i = process.argv.indexOf(name); return i > -1 ? process.argv[i + 1] : undefined; };
const positional = () => process.argv.slice(3).filter((a, i, all) => !a.startsWith('--') && !(all[i - 1] || '').startsWith('--'));

function rawPublicKey(keyObject) {
  // 32 byte kunci publik Ed25519 mentah (lihat RFC 8410: DER SPKI diakhiri 32 byte kunci).
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}
const keyIdOf = (raw32) => createHash('sha256').update(raw32).digest('hex').slice(0, 16);
function publicKeyFromRaw(raw32) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return createPublicKey({ key: Buffer.concat([prefix, raw32]), format: 'der', type: 'spki' });
}

function askHidden(question) {
  if (process.env.SIMPUL_KEY_PASSPHRASE) return Promise.resolve(process.env.SIMPUL_KEY_PASSPHRASE);
  const stdin = process.stdin;
  if (!stdin.isTTY) die('Passphrase harus diketik langsung di terminal (bukan lewat pipe).');
  // Baca per tombol dalam raw mode: tidak ada satu karakter pun yang ditampilkan di layar.
  return new Promise((res) => {
    process.stdout.write(question);
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stdout.write('\n');
          res(value);
          return;
        }
        if (ch === '\u0003') { stdin.setRawMode(false); process.stdout.write('\n'); process.exit(130); }
        if (ch === '\u0008' || ch === '\u007f') { value = value.slice(0, -1); continue; }
        if (ch >= ' ') value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

/* ------------------------------------------------------------- validasi */
function validateManifest(m) {
  const errs = [];
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  const isDate = (v) => typeof v === 'string' && !Number.isNaN(Date.parse(v)) && /Z$|[+-]\d\d:\d\d$/.test(v);
  const isVer = (v) => typeof v === 'string' && /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v);
  const isHttps = (v, hosts) => {
    try { const u = new URL(v); return u.protocol === 'https:' && (!hosts || hosts.includes(u.hostname)); } catch { return false; }
  };

  if (!isObj(m)) return ['Manifest harus berupa objek JSON.'];
  if (m.schema !== 1) errs.push('schema harus 1.');
  if (!isDate(m.issued_at)) errs.push('issued_at harus tanggal ISO 8601 dengan zona waktu.');
  if (!isObj(m.apps) || !Object.keys(m.apps).length) errs.push('apps harus berisi minimal satu aplikasi.');

  for (const [id, a] of Object.entries(m.apps || {})) {
    const p = `apps.${id}`;
    if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) errs.push(`${p}: id hanya huruf kecil, angka, dan tanda minus.`);
    if (!isObj(a)) { errs.push(`${p}: harus objek.`); continue; }
    if (typeof a.name !== 'string' || !a.name.trim()) errs.push(`${p}.name wajib diisi.`);
    if (!STATUSES.includes(a.status)) errs.push(`${p}.status harus salah satu dari: ${STATUSES.join(', ')}.`);

    if (a.status === 'green' && a.notice) errs.push(`${p}.notice harus kosong saat status green.`);
    if (a.status === 'yellow' || a.status === 'red') {
      const n = a.notice;
      if (!isObj(n)) errs.push(`${p}.notice wajib diisi saat status ${a.status}.`);
      else {
        if (typeof n.title !== 'string' || !n.title.trim()) errs.push(`${p}.notice.title wajib diisi.`);
        if (typeof n.message !== 'string' || !n.message.trim()) errs.push(`${p}.notice.message wajib diisi.`);
        if (n.source_url != null && !isHttps(n.source_url)) errs.push(`${p}.notice.source_url harus https.`);
        if (a.status === 'red') {
          if (!isDate(n.disable_at)) errs.push(`${p}.notice.disable_at wajib (ISO 8601) saat status red.`);
        } else if (n.disable_at != null) errs.push(`${p}.notice.disable_at hanya untuk status red.`);
      }
    }

    if (a.min_launcher != null && !isVer(a.min_launcher)) errs.push(`${p}.min_launcher harus format x.y.z.`);
    if (a.min_version != null) {
      if (!isVer(a.min_version)) errs.push(`${p}.min_version harus format x.y.z.`);
      else if (!isObj(a.release) || !isVer(a.release.version)) errs.push(`${p}.min_version butuh release.`);
      else {
        const num = (v) => v.split(/[-+]/)[0].split('.').map(Number);
        const [x, y] = [num(a.min_version), num(a.release.version)];
        const above = x[0] !== y[0] ? x[0] > y[0] : x[1] !== y[1] ? x[1] > y[1] : x[2] > y[2];
        if (above) errs.push(`${p}.min_version melebihi versi rilis.`);
      }
    }

    if (a.release != null) {
      const r = a.release;
      if (!isObj(r)) { errs.push(`${p}.release harus objek atau null.`); continue; }
      if (!isVer(r.version)) errs.push(`${p}.release.version harus format x.y.z.`);
      if (!isHttps(r.url, ALLOWED_HOSTS)) errs.push(`${p}.release.url harus https dan host-nya salah satu dari: ${ALLOWED_HOSTS.join(', ')}.`);
      if (typeof r.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(r.sha256)) errs.push(`${p}.release.sha256 harus 64 karakter heksadesimal huruf kecil.`);
      if (r.notes_url != null && !isHttps(r.notes_url)) errs.push(`${p}.release.notes_url harus https.`);
      if (a.status === 'red') errs.push(`${p}.release harus null saat status red (tidak ada lagi update).`);
    }
  }
  return errs;
}

function loadManifest(file) {
  if (!existsSync(file)) die(`File tidak ditemukan: ${file}`);
  try { return { text: readFileSync(file, 'utf8'), json: JSON.parse(readFileSync(file, 'utf8')) }; }
  catch (e) { die(`${file} bukan JSON yang valid: ${e.message}`); }
}

function trustedKeys() {
  if (!existsSync(PUBKEY_DIR)) return [];
  return readdirSync(PUBKEY_DIR).filter((f) => f.endsWith('.pub')).map((f) => {
    const raw = Buffer.from(readFileSync(join(PUBKEY_DIR, f), 'utf8').trim(), 'base64');
    if (raw.length !== 32) die(`Kunci publik tidak valid: ${f}`);
    return { id: keyIdOf(raw), raw, file: f };
  });
}

/* --------------------------------------------------------------- perintah */
async function keygen() {
  const out = resolve(arg('--out') || join(homedir(), '.simpul-keys'));
  const inside = (child, parent) => { const r = relative(parent, child); return r === '' || (!r.startsWith('..') && !isAbsolute(r)); };
  if (inside(out, REPO)) die('Jangan simpan kunci privat di dalam folder repo. Pakai --out ke folder lain.');
  const pass = await askHidden('Buat passphrase kunci (min. 12 karakter): ');
  if (pass.length < 12) die('Passphrase minimal 12 karakter.');
  if ((await askHidden('Ulangi passphrase: ')) !== pass) die('Passphrase tidak sama.');

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = rawPublicKey(publicKey);
  const id = keyIdOf(raw);
  mkdirSync(out, { recursive: true });
  mkdirSync(PUBKEY_DIR, { recursive: true });
  const privPath = join(out, `simpul-manifest-${id}.key`);
  writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: pass }), { mode: 0o600 });
  writeFileSync(join(PUBKEY_DIR, `${id}.pub`), raw.toString('base64') + '\n');
  ok(`Kunci privat : ${privPath}  (cadangkan ke 2 tempat aman, JANGAN di-commit)`);
  ok(`Kunci publik : public-keys/${id}.pub  (commit file ini)`);
  console.log(`\nTambahkan ke simpul-guard/src/keys.rs:\n    TrustedKey { id: "${id}", public_key_b64: "${raw.toString('base64')}" },`);
}

function validate() {
  const file = resolve(positional()[0] || join(REPO, 'manifest.json'));
  const { json } = loadManifest(file);
  const errs = validateManifest(json);
  if (errs.length) { errs.forEach((e) => console.error('✗ ' + e)); process.exit(1); }
  ok(`Manifest valid (${Object.keys(json.apps).length} aplikasi).`);
}

async function signCmd() {
  const file = resolve(positional()[0] || join(REPO, 'manifest.json'));
  const keyFile = arg('--key') || die('Sebutkan file kunci privat: --key <path>');
  const { json } = loadManifest(file);

  // issued_at selalu diperbarui: aplikasi menolak manifest yang lebih tua dari yang terakhir diterima.
  const prev = Date.parse(json.issued_at || 0) || 0;
  json.issued_at = new Date(Math.max(Date.now(), prev + 1000)).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const errs = validateManifest(json);
  if (errs.length) { errs.forEach((e) => console.error('✗ ' + e)); die('Perbaiki manifest dulu, tidak ditandatangani.'); }

  const pass = await askHidden('Passphrase kunci: ');
  let key;
  try { key = createPrivateKey({ key: readFileSync(keyFile, 'utf8'), passphrase: pass }); }
  catch { die('Gagal membuka kunci privat (passphrase salah atau file rusak).'); }

  const raw = rawPublicKey(createPublicKey(key));
  const id = keyIdOf(raw);
  if (!trustedKeys().some((k) => k.id === id)) die(`Kunci ${id} tidak ada di public-keys/. Aplikasi tidak akan mempercayainya.`);

  const text = JSON.stringify(json, null, 2) + '\n';
  const signature = sign(null, Buffer.from(text, 'utf8'), key).toString('base64');
  writeFileSync(file, text);
  writeFileSync(file + '.sig', JSON.stringify({ alg: 'ed25519', key_id: id, sig: signature }, null, 2) + '\n');
  ok(`Ditandatangani dengan kunci ${id}, issued_at ${json.issued_at}.`);
  ok(`Tulis: ${file} dan ${file}.sig  →  commit & push keduanya.`);
}

function verifyCmd() {
  const file = resolve(positional()[0] || join(REPO, 'manifest.json'));
  const { text, json } = loadManifest(file);
  if (!existsSync(file + '.sig')) die('File tanda tangan .sig tidak ada.');
  const sig = JSON.parse(readFileSync(file + '.sig', 'utf8'));
  const k = trustedKeys().find((x) => x.id === sig.key_id);
  if (!k) die(`Kunci ${sig.key_id} tidak dikenal.`);
  if (sig.alg !== 'ed25519') die('Algoritme harus ed25519.');
  const good = verify(null, Buffer.from(text, 'utf8'), publicKeyFromRaw(k.raw), Buffer.from(sig.sig, 'base64'));
  if (!good) die('Tanda tangan TIDAK cocok. Manifest diubah setelah ditandatangani, atau kuncinya salah.');
  const errs = validateManifest(json);
  if (errs.length) { errs.forEach((e) => console.error('✗ ' + e)); process.exit(1); }
  ok(`Tanda tangan cocok (kunci ${k.id}), issued_at ${json.issued_at}.`);
}

const cmds = { keygen, validate, sign: signCmd, verify: verifyCmd };
const cmd = process.argv[2];
if (!cmds[cmd]) {
  console.log('Pemakaian: node tools/simpul-sign.mjs <keygen|validate|sign|verify> [opsi]');
  process.exit(cmd ? 1 : 0);
}
await cmds[cmd]();
