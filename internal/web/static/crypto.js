/*
 * Sender-Report client-side cryptography.
 *
 * Implements the browser half of the end-to-end encryption described in
 * docs/ENCRYPTION.md. The byte layout matches internal/sealedbox (Go) exactly.
 *
 * Primitives:
 *   X25519       — TweetNaCl (nacl.scalarMult / nacl.box.keyPair), self-hosted
 *   HKDF-SHA256  — WebCrypto subtle.deriveBits
 *   AES-256-GCM  — WebCrypto subtle.encrypt / subtle.decrypt
 *
 * Requires tweetnacl.min.js (global `nacl`) to be loaded first.
 *
 * Public API (global `SenderReportCrypto`):
 *   await generateToken()          -> { token, secret, public, identifier }
 *   await fromToken(token)         -> { secret, public, identifier }
 *   await identifier(publicBytes)  -> "abc...16chars"
 *   await seal(ptBytes, pubBytes)  -> Uint8Array blob          (mirror of Go; mainly for tests)
 *   await open(blobBytes, secret)  -> Uint8Array plaintext
 *   await cryptoSelfTest()         -> boolean (verifies Go↔JS interop)
 */
(function (root) {
  'use strict';

  var nacl = root.nacl;
  var subtle = (root.crypto || {}).subtle;

  var MAGIC = 'MPE1';
  var HKDF_INFO = 'mailprobe-content-v1';
  var IDENT_DOMAIN = 'mailprobe-id-v1';
  var IDENT_LEN = 10; // bytes -> 16 base32 chars
  var B32 = 'abcdefghijklmnopqrstuvwxyz234567';

  // ── byte helpers ────────────────────────────────────────────────────────────
  function utf8(s) { return new TextEncoder().encode(s); }
  function fromUtf8(b) { return new TextDecoder().decode(b); }

  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
    return out;
  }

  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  function hexToBytes(h) {
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  function toBase64url(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromBase64url(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var bin = atob(str), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // RFC 4648 base32, lowercase, no padding (matches Go base32.StdEncoding lowercased).
  function toBase32Lower(bytes) {
    var bits = 0, value = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  // ── core crypto ─────────────────────────────────────────────────────────────
  async function hkdfAesKey(shared, ephPublic, recipientPublic) {
    var salt = concat(ephPublic, recipientPublic);
    var base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    var bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt, info: utf8(HKDF_INFO) },
      base, 256
    );
    return subtle.importKey('raw', new Uint8Array(bits), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function identifier(publicKey) {
    var data = concat(utf8(IDENT_DOMAIN), publicKey);
    var hash = new Uint8Array(await subtle.digest('SHA-256', data));
    return toBase32Lower(hash.slice(0, IDENT_LEN));
  }

  // seal mirrors Go's Seal; production encryption happens server-side, but this
  // lets us round-trip and test from the browser too.
  async function seal(plaintext, recipientPublic) {
    var ephSecret = nacl.randomBytes(32);
    var ephPublic = nacl.scalarMult.base(ephSecret);
    var shared = nacl.scalarMult(ephSecret, recipientPublic);
    var key = await hkdfAesKey(shared, ephPublic, recipientPublic);
    var nonce = root.crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: ephPublic, tagLength: 128 },
      key, plaintext
    ));
    return concat(utf8(MAGIC), ephPublic, nonce, ct);
  }

  async function open(blob, recipientSecret) {
    if (fromUtf8(blob.slice(0, 4)) !== MAGIC) throw new Error('sealedbox: bad magic');
    var ephPublic = blob.slice(4, 36);
    var nonce = blob.slice(36, 48);
    var ct = blob.slice(48);
    var recipientPublic = nacl.scalarMult.base(recipientSecret);
    var shared = nacl.scalarMult(recipientSecret, ephPublic);
    var key = await hkdfAesKey(shared, ephPublic, recipientPublic);
    var pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: ephPublic, tagLength: 128 },
      key, ct
    );
    return new Uint8Array(pt);
  }

  // ── token / identity ────────────────────────────────────────────────────────
  function encodeToken(secret) { return toBase64url(concat(new Uint8Array([1]), secret)); }
  function decodeToken(token) {
    var raw = fromBase64url(token);
    if (raw.length !== 33 || raw[0] !== 1) throw new Error('sealedbox: bad token');
    return raw.slice(1);
  }

  async function generateToken() {
    var kp = nacl.box.keyPair();
    var id = await identifier(kp.publicKey);
    return { token: encodeToken(kp.secretKey), secret: kp.secretKey, public: kp.publicKey, identifier: id };
  }
  async function fromToken(token) {
    var secret = decodeToken(token);
    var publicKey = nacl.scalarMult.base(secret);
    var id = await identifier(publicKey);
    return { secret: secret, public: publicKey, identifier: id };
  }

  // ── self-test against the Go test vector (sealedbox_test.go: TestVector) ──────
  var VECTOR = {
    secret: '0101010101010101010101010101010101010101010101010101010101010101',
    blob: '4d504531ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d596e9a68d5e08c00898a51b0c3379c42e57f2de8d1a1dd076b128cb7422a1a9a3f10c69b25e93a2fe9a3c9ea94b9fdf5094b74a2b03c',
    plaintext: 'mailprobe e2e test vector',
    identifier: '3t7lf53kan2txsm7',
  };
  async function cryptoSelfTest() {
    try {
      var secret = hexToBytes(VECTOR.secret);
      var pt = await open(hexToBytes(VECTOR.blob), secret);
      var text = fromUtf8(pt);
      var id = await identifier(nacl.scalarMult.base(secret));
      var ok = text === VECTOR.plaintext && id === VECTOR.identifier;
      if (ok) {
        console.log('[Sender-Report] crypto self-test PASSED (Go↔JS interop verified)');
      } else {
        console.error('[Sender-Report] crypto self-test FAILED', { text: text, id: id });
      }
      return ok;
    } catch (e) {
      console.error('[Sender-Report] crypto self-test ERROR', e);
      return false;
    }
  }

  root.SenderReportCrypto = {
    generateToken: generateToken,
    fromToken: fromToken,
    identifier: identifier,
    seal: seal,
    open: open,
    cryptoSelfTest: cryptoSelfTest,
    // low-level helpers exposed for the data-path wiring (phases 2–4)
    _encodeToken: encodeToken,
    _decodeToken: decodeToken,
    _hexToBytes: hexToBytes,
    _bytesToHex: bytesToHex,
    _fromBase64url: fromBase64url,
    _toBase64url: toBase64url,
    _utf8: utf8,
    _fromUtf8: fromUtf8,
  };
})(typeof window !== 'undefined' ? window : globalThis);
