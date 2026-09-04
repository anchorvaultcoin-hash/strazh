// secp256k1 point arithmetic in plain JavaScript (BigInt). No dependencies.
// Same algorithm as pure_secp256k1.py in this repo.

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

// Modular inverse via the extended Euclidean algorithm.
function invMod(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

function onCurve(x, y) {
  return mod(y * y - (x * x * x + 7n), P) === 0n;
}

function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2 && mod(y1 + y2, P) === 0n) return null;
  let lam;
  if (x1 === x2 && y1 === y2) {
    lam = mod(3n * x1 * x1 * invMod(2n * y1, P), P);
  } else {
    lam = mod((y2 - y1) * invMod(x2 - x1, P), P);
  }
  const x3 = mod(lam * lam - x1 - x2, P);
  const y3 = mod(lam * (x1 - x3) - y1, P);
  return [x3, y3];
}

function scalarMult(k, point) {
  let result = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function hexToBytes32(v) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[31 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

// Returns the 64-byte uncompressed public key (x || y), or null if the hex
// string is not a valid private key for this curve.
function privateKeyToPubkey(privHex) {
  const k = BigInt("0x" + privHex);
  if (k <= 0n || k >= N) return null;
  const pt = scalarMult(k, [GX, GY]);
  if (pt === null) return null;
  const out = new Uint8Array(64);
  out.set(hexToBytes32(pt[0]), 0);
  out.set(hexToBytes32(pt[1]), 32);
  return out;
}

if (typeof module !== "undefined") {
  module.exports = { privateKeyToPubkey, onCurve, P, N, GX, GY };
}
