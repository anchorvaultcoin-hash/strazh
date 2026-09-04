// Keccak-256 (Ethereum variant, 0x01 padding) in plain JavaScript.
// No dependencies. This is the same algorithm as pure_keccak.py in this repo.
//
// Note: Ethereum uses Keccak-256, not NIST SHA3-256. The padding byte is 0x01,
// not 0x06. Using the wrong one silently produces different addresses.

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
  0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
  0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const MASK = (1n << 64n) - 1n;

function rol(x, n) {
  const s = BigInt(n % 64);
  if (s === 0n) return x & MASK;
  return ((x << s) | (x >> (64n - s))) & MASK;
}

function keccakF1600(state) {
  for (let rnd = 0; rnd < 24; rnd++) {
    const C = [];
    for (let x = 0; x < 5; x++) {
      C.push(state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]);
    }
    const D = [];
    for (let x = 0; x < 5; x++) {
      D.push(C[(x + 4) % 5] ^ rol(C[(x + 1) % 5], 1));
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) state[x][y] ^= D[x];
    }
    const B = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n],
               [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y % 5][(2 * x + 3 * y) % 5] = rol(state[x][y], ROT[x][y]);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & MASK & B[(x + 2) % 5][y]);
      }
    }
    state[0][0] ^= RC[rnd];
  }
  return state;
}

function keccak256(bytes) {
  const rate = 136;
  const padded = Array.from(bytes);
  padded.push(0x01);
  while (padded.length % rate !== 0) padded.push(0x00);
  padded[padded.length - 1] ^= 0x80;

  const state = [[0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n],
                 [0n, 0n, 0n, 0n, 0n], [0n, 0n, 0n, 0n, 0n]];

  for (let i = 0; i < padded.length; i += rate) {
    for (let j = 0; j < rate / 8; j++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) {
        lane = (lane << 8n) | BigInt(padded[i + j * 8 + b]);
      }
      state[j % 5][Math.floor(j / 5)] ^= lane;
    }
    keccakF1600(state);
  }

  const out = [];
  while (out.length < 32) {
    for (let j = 0; j < rate / 8 && out.length < 32; j++) {
      let lane = state[j % 5][Math.floor(j / 5)];
      for (let b = 0; b < 8 && out.length < 32; b++) {
        out.push(Number(lane & 0xffn));
        lane >>= 8n;
      }
    }
    if (out.length < 32) keccakF1600(state);
  }
  return Uint8Array.from(out);
}

if (typeof module !== "undefined") module.exports = { keccak256 };
