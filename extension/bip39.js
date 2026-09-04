// BIP39 seed-phrase detection with checksum validation.
//
// Why the checksum matters: twelve random English words are not a seed phrase.
// A real BIP39 phrase carries a checksum in its last word, so a valid phrase
// is not something a person writes by accident. That is what keeps the false
// alarm rate at zero without any configuration from the user.
//
// Two levels are reported, and the difference is deliberate:
//   valid    - checksum passes. This is a seed phrase.
//   shaped   - twelve or more consecutive wordlist words, checksum fails.
//              Usually a phrase with one word mistyped. Still dangerous: a
//              phishing site collects what you typed regardless of typos.

const VALID_LENGTHS = [12, 15, 18, 21, 24];
const MAX_TOKENS = 4000; // a paste of a whole book must not freeze the page

function normalizeText(text) {
  // NFKD is what BIP39 specifies for the mnemonic itself. Applying it to both
  // sides is what makes non-Latin wordlists work later; for English it is
  // harmless and keeps one code path.
  return text.normalize("NFKD").toLowerCase();
}

function tokenize(text) {
  const out = [];
  const re = /[a-z]+/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ word: m[0], start: m.index, end: m.index + m[0].length });
    if (out.length >= MAX_TOKENS) break;
  }
  return out;
}

// words -> bit array (11 bits per word), then split into entropy + checksum.
function checksumValid(words, deps) {
  const L = words.length;
  const totalBits = L * 11;
  const entBits = (L * 32) / 3;
  if (!Number.isInteger(entBits)) return false;
  const csBits = totalBits - entBits;

  const bits = new Uint8Array(totalBits);
  for (let i = 0; i < L; i++) {
    const idx = deps.BIP39_INDEX.get(words[i]);
    if (idx === undefined) return false;
    for (let b = 0; b < 11; b++) {
      bits[i * 11 + b] = (idx >> (10 - b)) & 1;
    }
  }

  const entBytes = new Uint8Array(entBits / 8);
  for (let i = 0; i < entBits; i++) {
    if (bits[i]) entBytes[i >> 3] |= 0x80 >> (i & 7);
  }

  const digest = deps.sha256(entBytes);
  for (let i = 0; i < csBits; i++) {
    const expected = (digest[i >> 3] >> (7 - (i & 7))) & 1;
    if (bits[entBits + i] !== expected) return false;
  }
  return true;
}

// Public test vectors that must never raise an alarm. Derived, not copied:
// these are the mnemonics for all-zero entropy, which every wallet tutorial
// and test suite uses. Silence on them is a feature - a tool that shouts at
// documentation gets uninstalled.
function buildIgnoreList(deps) {
  const set = new Set();
  for (const entLen of [16, 32]) {
    const zeros = new Uint8Array(entLen);
    const words = entropyToWords(zeros, deps);
    if (words) set.add(words.join(" "));
  }
  return set;
}

function entropyToWords(entropy, deps) {
  const entBits = entropy.length * 8;
  const csBits = entBits / 32;
  const digest = deps.sha256(entropy);
  const total = entBits + csBits;
  const bits = new Uint8Array(total);
  for (let i = 0; i < entBits; i++) bits[i] = (entropy[i >> 3] >> (7 - (i & 7))) & 1;
  for (let i = 0; i < csBits; i++) bits[entBits + i] = (digest[i >> 3] >> (7 - (i & 7))) & 1;
  const words = [];
  for (let i = 0; i < total; i += 11) {
    let idx = 0;
    for (let b = 0; b < 11; b++) idx = (idx << 1) | bits[i + b];
    words.push(deps.BIP39_WORDS[idx]);
  }
  return words;
}

let IGNORE = null;

// Returns { level: "valid" | "shaped", words: number } or null.
function findSeedPhrase(text, deps) {
  if (!text) return null;
  if (IGNORE === null) IGNORE = buildIgnoreList(deps);

  const tokens = tokenize(normalizeText(text));
  if (tokens.length < 12) return null;

  // Cheap pre-filter: a run of at least 12 consecutive wordlist words.
  // Without this, every long paragraph costs a full scan.
  let best = null;
  let run = [];

  const flush = () => {
    if (run.length >= 12) {
      for (const L of VALID_LENGTHS) {
        if (run.length < L) break;
        for (let s = 0; s + L <= run.length; s++) {
          const slice = run.slice(s, s + L);
          if (IGNORE.has(slice.join(" "))) continue;
          if (checksumValid(slice, deps)) {
            best = { level: "valid", words: L };
            return;
          }
        }
      }
      if (!best) {
        const phrase = run.slice(0, Math.min(run.length, 24)).join(" ");
        if (!IGNORE.has(phrase)) best = { level: "shaped", words: run.length };
      }
    }
    run = [];
  };

  for (const t of tokens) {
    if (deps.BIP39_INDEX.has(t.word)) {
      run.push(t.word);
    } else {
      flush();
      if (best && best.level === "valid") return best;
    }
  }
  flush();
  return best;
}

if (typeof module !== "undefined") {
  module.exports = { findSeedPhrase, checksumValid, entropyToWords, VALID_LENGTHS };
}
