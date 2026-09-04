// STRAZH policy core for the browser.
//
// Two questions, in this order:
//   1. What is being sent?      - derived, not guessed from the shape
//   2. What was asked for?      - read from what the destination itself says
// The decision is made on the relationship between the two.
//
// Everything here is synchronous on purpose: a paste can only be stopped
// inside its own event handler.

const HEX64 = /\b[0-9a-fA-F]{64}\b/g;
const ETH_ADDRESS = /\b0x[0-9a-fA-F]{40}\b/;
const MAX_HEX_CANDIDATES = 16;

function toChecksumAddress(addrHex, keccak256) {
  const lower = addrHex.toLowerCase().replace(/^0x/, "");
  const hashBytes = keccak256(new TextEncoder().encode(lower));
  let hashHex = "";
  for (const b of hashBytes) hashHex += b.toString(16).padStart(2, "0");
  let out = "0x";
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i];
    if (ch >= "0" && ch <= "9") out += ch;
    else out += parseInt(hashHex[i], 16) >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

function privateKeyToAddress(privHex, deps) {
  const pub = deps.privateKeyToPubkey(privHex);
  if (pub === null) return null;
  const hash = deps.keccak256(pub);
  let addr = "";
  for (const b of hash.slice(12)) addr += b.toString(16).padStart(2, "0");
  return toChecksumAddress(addr, deps.keccak256);
}

// Normalization first: a key with a 0x prefix, in upper case, or with a stray
// newline in the middle is the same key. Without this the guard is bypassed by
// pressing shift.
function normalizeCandidateText(text) {
  return String(text).replace(/\s+/g, " ");
}

// What is this string? Returns { type, wallet?, words? }.
function identify(text, knownWallets, deps) {
  const clean = normalizeCandidateText(text);

  // 1. A seed phrase is the highest-value secret an ordinary person holds.
  const seed = deps.findSeedPhrase(clean, deps);
  if (seed) {
    return {
      type: seed.level === "valid" ? "SEED_PHRASE" : "SEED_PHRASE_SHAPED",
      words: seed.words,
    };
  }

  // 2. A private key is identified by derivation, never by shape: a key and a
  //    transaction hash are both 256 random bits.
  //
  // Two passes. The second one removes whitespace entirely, because a key
  // copied out of a wrapped terminal arrives with a newline through the middle
  // and would otherwise walk straight past the guard. Joining fragments can
  // only add candidates, never hide one, and a candidate still has to derive
  // to one of your own addresses before anything is blocked.
  const dense = String(text).replace(/\s+/g, "");
  const hexMatches = [
    ...(clean.replace(/0x/gi, "").match(HEX64) || []),
    ...(dense.replace(/0x/gi, "").match(HEX64) || []),
  ];
  if (hexMatches.length > 0) {
    const seen = new Set();
    for (const candidate of hexMatches.slice(0, MAX_HEX_CANDIDATES)) {
      if (seen.has(candidate.toLowerCase())) continue;
      seen.add(candidate.toLowerCase());
      const addr = privateKeyToAddress(candidate, deps);
      if (addr === null) continue;
      const name = knownWallets && knownWallets[addr.toLowerCase()];
      if (name) return { type: "ETH_PRIVATE_KEY", wallet: name, address: addr };
    }
    // Derivation matched no wallet of yours. Almost always a hash. Silence.
    return { type: "UNKNOWN" };
  }

  if (ETH_ADDRESS.test(clean)) return { type: "ADDRESS" };
  return { type: "UNKNOWN" };
}

// ctx: { askFragments: string[], destination: string }
// Returns { action: "STOP" | "WARN" | "SILENT", rule, detected, ask, ... }
function decide(text, ctx, knownWallets, deps) {
  const ask = deps.classifyAsk(ctx.askFragments || []);
  const detected = identify(text, knownWallets, deps);

  // Rule 1 - the request itself is the attack.
  // No legitimate web page needs your recovery phrase or your private key.
  // This needs no configuration at all, which is what makes STRAZH useful to
  // someone who just installed it and never opened the settings.
  if (deps.isIllegitimateAsk(ask.type)) {
    return {
      action: "STOP",
      rule: "ILLEGITIMATE_ASK",
      detected: detected.type,
      ask: ask.type,
      evidence: ask.evidence,
      destination: ctx.destination,
      wallet: detected.wallet,
    };
  }

  // Rule 2 - a valid seed phrase never belongs in a web page.
  if (detected.type === "SEED_PHRASE") {
    return {
      action: "STOP",
      rule: "SEED_PHRASE_LEAVING",
      detected: detected.type,
      ask: ask.type,
      words: detected.words,
      destination: ctx.destination,
    };
  }

  // Rule 3 - the 18 August case: the right action with the wrong secret.
  if (detected.type === "ETH_PRIVATE_KEY") {
    const verdict = deps.compare(detected.type, ask.type);
    if (verdict === "MISMATCH") {
      return {
        action: "STOP",
        rule: "WRONG_KEY_TYPE",
        detected: detected.type,
        ask: ask.type,
        evidence: ask.evidence,
        wallet: detected.wallet,
        address: detected.address,
        destination: ctx.destination,
      };
    }
    // Your key, and we cannot tell what this place wants. Not certain enough
    // to block, too important to ignore.
    return {
      action: "WARN",
      rule: "KNOWN_KEY_UNKNOWN_DESTINATION",
      detected: detected.type,
      ask: ask.type,
      wallet: detected.wallet,
      address: detected.address,
      destination: ctx.destination,
    };
  }

  // Rule 4 - shaped like a seed phrase but the checksum fails. Usually one
  // word mistyped. Only acted on when the destination asked for a phrase,
  // which rule 1 has already handled, so here it stays quiet.
  return { action: "SILENT", rule: "NO_MATCH", detected: detected.type, ask: ask.type };
}

if (typeof module !== "undefined") {
  module.exports = { decide, identify, privateKeyToAddress, toChecksumAddress };
}
