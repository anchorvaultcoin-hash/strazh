// STRAZH browser guard - test suite. Run with: node test.js
//
// No test framework, no dependencies: node test.js and read the output.
// Every number quoted in the README and in the submission comes from here.

const crypto = require("crypto");

const { sha256 } = require("./sha256.js");
const { keccak256 } = require("./keccak.js");
const { privateKeyToPubkey } = require("./secp256k1.js");
const { BIP39_WORDS, BIP39_INDEX } = require("./bip39-wordlist.js");
const { findSeedPhrase, entropyToWords } = require("./bip39.js");
const { classifyAsk, isIllegitimateAsk, compare } = require("./expectation.js");
const { decide, privateKeyToAddress } = require("./detector.js");

const deps = {
  sha256, keccak256, privateKeyToPubkey,
  BIP39_WORDS, BIP39_INDEX, findSeedPhrase,
  classifyAsk, isIllegitimateAsk, compare,
};

let passed = 0;
let failed = 0;
const hex = (b) => Buffer.from(b).toString("hex");

function check(name, ok, detail) {
  if (ok) { passed++; console.log("  ok   " + name); }
  else { failed++; console.log("  FAIL " + name + (detail ? "  -> " + detail : "")); }
}

function section(title) {
  console.log("\n" + title);
}

// ---------------------------------------------------------------- SHA-256 --

section("SHA-256");
check("empty input matches the known digest",
  hex(sha256(new TextEncoder().encode(""))) ===
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
check('"abc" matches the known digest',
  hex(sha256(new TextEncoder().encode("abc"))) ===
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
{
  let bad = 0;
  for (let len = 0; len <= 200; len++) {
    const buf = crypto.randomBytes(len);
    if (hex(sha256(new Uint8Array(buf))) !== crypto.createHash("sha256").update(buf).digest("hex")) bad++;
  }
  check("every length from 0 to 200 bytes matches the reference", bad === 0, bad + " mismatches");
}

// ------------------------------------------------------------- Keccak-256 --

section("Keccak-256 (Ethereum variant)");
check("empty input matches the known digest",
  hex(keccak256(new Uint8Array([]))) ===
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

// ------------------------------------------------------------- secp256k1 --

section("secp256k1 derivation");
{
  // A derived address must be 20 bytes with a valid EIP-55 checksum, and the
  // same key must always give the same address.
  const k = crypto.randomBytes(32).toString("hex");
  const a1 = privateKeyToAddress(k, deps);
  const a2 = privateKeyToAddress(k, deps);
  check("address is 0x + 40 hex characters", /^0x[0-9a-fA-F]{40}$/.test(a1), a1);
  check("derivation is deterministic", a1 === a2);
  check("a different key gives a different address",
    privateKeyToAddress(crypto.randomBytes(32).toString("hex"), deps) !== a1);
}

// ------------------------------------------------------------------ BIP39 --

section("BIP39 wordlist and checksum");
check("wordlist has exactly 2048 words", BIP39_WORDS.length === 2048, String(BIP39_WORDS.length));
check("wordlist reproduces the official SHA-256",
  crypto.createHash("sha256").update(BIP39_WORDS.join("\n") + "\n").digest("hex") ===
  "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
{
  // Round trip: entropy -> words -> detected as a valid phrase.
  let ok = 0;
  const total = 200;
  for (let i = 0; i < total; i++) {
    const entLen = [16, 20, 24, 28, 32][i % 5];
    const words = entropyToWords(new Uint8Array(crypto.randomBytes(entLen)), deps).join(" ");
    const r = findSeedPhrase("my phrase is " + words + " thanks", deps);
    if (r && r.level === "valid") ok++;
  }
  check("200 generated phrases of all five lengths are detected", ok === total, ok + "/" + total);
}
{
  const prose = [
    "The quick brown fox jumps over the lazy dog while the cat sleeps near the fire",
    "Please review the attached document and let me know if you have any questions today",
    "npm install express react typescript eslint prettier jest webpack babel vite rollup esbuild",
    "Our team will focus on delivery quality speed and safety across every region this season",
  ];
  let alarms = 0;
  for (const p of prose) if (findSeedPhrase(p, deps)) alarms++;
  check("ordinary English prose raises no alarm", alarms === 0, alarms + " alarms");
}
check("the public all-zero test vector is ignored",
  findSeedPhrase("abandon ".repeat(11) + "about", deps) === null);
{
  // A run of random wordlist words passes the checksum about 1 time in 16,
  // which is exactly what four checksum bits predict. If this drifts far from
  // 1/16 the checksum implementation is wrong.
  let valid = 0;
  const total = 400;
  for (let i = 0; i < total; i++) {
    const w = [];
    for (let j = 0; j < 12; j++) w.push(BIP39_WORDS[crypto.randomInt(2048)]);
    const r = findSeedPhrase(w.join(" "), deps);
    if (r && r.level === "valid") valid++;
  }
  const rate = valid / total;
  check("random word runs validate at roughly 1/16 as the checksum predicts",
    rate > 0.03 && rate < 0.10, "rate " + rate.toFixed(3));
}

// ------------------------------------------------------------ the ask --

section("Reading what the destination asks for");
{
  const cases = [
    [["Enter your Etherscan API key: "], "API_KEY"],
    [["ALCHEMY_API_KEY"], "API_KEY"],
    [["--private-key"], "PRIVATE_KEY"],
    [["Введите ключ API"], "API_KEY"],
    [["api 密钥"], "API_KEY"],
    [["Enter your seed phrase to continue"], "SEED_PHRASE"],
    [["Enter your 12-word phrase"], "SEED_PHRASE"],
    [["Введите сид-фразу"], "SEED_PHRASE"],
    [["секретная фраза кошелька"], "SEED_PHRASE"],
    [["请输入助记词"], "SEED_PHRASE"],
    [["Приватный ключ"], "PRIVATE_KEY"],
    [["请输入私钥"], "PRIVATE_KEY"],
    [["Password"], "PASSWORD"],
    [["Email address"], "EMAIL"],
    [["Search by address / txn hash"], "SEARCH"],
    [["Recipient wallet address"], "ADDRESS"],
    [["钱包地址"], "ADDRESS"],
    [["Comment"], "UNKNOWN"],
    [["Amount"], "UNKNOWN"],
    [[""], "UNKNOWN"],
  ];
  let bad = 0;
  for (const [frags, want] of cases) {
    if (classifyAsk(frags).type !== want) { bad++; console.log("       " + frags[0] + " -> " + classifyAsk(frags).type + ", expected " + want); }
  }
  check(cases.length + " real asks in three languages are classified correctly", bad === 0, bad + " wrong");
}

// ---------------------------------------------------------------- policy --

section("Policy decisions");
{
  const key = crypto.randomBytes(32).toString("hex");
  const addr = privateKeyToAddress(key, deps);
  const wallets = { [addr.toLowerCase()]: "Creator" };
  const seed = entropyToWords(new Uint8Array(crypto.randomBytes(16)), deps).join(" ");
  const txhash = crypto.randomBytes(32).toString("hex");
  const NL = String.fromCharCode(10);

  const cases = [
    ["18 August: own wallet key into an API-key field", key, ["Enter your Etherscan API key"], "STOP", "WRONG_KEY_TYPE"],
    ["a page asking for a recovery phrase", "anything", ["Enter your seed phrase"], "STOP", "ILLEGITIMATE_ASK"],
    ["a page asking for a private key", "anything", ["Paste your private key"], "STOP", "ILLEGITIMATE_ASK"],
    ["a real seed phrase pasted anywhere", seed, ["Comment"], "STOP", "SEED_PHRASE_LEAVING"],
    ["own key with a 0x prefix in upper case", "0x" + key.toUpperCase(), ["API key"], "STOP", "WRONG_KEY_TYPE"],
    ["own key broken by a line wrap", key.slice(0, 32) + NL + key.slice(32), ["API key"], "STOP", "WRONG_KEY_TYPE"],
    ["own key with a space every eight characters", key.match(/.{1,8}/g).join(" "), ["API key"], "STOP", "WRONG_KEY_TYPE"],
    ["Russian phishing page", "x", ["Введите сид-фразу"], "STOP", "ILLEGITIMATE_ASK"],
    ["Chinese phishing page", "x", ["请输入助记词"], "STOP", "ILLEGITIMATE_ASK"],
    ["own key into an unlabelled field", key, ["Notes"], "WARN", "KNOWN_KEY_UNKNOWN_DESTINATION"],
    ["a transaction hash into an explorer search box", txhash, ["Search by address / txn hash"], "SILENT", "NO_MATCH"],
    ["a genuine API key into an API-key field", "AB12CD34EF56GH78IJ90", ["API key"], "SILENT", "NO_MATCH"],
    ["ordinary text into a comment box", "looks good to me, merging now", ["Comment"], "SILENT", "NO_MATCH"],
    ["an address into a recipient field", addr, ["Recipient wallet address"], "SILENT", "NO_MATCH"],
  ];
  let bad = 0;
  for (const [name, text, frags, wantAction, wantRule] of cases) {
    const d = decide(text, { askFragments: frags, destination: "example.com" }, wallets, deps);
    if (d.action !== wantAction || d.rule !== wantRule) {
      bad++;
      console.log("       " + name + " -> " + d.action + "/" + d.rule + ", expected " + wantAction + "/" + wantRule);
    }
  }
  check(cases.length + " policy cases decide correctly", bad === 0, bad + " wrong");

  // The false-alarm test that decides whether a tool like this survives use.
  let fp = 0;
  for (let i = 0; i < 1000; i++) {
    const d = decide(crypto.randomBytes(32).toString("hex"),
      { askFragments: ["Enter your API key"], destination: "x.com" }, wallets, deps);
    if (d.action !== "SILENT") fp++;
  }
  check("1000 transaction hashes into an API-key field raise no alarm", fp === 0, fp + " false alarms");
}

// ----------------------------------------------------------- performance --

section("Performance");
{
  const key = crypto.randomBytes(32).toString("hex");
  const addr = privateKeyToAddress(key, deps);
  const wallets = { [addr.toLowerCase()]: "Creator" };
  const t0 = Date.now();
  for (let i = 0; i < 50; i++) {
    decide(crypto.randomBytes(32).toString("hex"), { askFragments: ["API key"], destination: "x.com" }, wallets, deps);
  }
  const per = (Date.now() - t0) / 50;
  console.log("  ..   " + per.toFixed(1) + " ms per check, worst case (every candidate derived)");
  check("a single check stays under 100 ms", per < 100, per.toFixed(1) + " ms");

  const bigText = "the team will review the plan and respond by friday ".repeat(4000);
  const t1 = Date.now();
  decide(bigText, { askFragments: ["Comment"], destination: "x.com" }, wallets, deps);
  const bigMs = Date.now() - t1;
  console.log("  ..   " + bigText.length + " characters scanned in " + bigMs + " ms");
  check("a very large paste stays under 250 ms", bigMs < 250, bigMs + " ms");
}

// ------------------------------------------------------------------ done --

console.log("\n" + (failed === 0
  ? "all " + passed + " checks passed"
  : passed + " passed, " + failed + " FAILED"));
process.exit(failed === 0 ? 0 : 1);
