// What is the destination actually asking for?
//
// This is the part that makes STRAZH different from a secret scanner. A
// scanner asks "is this a secret". STRAZH also asks "what did the other side
// ask for", and decides on the mismatch between the two.
//
// The expectation is not looked up in a registry of known sites. It is read
// from what the destination itself says at the moment of the request: the
// label of the field in a browser, the prompt printed by a program in a
// terminal. That is why it works on sites nobody has ever catalogued - and it
// is exactly what happened on 18 August 2026, when the tool printed
// "Enter your Etherscan API key:" and received a wallet key.
//
// classifyAsk() takes plain text fragments and is deliberately free of any DOM
// or terminal specifics, so the browser guard and the terminal guard can share
// one implementation and one policy.

// Rules are checked in order, most specific first. "Email address" must not
// come out as ADDRESS, and an explorer's "Search by address" must not either -
// so EMAIL and SEARCH are tested before ADDRESS.
//
// Patterns are matched against a normalized fragment (see normalizeFragment):
// underscores and dashes become spaces, so ALCHEMY_API_KEY reads as
// "alchemy api key". Cyrillic is written out explicitly because \w in
// JavaScript covers only Latin letters, digits and the underscore.
const ASK_PATTERNS = [
  {
    type: "SEED_PHRASE",
    // Russian and Chinese included: seed-phrase phishing is not an
    // English-only problem, and a localized phishing page is still phishing.
    patterns: [
      /seed\s*phrase/i, /recovery\s*phrase/i, /secret\s*phrase/i, /backup\s*phrase/i,
      /mnemonic/i, /\b(12|15|18|21|24)\s*word/i, /wallet\s*phrase/i,
      /сид\s*фраз/i, /секретн[а-яё]*\s*фраз/i, /мнемоник/i, /мнемоническ/i,
      /восстановительн[а-яё]*\s*фраз/i, /резервн[а-яё]*\s*фраз/i,
      /фраз[а-яё]*\s*восстановлен/i,
      /助记词/, /恢复短语/, /种子短语/,
    ],
  },
  {
    type: "PRIVATE_KEY",
    patterns: [
      /private\s*key/i, /secret\s*key\b/i, /\bprivkey\b/i, /wallet\s*key/i,
      /приватн[а-яё]*\s*ключ/i, /закрыт[а-яё]*\s*ключ/i, /секретн[а-яё]*\s*ключ/i,
      /私钥/, /私人密钥/,
    ],
  },
  {
    type: "API_KEY",
    patterns: [
      /\bapi\s*key\b/i, /\bapi\s*token\b/i, /access\s*token/i,
      /etherscan\s*key/i, /\bapikey\b/i, /developer\s*key/i,
      /ключ\s*api/i, /api\s*ключ/i, /токен\s*доступа/i,
      /api\s*密钥/, /接口密钥/,
    ],
  },
  {
    type: "PASSWORD",
    patterns: [/password/i, /passphrase/i, /пароль/i, /密码/],
  },
  {
    type: "EMAIL",
    patterns: [/e\s*mail/i, /почт[аыуе]/i, /邮箱/, /电子邮件/],
  },
  {
    type: "SEARCH",
    patterns: [/\bsearch\b/i, /\bquery\b/i, /\bfilter\b/i, /поиск/i, /искать/i, /搜索/, /查询/],
  },
  {
    type: "ADDRESS",
    patterns: [
      /wallet\s*address/i, /\brecipient\b/i, /\bsend\s*to\b/i, /\baddress\b/i,
      /адрес\s*кошель/i, /получател/i, /\bадрес\b/i,
      /钱包地址/, /收款地址/, /地址/,
    ],
  },
];

// Underscores and dashes are separators in the wild: env var names
// (ALCHEMY_API_KEY), field names (api-key), CLI flags (--private-key).
// Without this, \b fails right next to an underscore and the ask is missed.
function normalizeFragment(text) {
  return String(text).replace(/[_\-]+/g, " ").replace(/\s+/g, " ").trim();
}

// An ask for one of these is never legitimate from an ordinary web page.
// No bank, no exchange, no explorer, no support desk needs your recovery
// phrase or your private key. The request itself is the attack.
const NEVER_LEGITIMATE_ASK = new Set(["SEED_PHRASE", "PRIVATE_KEY"]);

// fragments: array of strings, most specific first (label, placeholder, name,
// nearby text). The first fragment that matches wins, so a real label beats a
// vague piece of surrounding text.
function classifyAsk(fragments) {
  if (!fragments || fragments.length === 0) return { type: "UNKNOWN", evidence: null };

  for (const fragment of fragments) {
    if (!fragment) continue;
    const text = normalizeFragment(String(fragment).slice(0, 400));
    for (const rule of ASK_PATTERNS) {
      for (const re of rule.patterns) {
        const m = text.match(re);
        if (m) {
          return { type: rule.type, evidence: text.trim().slice(0, 120) };
        }
      }
    }
  }
  return { type: "UNKNOWN", evidence: null };
}

function isIllegitimateAsk(askType) {
  return NEVER_LEGITIMATE_ASK.has(askType);
}

// Which detected types are acceptable for a given ask.
const COMPATIBLE = {
  API_KEY: ["API_KEY", "BEARER_TOKEN", "UNKNOWN"],
  PASSWORD: ["PASSWORD", "UNKNOWN"],
  ADDRESS: ["ADDRESS", "UNKNOWN"],
  EMAIL: ["EMAIL", "UNKNOWN"],
  SEARCH: ["UNKNOWN", "ADDRESS", "TX_HASH"],
  SEED_PHRASE: ["SEED_PHRASE", "UNKNOWN"],
  PRIVATE_KEY: ["PRIVATE_KEY", "UNKNOWN"],
  UNKNOWN: null, // nothing to compare against
};

// The core comparison. Returns one of:
//   MATCH | MISMATCH | ILLEGITIMATE_ASK | UNKNOWN
function compare(detectedType, askType) {
  if (isIllegitimateAsk(askType)) return "ILLEGITIMATE_ASK";
  if (askType === "UNKNOWN") return "UNKNOWN";
  if (!detectedType || detectedType === "UNKNOWN") return "UNKNOWN";
  const allowed = COMPATIBLE[askType];
  if (!allowed) return "UNKNOWN";
  return allowed.includes(detectedType) ? "MATCH" : "MISMATCH";
}

if (typeof module !== "undefined") {
  module.exports = { classifyAsk, isIllegitimateAsk, compare, ASK_PATTERNS };
}
