// STRAZH browser guard.
//
// Two moments are watched, and the difference matters:
//
//   focus  - the page has asked for a recovery phrase or a private key.
//            The warning appears before a single character is typed, because
//            a phrase typed by hand never produces a paste event. This is the
//            one hole in a paste-only guard, and this closes most of it.
//
//   paste  - the full check: what is this, what was asked for, do they match.
//            Decided and blocked inside the event, synchronously, because
//            afterwards the page already has the data.
//
// The extension asks for no host permissions and makes no network requests.
// Nothing about what you paste ever leaves your machine.

let KNOWN_WALLETS = {};
let LANG = null;
const warnedFields = new WeakSet();

function loadSettings() {
  try {
    chrome.storage.local.get(["wallets", "lang"], (res) => {
      const list = (res && res.wallets) || [];
      const map = {};
      for (const w of list) {
        if (w && w.address) map[String(w.address).toLowerCase()] = w.name || "your wallet";
      }
      KNOWN_WALLETS = map;
      LANG = (res && res.lang) || null;
    });
  } catch (e) {
    KNOWN_WALLETS = {};
  }
}

loadSettings();
try {
  chrome.storage.onChanged.addListener(loadSettings);
} catch (e) { /* storage unavailable: the phishing rules still work */ }

// ---------------------------------------------------------------- the ask --

// Collect what the destination says about this field, most specific first.
// A real label beats a placeholder, a placeholder beats surrounding prose.
function askFragments(el) {
  const out = [];
  if (!el || !el.tagName) return out;

  const id = el.getAttribute("id");
  if (id) {
    try {
      const label = document.querySelector('label[for="' + CSS.escape(id) + '"]');
      if (label) out.push(label.textContent);
    } catch (e) { /* malformed id */ }
  }

  const labelledby = el.getAttribute("aria-labelledby");
  if (labelledby) {
    for (const part of labelledby.split(/\s+/)) {
      const node = document.getElementById(part);
      if (node) out.push(node.textContent);
    }
  }

  out.push(el.getAttribute("aria-label"));
  out.push(el.getAttribute("placeholder"));
  out.push(el.getAttribute("name"));
  out.push(el.getAttribute("id"));
  out.push(el.getAttribute("autocomplete"));
  out.push(el.getAttribute("data-testid"));

  const wrapping = el.closest("label");
  if (wrapping) out.push(wrapping.textContent);

  // Everything below is unbound text - it belongs to the neighbourhood, not to
  // this field. It is used only when it is short enough to be a label and not
  // a paragraph, because otherwise one mention of "recovery phrase" anywhere
  // on a page would make every field on that page raise an alarm. That bug
  // was real and was caught by a browser test, not by reading the code.
  const NEARBY_LIMIT = 90;

  let prev = el.previousElementSibling;
  for (let i = 0; i < 2 && prev; i++) {
    const text = (prev.textContent || "").trim();
    if (text && text.length <= NEARBY_LIMIT && prev.querySelectorAll("input, textarea, select").length === 0) {
      out.push(text);
    }
    prev = prev.previousElementSibling;
  }

  // The parent counts only when it is a tight wrapper around this one field -
  // a form row, not a section of the page.
  const parent = el.parentElement;
  if (parent) {
    const text = (parent.textContent || "").trim();
    const fieldsInside = parent.querySelectorAll("input, textarea, select").length;
    if (text && text.length <= NEARBY_LIMIT && fieldsInside <= 1) out.push(text);
  }

  return out.filter(Boolean).map((s) => String(s).replace(/\s+/g, " ").trim().slice(0, 300));
}

// ------------------------------------------------------------- the warning --

function messageFor(finding, S) {
  switch (finding.rule) {
    case "ILLEGITIMATE_ASK":
      return finding.ask === "SEED_PHRASE"
        ? S.ruleIllegitimateAskSeed
        : S.ruleIllegitimateAskKey;
    case "SEED_PHRASE_LEAVING":
      return S.ruleSeedLeaving;
    case "WRONG_KEY_TYPE":
      return S.ruleWrongKeyType;
    default:
      return S.ruleUnknownDestination;
  }
}

function detectedLabel(finding, S) {
  if (finding.rule === "ILLEGITIMATE_ASK") {
    return finding.ask === "SEED_PHRASE" ? S.typeSeed : S.typeKey;
  }
  if (finding.detected === "SEED_PHRASE") return S.typeSeed;
  if (finding.detected === "ETH_PRIVATE_KEY") return S.typeKey;
  return S.typeUnknown;
}

function askLabel(askType, S) {
  switch (askType) {
    case "API_KEY": return S.typeApiKey;
    case "SEED_PHRASE": return S.typeSeed;
    case "PRIVATE_KEY": return S.typeKey;
    default: return null;
  }
}

function showWarning(finding) {
  const S = t(LANG);
  const blocking = finding.action === "STOP";

  const old = document.getElementById("strazh-overlay-host");
  if (old) old.remove();

  const host = document.createElement("div");
  host.id = "strazh-overlay-host";
  host.style.cssText = "all: initial; position: fixed; inset: 0; z-index: 2147483647;";
  const shadow = host.attachShadow({ mode: "closed" });

  const accent = blocking ? "#d64545" : "#d1a03a";
  const rows = [];
  rows.push([S.found, detectedLabel(finding, S)]);
  if (finding.wallet) rows.push([S.wallet, finding.wallet]);
  if (finding.address) rows.push([S.address, finding.address]);
  const asked = askLabel(finding.ask, S);
  if (asked && finding.rule !== "ILLEGITIMATE_ASK") rows.push([S.askedFor, asked]);
  rows.push([S.page, location.host || location.href]);

  const wrap = document.createElement("div");
  wrap.innerHTML =
    '<style>' +
    '.backdrop{position:fixed;inset:0;background:rgba(10,12,18,.74);display:flex;' +
    'align-items:center;justify-content:center;' +
    'font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}' +
    '.card{background:#14161c;color:#e9edf5;width:min(560px,calc(100vw - 32px));' +
    'border:1px solid #2a2f3c;border-left:6px solid ' + accent + ';border-radius:10px;' +
    'padding:24px 26px;box-shadow:0 24px 64px rgba(0,0,0,.55)}' +
    '.title{font-size:19px;font-weight:650;margin:0 0 16px;letter-spacing:.01em}' +
    '.row{display:flex;gap:10px;font-size:14px;line-height:1.55;margin:3px 0}' +
    '.k{color:#97a1b5;min-width:96px;flex:none}' +
    '.v{color:#e9edf5;word-break:break-all}' +
    '.note{margin:16px 0 0;font-size:14px;line-height:1.6;color:#c8cfdd}' +
    '.verdict{margin:16px 0 0;font-size:14px;font-weight:600;color:#ff9a9a}' +
    '.actions{margin-top:22px;display:flex;justify-content:flex-end}' +
    'button{font:inherit;font-size:14px;padding:9px 18px;border-radius:7px;' +
    'border:1px solid #4a5165;background:#232734;color:#e9edf5;cursor:pointer}' +
    'button:hover{background:#2c3142}' +
    '</style>' +
    '<div class="backdrop"><div class="card" role="alertdialog" aria-modal="true">' +
    '<p class="title">' + (blocking ? "⛔ " + S.stopped : "⚠ " + S.warning) + '</p>' +
    '<div id="rows"></div>' +
    '<p class="note" id="note"></p>' +
    (blocking ? '<p class="verdict">❌ ' + S.nothingPasted + '</p>' : '') +
    '<div class="actions"><button id="ok"></button></div>' +
    '</div></div>';

  shadow.appendChild(wrap);

  const rowsEl = shadow.getElementById("rows");
  for (const [k, v] of rows) {
    const row = document.createElement("div");
    row.className = "row";
    const ke = document.createElement("span");
    ke.className = "k";
    ke.textContent = k;
    const ve = document.createElement("span");
    ve.className = "v";
    ve.textContent = v;
    row.append(ke, ve);
    rowsEl.appendChild(row);
  }
  shadow.getElementById("note").textContent = messageFor(finding, S);
  const okBtn = shadow.getElementById("ok");
  okBtn.textContent = S.close;

  const close = () => host.remove();
  okBtn.addEventListener("click", close);
  shadow.querySelector(".backdrop").addEventListener("click", (e) => {
    if (e.target === shadow.querySelector(".backdrop")) close();
  });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });

  document.documentElement.appendChild(host);
  okBtn.focus();
}

// ------------------------------------------------------------------ hooks --

// A page that asks for a recovery phrase is dangerous before anything is
// typed, so this fires on focus rather than on paste.
document.addEventListener(
  "focusin",
  (event) => {
    const el = event.target;
    if (!el || !el.tagName) return;
    const tag = el.tagName.toLowerCase();
    if (tag !== "input" && tag !== "textarea" && !el.isContentEditable) return;
    if (warnedFields.has(el)) return;

    const ask = classifyAsk(askFragments(el));
    if (!isIllegitimateAsk(ask.type)) return;

    warnedFields.add(el);
    showWarning({
      action: "STOP",
      rule: "ILLEGITIMATE_ASK",
      ask: ask.type,
      detected: "UNKNOWN",
      evidence: ask.evidence,
    });
  },
  true
);

document.addEventListener(
  "paste",
  (event) => {
    let text = "";
    try {
      text = (event.clipboardData || window.clipboardData).getData("text");
    } catch (e) {
      return;
    }
    if (!text) return;

    const finding = decide(
      text,
      {
        askFragments: askFragments(event.target),
        destination: location.host,
      },
      KNOWN_WALLETS,
      {
        keccak256: keccak256,
        privateKeyToPubkey: privateKeyToPubkey,
        sha256: sha256,
        BIP39_WORDS: BIP39_WORDS,
        BIP39_INDEX: BIP39_INDEX,
        findSeedPhrase: findSeedPhrase,
        classifyAsk: classifyAsk,
        isIllegitimateAsk: isIllegitimateAsk,
        compare: compare,
      }
    );

    if (finding.action === "STOP") {
      // Block first, explain after. Approval never resumes this event.
      event.preventDefault();
      event.stopImmediatePropagation();
      showWarning(finding);
    } else if (finding.action === "WARN") {
      showWarning(finding);
    }
  },
  true // capture phase: before the page's own handlers
);
