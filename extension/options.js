// STRAZH options: the list of wallet addresses to protect, and the language.
//
// Only addresses are stored. A private key is never asked for, and if one is
// pasted here by mistake the page refuses it loudly instead of saving it -
// the settings screen of a tool like this must not become the leak.

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
// 64 hex characters is the shape of a private key.
const LOOKS_LIKE_PRIVATE_KEY = /^(0x)?[0-9a-fA-F]{64}$/;

const $ = (id) => document.getElementById(id);
let S = t(null);

function load(cb) {
  chrome.storage.local.get(["wallets", "lang"], (res) => cb((res && res.wallets) || [], (res && res.lang) || null));
}

function applyLanguage(lang) {
  S = t(lang);
  $("t-title").textContent = S.optionsTitle;
  $("t-sub").textContent = S.optionsSubtitle;
  $("t-warn").textContent = S.optionsWarn;
  $("t-name-label").textContent = S.nameLabel;
  $("t-addr-label").textContent = S.addrLabel;
  $("name").placeholder = S.namePlaceholder;
  $("add").textContent = S.addButton;
  $("empty").textContent = S.emptyList;
}

function buildLanguageSelect(current) {
  const sel = $("lang");
  sel.textContent = "";
  for (const code of LANG_ORDER) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = STRINGS[code].lang;
    if (code === current) opt.selected = true;
    sel.appendChild(opt);
  }
  sel.addEventListener("change", () => {
    chrome.storage.local.set({ lang: sel.value }, () => {
      applyLanguage(sel.value);
      render();
    });
  });
}

function render() {
  load((list) => {
    const ul = $("list");
    ul.textContent = "";
    $("empty").style.display = list.length ? "none" : "block";

    list.forEach((w, i) => {
      const li = document.createElement("li");

      const name = document.createElement("span");
      name.className = "name";
      name.textContent = w.name;

      const addr = document.createElement("span");
      addr.className = "addr";
      addr.textContent = w.address;

      const del = document.createElement("button");
      del.className = "del";
      del.textContent = "×";
      del.addEventListener("click", () => {
        load((cur) => {
          cur.splice(i, 1);
          chrome.storage.local.set({ wallets: cur }, render);
        });
      });

      li.append(name, addr, del);
      ul.appendChild(li);
    });
  });
}

$("add").addEventListener("click", () => {
  const name = $("name").value.trim() || "wallet";
  const address = $("addr").value.trim();
  const err = $("err");
  err.textContent = "";

  if (LOOKS_LIKE_PRIVATE_KEY.test(address)) {
    err.textContent = S.errIsPrivateKey;
    $("addr").value = "";
    return;
  }
  if (!ADDRESS_RE.test(address)) {
    err.textContent = S.errNotAddress;
    return;
  }

  load((list) => {
    if (list.some((w) => w.address.toLowerCase() === address.toLowerCase())) {
      err.textContent = S.errDuplicate;
      return;
    }
    list.push({ name, address });
    chrome.storage.local.set({ wallets: list }, () => {
      $("name").value = "";
      $("addr").value = "";
      render();
    });
  });
});

load((list, lang) => {
  const chosen = pickLanguage(lang);
  buildLanguageSelect(chosen);
  applyLanguage(chosen);
  render();
});
