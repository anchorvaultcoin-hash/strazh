// Interface text in English, Russian and Chinese.
//
// Seed-phrase phishing is not an English-language problem. A person who reads
// the warning in their own language reads it; a person who does not, clicks
// past it. That is the whole reason this file exists.

const STRINGS = {
  en: {
    lang: "English",
    stopped: "STRAZH stopped this",
    warning: "STRAZH warning",
    found: "Found",
    wallet: "Wallet",
    address: "Address",
    page: "Page",
    askedFor: "Asked for",
    nothingPasted: "Nothing was pasted. The page never received it.",
    close: "Close",

    typeSeed: "recovery phrase",
    typeKey: "Ethereum private key",
    typeApiKey: "API key",
    typeUnknown: "a secret",

    ruleIllegitimateAskSeed:
      "This page is asking for your recovery phrase. No wallet, exchange, " +
      "explorer or support desk ever needs it. A page that asks for it is " +
      "trying to take everything you own.",
    ruleIllegitimateAskKey:
      "This page is asking for a private key. No legitimate service needs " +
      "your private key. Whoever has it owns the wallet.",
    ruleSeedLeaving:
      "That is a recovery phrase — the keys to every wallet derived from it. " +
      "It should never be typed into a web page, a chat, or a note.",
    ruleWrongKeyType:
      "The page asked for something else. This is the key to your wallet — " +
      "a different key, with different consequences.",
    ruleUnknownDestination:
      "This is the key to your wallet, and STRAZH cannot tell what this page " +
      "expects. Check where it is going before you continue.",

    optionsTitle: "Wallets to protect",
    optionsSubtitle:
      "STRAZH already blocks any page that asks for a recovery phrase, with " +
      "no setup. Adding your addresses lets it also name your own key.",
    optionsWarn:
      "Addresses only — the public 0x… you can show anyone. Never enter a " +
      "private key or a recovery phrase here. STRAZH does not ask for them " +
      "and has nowhere to send them.",
    nameLabel: "Name (for you)",
    namePlaceholder: "Creator wallet",
    addrLabel: "Address (0x + 40 hex characters)",
    addButton: "Add wallet",
    emptyList: "No wallets yet. Protection against phishing pages is already on.",
    errIsPrivateKey:
      "That is 64 hex characters — the shape of a PRIVATE KEY, not an address. " +
      "Nothing was saved. Paste the 0x address (40 characters) instead.",
    errNotAddress: "An address is 0x followed by exactly 40 hex characters.",
    errDuplicate: "This address is already in the list.",
    languageLabel: "Language",
  },

  ru: {
    lang: "Русский",
    stopped: "СТРАЖ остановил",
    warning: "Предупреждение СТРАЖа",
    found: "Найдено",
    wallet: "Кошелёк",
    address: "Адрес",
    page: "Страница",
    askedFor: "Просили",
    nothingPasted: "Ничего не вставлено. Страница этого не получила.",
    close: "Закрыть",

    typeSeed: "сид-фраза",
    typeKey: "приватный ключ Ethereum",
    typeApiKey: "ключ API",
    typeUnknown: "секрет",

    ruleIllegitimateAskSeed:
      "Эта страница просит вашу сид-фразу. Ни кошелёк, ни биржа, ни " +
      "обозреватель, ни поддержка её никогда не спрашивают. Страница, которая " +
      "её просит, пытается забрать всё, что у вас есть.",
    ruleIllegitimateAskKey:
      "Эта страница просит приватный ключ. Ни один честный сервис его не " +
      "спрашивает. У кого ключ — тот и владелец кошелька.",
    ruleSeedLeaving:
      "Это сид-фраза — ключи от всех кошельков, которые из неё выводятся. " +
      "Её нельзя вводить на сайте, в переписке или в заметке.",
    ruleWrongKeyType:
      "Страница просила другое. Это ключ от вашего кошелька — другой ключ и " +
      "другие последствия.",
    ruleUnknownDestination:
      "Это ключ от вашего кошелька, и СТРАЖ не может определить, чего ждёт " +
      "эта страница. Проверьте, куда он уходит, прежде чем продолжить.",

    optionsTitle: "Кошельки под защитой",
    optionsSubtitle:
      "СТРАЖ уже блокирует любую страницу, которая просит сид-фразу, — без " +
      "всякой настройки. Добавленные адреса нужны, чтобы он ещё и называл ваш " +
      "собственный ключ по имени.",
    optionsWarn:
      "Только адреса — публичные 0x…, которые можно показать кому угодно. " +
      "Никогда не вводите здесь приватный ключ или сид-фразу. СТРАЖ их не " +
      "просит, и отправлять их ему некуда.",
    nameLabel: "Название (для вас)",
    namePlaceholder: "Кошелёк Creator",
    addrLabel: "Адрес (0x и 40 знаков)",
    addButton: "Добавить кошелёк",
    emptyList: "Кошельков пока нет. Защита от фишинговых страниц уже работает.",
    errIsPrivateKey:
      "Это 64 знака — форма ПРИВАТНОГО КЛЮЧА, а не адреса. Ничего не " +
      "сохранено. Вставьте адрес 0x из 40 знаков.",
    errNotAddress: "Адрес — это 0x и ровно 40 знаков.",
    errDuplicate: "Этот адрес уже есть в списке.",
    languageLabel: "Язык",
  },

  zh: {
    lang: "中文",
    stopped: "STRAZH 已阻止",
    warning: "STRAZH 警告",
    found: "发现",
    wallet: "钱包",
    address: "地址",
    page: "页面",
    askedFor: "请求的是",
    nothingPasted: "未粘贴任何内容，页面没有收到。",
    close: "关闭",

    typeSeed: "助记词",
    typeKey: "以太坊私钥",
    typeApiKey: "API 密钥",
    typeUnknown: "机密信息",

    ruleIllegitimateAskSeed:
      "此页面正在索取您的助记词。任何钱包、交易所、区块浏览器或客服都" +
      "不需要它。索取助记词的页面，是在拿走您的全部资产。",
    ruleIllegitimateAskKey:
      "此页面正在索取私钥。任何正规服务都不会索取私钥。谁拥有私钥，" +
      "谁就拥有钱包。",
    ruleSeedLeaving:
      "这是助记词，由它派生出的每一个钱包的钥匙。不应输入到网页、" +
      "聊天或笔记中。",
    ruleWrongKeyType:
      "页面请求的是别的东西。这是您钱包的私钥——不同的钥匙，" +
      "后果也完全不同。",
    ruleUnknownDestination:
      "这是您钱包的私钥，STRAZH 无法判断此页面需要什么。继续之前请" +
      "确认它将被发送到哪里。",

    optionsTitle: "受保护的钱包",
    optionsSubtitle:
      "STRAZH 无需任何设置，已经会拦截索取助记词的页面。添加地址后，" +
      "它还能指出这是您本人的哪一个钱包。",
    optionsWarn:
      "只填地址——可以公开示人的 0x… 。切勿在此输入私钥或助记词。" +
      "STRAZH 不会索取它们，也无处发送。",
    nameLabel: "名称（仅供您自己识别）",
    namePlaceholder: "Creator 钱包",
    addrLabel: "地址（0x 加 40 个十六进制字符）",
    addButton: "添加钱包",
    emptyList: "尚未添加钱包。针对钓鱼页面的防护已经生效。",
    errIsPrivateKey:
      "这是 64 个十六进制字符——私钥的格式，不是地址。未保存任何内容。" +
      "请改为粘贴 40 个字符的 0x 地址。",
    errNotAddress: "地址是 0x 后面跟正好 40 个十六进制字符。",
    errDuplicate: "该地址已在列表中。",
    languageLabel: "语言",
  },
};

const LANG_ORDER = ["en", "ru", "zh"];

function pickLanguage(preferred) {
  if (preferred && STRINGS[preferred]) return preferred;
  const nav = (typeof navigator !== "undefined" && navigator.language) || "en";
  const short = nav.toLowerCase().split("-")[0];
  if (STRINGS[short]) return short;
  return "en";
}

function t(lang) {
  return STRINGS[pickLanguage(lang)];
}

if (typeof module !== "undefined") {
  module.exports = { STRINGS, LANG_ORDER, pickLanguage, t };
}
