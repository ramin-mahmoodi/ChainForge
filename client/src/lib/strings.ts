/* ChainForge UI text, English and Persian. */
export type Lang = "en" | "fa";
export type TFn = (key: string, vars?: Record<string, string | number>) => string;

export const LANG_KEY = "chainforge-lang";

const en = {
  docTitle: "ChainForge — V2Ray & Xray Chain Builder",
  docDesc:
    "Build multi-hop V2Ray and Xray proxy chains in your browser. Paste your server links, get one config.json. Nothing is uploaded.",

  logoAria: "ChainForge home",
  themeToLight: "Switch to light theme",
  themeToDark: "Switch to dark theme",
  themeLightTitle: "Light theme",
  themeDarkTitle: "Dark theme",
  githubAria: "View source on GitHub",
  langLabel: "Language",

  route: "Route",
  ready: "{n}/{m} ready",
  loadSample: "Load sample",
  reset: "Reset",
  yourDevice: "Your device",
  localProxyOn: "Local proxy on",
  and: "and",
  internet: "Internet",
  internetHint: "Traffic exits through the last server",
  insertBeforeEntry: "Insert a hop before the entry",
  insertAtPosition: "Insert a hop at position {n}",
  insertAsEntry: "Insert as new entry",
  insertHere: "Insert hop here",
  addHop: "Add another hop",

  config: "Config",
  statusEmpty: "Not generated",
  statusReady: "Up to date",
  statusStale: "Outdated",
  generate: "Generate chain config",
  staleNote: "Servers changed since this was generated. Generate again to update it.",
  codeAria: "Generated JSON config",
  emptyTitle: "Your config appears here.",
  emptyText: "Add at least two servers, then press Generate.",
  copy: "Copy",
  copied: "Copied",
  download: "Download JSON",
  metaLine: "{lines} lines · {kb} KB.",
  clients: "Load the file in v2rayN, v2rayNG, Nekoray, MahsaNG or Streisand.",

  privacy: "Runs 100% in your browser. No servers, no uploads.",
  license: "MIT licensed",

  roleEntry: "Entry",
  roleRelay: "Relay",
  roleExit: "Exit",
  hintEntry: "First server your traffic reaches",
  hintRelay: "Passes traffic between its neighbours",
  hintExit: "Last hop, connects to the internet",
  hopLabel: "Hop {n}, {role}",
  pasteAria: "Paste from clipboard",
  clearAria: "Clear this server",
  clearTitle: "Clear",
  dragHandle: "Drag to reorder. With the handle focused, use the arrow keys.",
  removeAria: "Remove this hop",
  removeTitle: "Remove hop",
  placeholder: "Paste a vless://, vmess://, trojan://, socks5:// link or a JSON outbound",
  summaryAria: "Server summary",
  valid: "Valid",

  advTitle: "Advanced settings",
  advSocks: "SOCKS port",
  advHttp: "HTTP port",
  advLog: "Log level",
  advBypass: "Send local network traffic directly",
  advBypassHint: "Private addresses such as 192.168.x.x skip the chain. Needs geoip.dat, which common clients include.",
  advReset: "Restore defaults",
  errPort: "Ports must be whole numbers from 1 to 65535",
  errPortSame: "SOCKS and HTTP ports must be different",
  toastSettings: "Fix the advanced settings first",

  toastMinTwo: "A chain needs at least two servers",
  hopError: "Hop {n}: {msg}",
  toastGenerated: "Chain config generated",
  toastCopied: "Config copied",
  toastCopyFail: "Copy failed. Select the text and copy it manually",
  toastSaved: "File saved",
  toastSample: "Sample servers loaded",
  toastCleared: "Form cleared",
  toastPasted: "Pasted into hop {n}",
  toastClipboardBlocked: "Clipboard access is blocked. Paste with Ctrl+V instead",

  "err.empty": "This field is empty",
  "err.noOutbound": "No usable outbound found in the JSON",
  "err.json": "Invalid JSON",
  "err.vmess": "Invalid VMess link",
  "err.link": "Invalid proxy link",
  "err.unsupported": "Unsupported format. Use VLESS, VMess, Trojan, SOCKS, HTTP or JSON",
} as const;

const fa: Record<keyof typeof en, string> = {
  docTitle: "ChainForge — ساخت زنجیره‌ی V2Ray و Xray",
  docDesc:
    "زنجیره‌ی پروکسی چندهاپه برای V2Ray و Xray را مستقیم در مرورگر بسازید. لینک سرورها را وارد کنید و config.json بگیرید؛ هیچ داده‌ای ارسال نمی‌شود.",

  logoAria: "صفحه‌ی اصلی ChainForge",
  themeToLight: "رفتن به تم روشن",
  themeToDark: "رفتن به تم تاریک",
  themeLightTitle: "تم روشن",
  themeDarkTitle: "تم تاریک",
  githubAria: "کد منبع در گیت‌هاب",
  langLabel: "زبان",

  route: "مسیر",
  ready: "{n} از {m} آماده",
  loadSample: "نمونه‌ی آماده",
  reset: "شروع دوباره",
  yourDevice: "دستگاه شما",
  localProxyOn: "پروکسی محلی روی",
  and: "و",
  internet: "اینترنت",
  internetHint: "خروج ترافیک از آخرین سرور انجام می‌شود",
  insertBeforeEntry: "اضافه کردن هاپ پیش از سرور ورودی",
  insertAtPosition: "اضافه کردن هاپ در جایگاه {n}",
  insertAsEntry: "اضافه به‌عنوان ورودی",
  insertHere: "اضافه کردن اینجا",
  addHop: "افزودن هاپ",

  config: "کانفیگ",
  statusEmpty: "هنوز ساخته نشده",
  statusReady: "به‌روز",
  statusStale: "منقضی",
  generate: "ساخت کانفیگ",
  staleNote: "از آخرین ساخت، سرورها تغییر کرده‌اند. برای به‌روز شدن کانفیگ دوباره بسازید.",
  codeAria: "پیش‌نمایش JSON کانفیگ",
  emptyTitle: "کانفیگ اینجا نشان داده می‌شود",
  emptyText: "دست‌کم دو سرور اضافه کنید و «ساخت کانفیگ» را بزنید.",
  copy: "کپی",
  copied: "کپی شد",
  download: "دانلود JSON",
  metaLine: "{lines} خط، {kb} کیلوبایت.",
  clients: "فایل خروجی را در v2rayN، v2rayNG، Nekoray، MahsaNG یا Streisand وارد کنید.",

  privacy: "همه‌چیز در مرورگر شما اجرا می‌شود؛ بدون سرور و بدون آپلود.",
  license: "مجوز MIT",

  roleEntry: "ورودی",
  roleRelay: "واسطه",
  roleExit: "خروجی",
  hintEntry: "اولین سروری که ترافیک شما به آن می‌رسد",
  hintRelay: "ترافیک را میان سرور قبلی و بعدی جابه‌جا می‌کند",
  hintExit: "آخرین هاپ؛ اتصال به اینترنت از اینجا انجام می‌شود",
  hopLabel: "هاپ {n} ({role})",
  pasteAria: "چسباندن از کلیپ‌بورد",
  clearAria: "خالی کردن این سرور",
  clearTitle: "خالی کردن",
  dragHandle: "برای جابه‌جایی بکشید. وقتی دستگیره فوکوس دارد، از کلیدهای جهت‌دار استفاده کنید.",
  removeAria: "حذف این هاپ",
  removeTitle: "حذف",
  placeholder: "لینک سرور (vless، vmess، trojan، socks5) یا JSON را اینجا بچسبانید",
  summaryAria: "مشخصات سرور",
  valid: "معتبر",

  advTitle: "تنظیمات پیشرفته",
  advSocks: "پورت SOCKS",
  advHttp: "پورت HTTP",
  advLog: "سطح لاگ",
  advBypass: "ترافیک شبکه‌ی محلی مستقیم برود",
  advBypassHint: "آدرس‌های خصوصی مثل 192.168.x.x از زنجیره رد نمی‌شوند. به geoip.dat نیاز دارد که کلاینت‌های رایج همراه دارند.",
  advReset: "بازگرداندن پیش‌فرض‌ها",
  errPort: "پورت‌ها باید عدد صحیح بین ۱ تا ۶۵۵۳۵ باشند",
  errPortSame: "پورت SOCKS و HTTP باید با هم فرق داشته باشند",
  toastSettings: "اول تنظیمات پیشرفته را اصلاح کنید",

  toastMinTwo: "برای ساخت زنجیره دست‌کم دو سرور لازم است",
  hopError: "هاپ {n}: {msg}",
  toastGenerated: "کانفیگ ساخته شد",
  toastCopied: "کانفیگ کپی شد",
  toastCopyFail: "کپی نشد. متن را انتخاب کنید و دستی کپی کنید",
  toastSaved: "فایل ذخیره شد",
  toastSample: "نمونه بارگذاری شد",
  toastCleared: "همه‌چیز پاک شد",
  toastPasted: "در هاپ {n} چسبانده شد",
  toastClipboardBlocked: "مرورگر اجازه‌ی خواندن کلیپ‌بورد را نمی‌دهد. با Ctrl+V بچسبانید",

  "err.empty": "این کادر خالی است",
  "err.noOutbound": "در این JSON هیچ outbound قابل‌استفاده‌ای نبود",
  "err.json": "JSON درست نیست",
  "err.vmess": "لینک VMess درست نیست",
  "err.link": "لینک سرور درست نیست",
  "err.unsupported": "این فرمت پشتیبانی نمی‌شود؛ VLESS، VMess، Trojan، SOCKS، HTTP یا JSON وارد کنید",
};

export const dict: Record<Lang, Record<string, string>> = { en, fa };

export const makeT = (lang: Lang): TFn => (key, vars) => {
  let s = dict[lang][key] ?? dict.en[key] ?? key;
  if (vars) for (const k of Object.keys(vars)) s = s.split(`{${k}}`).join(String(vars[k]));
  return s;
};

export function detectLang(): Lang {
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved === "en" || saved === "fa") return saved;
  } catch { /* storage unavailable */ }
  return (navigator.language || "").toLowerCase().startsWith("fa") ? "fa" : "en";
}

export const dirOf = (lang: Lang) => (lang === "fa" ? "rtl" : "ltr");

/** Format a number with the digits of the active language. */
export function fmtNum(lang: Lang, n: number, fractionDigits = 0): string {
  return n.toLocaleString(lang === "fa" ? "fa-IR" : "en-US", {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  });
}
