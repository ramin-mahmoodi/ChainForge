import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle, ArrowDown, ArrowUp, Check, ClipboardPaste, Copy, Download, Github, Globe,
  GitBranch, Languages, Laptop, LockKeyhole, Moon, Plus, RotateCcw, Sun, Terminal, Trash2,
  WandSparkles, X, Zap
} from "lucide-react";
import { toast, Toaster } from "sonner";

type Hop = { id: number; value: string };
const SAMPLE = [
  "vless://a1b2c3d4-5678-90ab-cdef-1234567890ab@upstream.domain.com:443?security=tls&sni=upstream.domain.com&type=ws&path=%2Fws#Server-1-Upstream",
  "trojan://my-password@final.domain.com:443?security=tls&sni=final.domain.com&type=xhttp&path=%2Fxhttp-path#Server-2-Final"
];

function tryBase64(value: string) {
  const compact = value.trim().replace(/\s+/g, "");
  if (!compact || compact.includes("://") || compact.startsWith("{")) return value.trim();
  try {
    const decoded = atob(compact.replace(/-/g, "+").replace(/_/g, "/"));
    return decoded.includes("://") || decoded.trim().startsWith("{") ? decoded : value.trim();
  } catch {
    return value.trim();
  }
}

function buildStreamSettings(networkRaw: string, securityRaw: string, p: Record<string, any>, hostFallback: string) {
  const network = (networkRaw || p.type || p.net || p.network || "tcp").toLowerCase();
  const security = (securityRaw || p.tls || p.security || "none").toLowerCase();
  const sni = p.sni || p.peer || (security !== "none" ? hostFallback : undefined);
  const fp = p.fp || p.fingerprint || (security === "reality" ? "chrome" : undefined);
  const alpn = p.alpn ? (Array.isArray(p.alpn) ? p.alpn : p.alpn.split(",").map((s: string) => s.trim())) : undefined;

  const stream: any = {
    network: network === "splithttp" ? "xhttp" : network,
    security: security === "reality" ? "reality" : security === "tls" ? "tls" : "none",
  };

  if (stream.security === "tls") {
    stream.tlsSettings = {
      serverName: sni,
      ...(fp ? { fingerprint: fp } : {}),
      ...(alpn ? { alpn } : {}),
    };
  } else if (stream.security === "reality") {
    stream.realitySettings = {
      show: false,
      fingerprint: fp || "chrome",
      serverName: sni || hostFallback,
      publicKey: p.pbk || p.publicKey || "",
      shortId: p.sid || p.shortId || "",
      spiderX: p.spx || p.spiderX || "/"
    };
  }

  if (network === "ws") {
    stream.wsSettings = {
      path: p.path || "/",
      headers: p.host ? { Host: p.host } : undefined
    };
  } else if (network === "grpc") {
    stream.grpcSettings = {
      serviceName: p.serviceName || p.path || "",
      multiMode: p.mode === "multi" || p.type === "multi"
    };
  } else if (network === "xhttp" || network === "splithttp") {
    stream.xhttpSettings = {
      host: p.host || sni || "",
      path: p.path || "/",
      mode: p.mode || "auto"
    };
  } else if (network === "http" || network === "h2") {
    stream.httpSettings = {
      host: p.host ? (Array.isArray(p.host) ? p.host : p.host.split(",").map((s: string) => s.trim())) : (sni ? [sni] : undefined),
      path: p.path || "/"
    };
  }

  return stream;
}

function detectProtocol(raw: string) {
  const input = tryBase64(raw);
  if (!input) return { name: "", type: "empty", badge: "" };
  if (input.startsWith("{")) return { name: "JSON", type: "json", badge: "JSON" };
  if (input.startsWith("vmess://")) return { name: "VMess", type: "vmess", badge: "VMESS" };
  if (input.startsWith("trojan://")) {
    const isReality = input.includes("security=reality");
    return { name: isReality ? "Trojan Reality" : "Trojan", type: "trojan", badge: isReality ? "REALITY" : "TROJAN" };
  }
  if (input.startsWith("vless://")) {
    const isReality = input.includes("security=reality");
    return { name: isReality ? "VLESS Reality" : "VLESS", type: "vless", badge: isReality ? "REALITY" : "VLESS" };
  }
  if (input.startsWith("socks5://") || input.startsWith("socks://")) return { name: "SOCKS5", type: "socks", badge: "SOCKS5" };
  if (input.startsWith("http://") || input.startsWith("https://")) return { name: "HTTP", type: "http", badge: "HTTP" };
  return { name: "Unknown", type: "unknown", badge: "UNKNOWN" };
}

function makeOutbound(raw: string, fallbackTag: string) {
  const input = tryBase64(raw);
  if (!input) throw new Error("This field is empty");
  
  if (input.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(input);
      let candidate;
      if (parsed.outbounds && Array.isArray(parsed.outbounds)) {
        candidate = parsed.outbounds.find((x: any) => !["direct", "block"].includes(x.tag)) || parsed.outbounds[0];
      } else if (parsed.protocol) {
        candidate = parsed;
      }
      if (!candidate) throw new Error("No outbound found in the JSON");
      return { ...candidate, tag: candidate.tag || fallbackTag };
    } catch {
      throw new Error("Invalid JSON");
    }
  }

  if (input.startsWith("vmess://")) {
    try {
      const b64 = input.replace(/^vmess:\/\//, "").trim();
      const decoded = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
      const v = JSON.parse(decoded);
      const tag = v.ps || fallbackTag;
      const streamSettings = buildStreamSettings(v.net, v.tls, v, v.add);
      
      return {
        tag,
        protocol: "vmess",
        settings: {
          vnext: [{
            address: v.add,
            port: Number(v.port || 443),
            users: [{ id: v.id, alterId: Number(v.aid || 0), security: v.scy || "auto" }]
          }]
        },
        streamSettings
      };
    } catch {
      throw new Error("Invalid VMess link");
    }
  }

  try {
    const uri = new URL(input.split("\n")[0].trim());
    const tag = decodeURIComponent(uri.hash.replace(/^#/, "")) || fallbackTag;
    const p = Object.fromEntries(uri.searchParams.entries());

    if (uri.protocol === "vless:") {
      const streamSettings = buildStreamSettings(p.type || p.network, p.security, p, uri.hostname);
      return { 
        tag, 
        protocol: "vless", 
        settings: { 
          vnext: [{ 
            address: uri.hostname, 
            port: Number(uri.port || 443), 
            users: [{ id: uri.username, encryption: "none", ...(p.flow ? { flow: p.flow } : {}) }] 
          }] 
        }, 
        streamSettings
      };
    }

    if (uri.protocol === "trojan:") {
      const streamSettings = buildStreamSettings(p.type || p.network, p.security || "tls", p, uri.hostname);
      return {
        tag,
        protocol: "trojan",
        settings: {
          servers: [{ address: uri.hostname, port: Number(uri.port || 443), password: decodeURIComponent(uri.username) }]
        },
        streamSettings
      };
    }
    
    if (["socks5:", "socks:", "http:"].includes(uri.protocol)) {
      const protocol = uri.protocol === "http:" ? "http" : "socks";
      const server: any = { address: uri.hostname, port: Number(uri.port || (protocol === "http" ? 80 : 1080)) };
      if (uri.username) server.users = [{ user: decodeURIComponent(uri.username), pass: decodeURIComponent(uri.password) }];
      return { tag, protocol, settings: { servers: [server] } };
    }
  } catch (e: any) {
    throw new Error(e instanceof TypeError ? "Invalid proxy link" : e.message || "Invalid proxy link");
  }

  throw new Error("Unsupported format. Use VLESS, VMess, Trojan, SOCKS, HTTP or JSON");
}

function buildConfig(hops: Hop[]) {
  const parsed = hops.map((hop, index) => makeOutbound(hop.value, `hop-${index + 1}`));
  const seen = new Set<string>();
  parsed.forEach((item, index) => { if (seen.has(item.tag)) item.tag = `${item.tag}-${index + 1}`; seen.add(item.tag); });
  const chained = parsed.map((item, index) => index === 0 ? item : { ...item, proxySettings: { tag: parsed[index - 1].tag } });
  return {
    log: { loglevel: "warning" },
    inbounds: [
      { tag: "socks-in", port: 10808, listen: "127.0.0.1", protocol: "socks", settings: { auth: "noauth", udp: true } },
      { tag: "http-in", port: 10809, listen: "127.0.0.1", protocol: "http", settings: {} },
    ],
    outbounds: [
      { ...chained[chained.length - 1], proxySettings: { tag: chained.length > 1 ? chained[chained.length - 2].tag : undefined } },
      ...chained.slice(0, -1).reverse(),
      { tag: "direct", protocol: "freedom", settings: {} },
      { tag: "block", protocol: "blackhole", settings: { response: { type: "none" } } }
    ],
    routing: {
      domainStrategy: "AsIs",
      rules: [{ type: "field", outboundTag: chained[chained.length - 1].tag, network: "udp,tcp" }]
    },
  };
}

/* ------------------------------------------------------------------ */
/* Bilingual Dictionary                                              */
/* ------------------------------------------------------------------ */
type Lang = "fa" | "en";

const translations = {
  fa: {
    switchThemeLight: "تغییر به تم روشن",
    switchThemeDark: "تغییر به تم تاریک",
    githubTitle: "مشاهده سورس در گیت‌هاب",
    switchLang: "Switch to English",
    langLabel: "EN",

    route: "مسیر اتصال",
    readyCount: (filled: number, total: number) => `${filled} از ${total} سرور آماده`,
    loadSample: "داده نمونه",
    reset: "پاک‌سازی",
    yourDevice: "دستگاه شما",
    localProxy: "پروکسی محلی روی 127.0.0.1:10808 (SOCKS) و :10809 (HTTP)",
    insertEntry: "افزودن به عنوان سرور اول",
    insertHop: "افزودن سرور در این مرحله",
    addAnotherHop: "افزودن سرور بعدی",
    internet: "اینترنت آزاد",
    internetDesc: "ترافیک از طریق آخرین سرور خارج می‌شود",

    roleEntry: "سرور مبدأ (ورودی)",
    roleExit: "سرور مقصد (خروجی)",
    roleRelay: (n: number) => `سرور میانی (${n})`,
    roleHintEntry: "اولین سروری که ترافیک شما به آن متصل می‌شود",
    roleHintExit: "آخرین سرور، متصل‌کننده به اینترنت آزاد",
    roleHintRelay: "هدایت‌کننده ترافیک بین سرورهای قبل و بعد",

    paste: "جای‌گذاری",
    clear: "پاک‌کردن",
    moveUp: "انتقال به بالا",
    moveDown: "انتقال به پایین",
    removeHop: "حذف این سرور",
    inputPlaceholder: "لینک کانفیگ (vless://, vmess://, trojan://, socks5://) یا JSON را وارد کنید...",
    fieldEmpty: "این فیلد خالی است",

    config: "کانفیگ خروجی",
    statusEmpty: "تولید نشده",
    statusReady: "آماده استفاده",
    statusStale: "نیازمند به‌روزرسانی",
    generate: "تولید کانفیگ زنجیره‌ای",
    staleNote: "سرورها تغییر کرده‌اند. برای دریافت تنظیمات جدید، مجدداً دکمه تولید را بزنید.",
    codeEmptyTitle: "کانفیگ شما اینجا نمایش داده می‌شود.",
    codeEmptyDesc: "حداقل دو سرور وارد کرده و دکمه تولید کانفیگ را بزنید.",
    copy: "کپی کد",
    copied: "کپی شد",
    downloadJson: "دانلود JSON",
    panelNote: (lines: number, kb: string) => `${lines} خط · ${kb} کیلوبایت. قابل استفاده در v2rayN، v2rayNG، Nekoray، MahsaNG یا Streisand.`,
    panelNoteEmpty: "قابل استفاده در v2rayN، v2rayNG، Nekoray، MahsaNG یا Streisand.",

    privacy: "اجرای ۱۰۰٪ درون مرورگر. بدون ارسال داده به هیچ سرور خارجی.",
    license: "تحت مجوز MIT",

    pastedInto: (n: number) => `کانفیگ در سرور ${n} جای‌گذاری شد`,
    clipboardBlocked: "دسترسی به کلیپ‌بورد مسدود است. لطفاً از Ctrl+V استفاده کنید",
    atLeastTwo: "برای ساخت زنجیره حداقل به دو سرور نیاز است",
    sampleLoaded: "سرورهای نمونه بارگذاری شدند",
    formCleared: "فرم پاک‌سازی شد",
    configGenerated: "کانفیگ زنجیره‌ای ساخته شد",
    configCopied: "کانفیگ در کلیپ‌بورد کپی شد",
    copyFailed: "کپی ناموفق بود. لطفاً متن را دستی کپی کنید",
    fileSaved: "فایل کانفیگ ذخیره شد",
  },
  en: {
    switchThemeLight: "Switch to light theme",
    switchThemeDark: "Switch to dark theme",
    githubTitle: "View source on GitHub",
    switchLang: "تغییر به زبان فارسی",
    langLabel: "FA",

    route: "Route",
    readyCount: (filled: number, total: number) => `${filled}/${total} ready`,
    loadSample: "Load sample",
    reset: "Reset",
    yourDevice: "Your device",
    localProxy: "Local proxy on 127.0.0.1:10808 (SOCKS) and :10809 (HTTP)",
    insertEntry: "Insert as new entry",
    insertHop: "Insert hop here",
    addAnotherHop: "Add another hop",
    internet: "Internet",
    internetDesc: "Traffic exits through the last server",

    roleEntry: "Entry",
    roleExit: "Exit",
    roleRelay: (n: number) => `Relay (${n})`,
    roleHintEntry: "First server your traffic reaches",
    roleHintExit: "Last hop, connects to the internet",
    roleHintRelay: "Passes traffic between its neighbours",

    paste: "Paste from clipboard",
    clear: "Clear",
    moveUp: "Move up",
    moveDown: "Move down",
    removeHop: "Remove hop",
    inputPlaceholder: "Paste a vless://, vmess://, trojan://, socks5:// link or a JSON outbound",
    fieldEmpty: "This field is empty",

    config: "Config",
    statusEmpty: "Not generated",
    statusReady: "Up to date",
    statusStale: "Outdated",
    generate: "Generate chain config",
    staleNote: "Servers changed since this was generated. Generate again to update it.",
    codeEmptyTitle: "Your config appears here.",
    codeEmptyDesc: "Add at least two servers, then press Generate.",
    copy: "Copy",
    copied: "Copied",
    downloadJson: "Download JSON",
    panelNote: (lines: number, kb: string) => `${lines} lines · ${kb} KB. Load the file in v2rayN, v2rayNG, Nekoray, MahsaNG or Streisand.`,
    panelNoteEmpty: "Load the file in v2rayN, v2rayNG, Nekoray, MahsaNG or Streisand.",

    privacy: "Runs 100% in your browser. No servers, no uploads.",
    license: "MIT licensed",

    pastedInto: (n: number) => `Pasted into hop ${n}`,
    clipboardBlocked: "Clipboard access is blocked. Paste with Ctrl+V instead",
    atLeastTwo: "A chain needs at least two servers",
    sampleLoaded: "Sample servers loaded",
    formCleared: "Form cleared",
    configGenerated: "Chain config generated",
    configCopied: "Config copied",
    copyFailed: "Copy failed. Select the text and copy it manually",
    fileSaved: "File saved",
  }
};

type TranslationDict = typeof translations["fa"];

/* ------------------------------------------------------------------ */
/* UI helpers                                                          */
/* ------------------------------------------------------------------ */
const roleOf = (index: number, total: number, t: TranslationDict) =>
  index === 0 ? t.roleEntry : index === total - 1 ? t.roleExit : t.roleRelay(index + 1);

const roleHint = (index: number, total: number, t: TranslationDict) =>
  index === 0
    ? t.roleHintEntry
    : index === total - 1
      ? t.roleHintExit
      : t.roleHintRelay;

function summarize(raw: string) {
  if (!raw.trim()) return null;
  try {
    const o: any = makeOutbound(raw, "check");
    const srv = o.settings?.vnext?.[0] ?? o.settings?.servers?.[0];
    return {
      ok: true as const,
      host: srv?.address as string | undefined,
      port: srv?.port as number | undefined,
      network: o.streamSettings?.network as string | undefined,
      security: o.streamSettings?.security as string | undefined,
    };
  } catch (e: any) {
    return { ok: false as const, error: (e?.message as string) || "Invalid link" };
  }
}

/** Colourise JSON for the output panel. Input is escaped first, so user content stays inert. */
function highlight(json: string) {
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?)/g,
    (_m, str, colon, bool, num) => {
      if (str) return colon ? `<span class="tk-key">${str}</span>${colon}` : `<span class="tk-str">${str}</span>`;
      if (bool) return `<span class="tk-bool">${bool}</span>`;
      return `<span class="tk-num">${num}</span>`;
    }
  );
}

const focusHop = (id: number) => {
  const el = document.getElementById(`proxy-${id}`) as HTMLTextAreaElement | null;
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.focus({ preventScroll: true });
};

export default function Home() {
  const [lang, setLang] = useState<Lang>(() => {
    let saved: string | null = null;
    try { saved = localStorage.getItem("chainforge-lang"); } catch {}
    if (saved === "fa" || saved === "en") return saved;
    return (navigator.language && navigator.language.startsWith("fa")) ? "fa" : "fa";
  });

  const [theme, setTheme] = useState<"dark" | "light">(() => {
    let saved: string | null = null;
    try { saved = localStorage.getItem("chainforge-theme"); } catch { /* storage unavailable */ }
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  const [hops, setHops] = useState<Hop[]>([{ id: 1, value: "" }, { id: 2, value: "" }]);
  const [output, setOutput] = useState<any>(null);
  const [generatedKey, setGeneratedKey] = useState("");
  const [errors, setErrors] = useState<Record<number, string>>({});
  const [feedback, setFeedback] = useState<"copy" | "download" | null>(null);
  const nextId = useRef(3);
  const panelRef = useRef<HTMLElement>(null);

  const t = translations[lang];

  useEffect(() => {
    document.documentElement.setAttribute("lang", lang);
    document.documentElement.setAttribute("dir", lang === "fa" ? "rtl" : "ltr");
    try { localStorage.setItem("chainforge-lang", lang); } catch {}
  }, [lang]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.style.colorScheme = theme;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", theme === "dark" ? "#0a101c" : "#e9eef2");
    try { localStorage.setItem("chainforge-theme", theme); } catch { /* ignore */ }
  }, [theme]);

  const toggleTheme = () => setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  const toggleLang = () => setLang((prev) => (prev === "fa" ? "en" : "fa"));

  const json = useMemo(() => (output ? JSON.stringify(output, null, 2) : ""), [output]);
  const html = useMemo(() => (json ? highlight(json) : ""), [json]);
  const hopsKey = useMemo(() => hops.map((h) => h.value.trim()).join("\n§\n"), [hops]);
  const isStale = !!output && generatedKey !== hopsKey;
  const status: "empty" | "ready" | "stale" = !output ? "empty" : isStale ? "stale" : "ready";
  const jsonMeta = useMemo(() => {
    if (!json) return null;
    return { lines: json.split("\n").length, kb: (new Blob([json]).size / 1024).toFixed(1) };
  }, [json]);

  const dropError = (id: number) =>
    setErrors((e) => {
      if (!e[id]) return e;
      const { [id]: _drop, ...rest } = e;
      return rest;
    });

  const updateHop = (id: number, value: string) => {
    setHops((items) => items.map((item) => (item.id === id ? { ...item, value } : item)));
    dropError(id);
  };

  const addHop = () => {
    const id = nextId.current++;
    setHops((items) => [...items, { id, value: "" }]);
    window.setTimeout(() => focusHop(id), 60);
  };

  const insertHop = (at: number) => {
    const id = nextId.current++;
    setHops((items) => [...items.slice(0, at), { id, value: "" }, ...items.slice(at)]);
    window.setTimeout(() => focusHop(id), 60);
  };

  const removeHop = (id: number) => {
    if (hops.length <= 2) return toast.error(t.atLeastTwo);
    setHops((items) => items.filter((item) => item.id !== id));
    dropError(id);
  };

  const moveHop = (index: number, direction: -1 | 1) => {
    setHops((items) => {
      const next = [...items];
      const target = index + direction;
      if (target < 0 || target >= next.length) return items;
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  };

  const generate = () => {
    const nextErrors: Record<number, string> = {};
    hops.forEach((hop) => {
      if (!hop.value.trim()) {
        nextErrors[hop.id] = t.fieldEmpty;
        return;
      }
      try {
        makeOutbound(hop.value, "check");
      } catch (e: any) {
        nextErrors[hop.id] = e.message;
      }
    });
    setErrors(nextErrors);

    const firstBad = hops.findIndex((h) => nextErrors[h.id]);
    if (firstBad !== -1) {
      toast.error(`${lang === "fa" ? `سرور ${firstBad + 1}` : `Hop ${firstBad + 1}`}: ${nextErrors[hops[firstBad].id]}`);
      focusHop(hops[firstBad].id);
      return;
    }

    try {
      setOutput(buildConfig(hops));
      setGeneratedKey(hopsKey);
      toast.success(t.configGenerated);
      window.setTimeout(() => {
        const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
        panelRef.current?.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "nearest" });
      }, 60);
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        generate();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [hops, lang]);

  const flash = (kind: "copy" | "download") => {
    setFeedback(kind);
    window.setTimeout(() => setFeedback(null), 1800);
  };

  const copy = async () => {
    if (!json) return;
    try {
      await navigator.clipboard.writeText(json);
      flash("copy");
      toast.success(t.configCopied);
    } catch {
      toast.error(t.copyFailed);
    }
  };

  const download = () => {
    if (!json) return;
    const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `v2ray-chain-${hops.length}hops.json`;
    a.click();
    URL.revokeObjectURL(url);
    flash("download");
    toast.success(t.fileSaved);
  };

  const loadSample = () => {
    setHops(SAMPLE.map((value, i) => ({ id: i + 1, value })));
    nextId.current = SAMPLE.length + 1;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    toast.info(t.sampleLoaded);
  };

  const reset = () => {
    setHops([{ id: 1, value: "" }, { id: 2, value: "" }]);
    nextId.current = 3;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    setFeedback(null);
    toast.success(t.formCleared);
  };

  const filledCount = hops.filter((h) => h.value.trim()).length;
  const routeReady = filledCount === hops.length && hops.every((h) => !errors[h.id]);

  return (
    <div className="app">
      <Toaster position="top-center" richColors theme={theme} dir={lang === "fa" ? "rtl" : "ltr"} />

      <header className="topbar">
        <a className="logo" href="./" aria-label="ChainForge home">
          <span className="logo-mark"><GitBranch size={18} aria-hidden="true" /></span>
          <span className="logo-name">ChainForge</span>
        </a>
        <div className="topbar-tools">
          <button
            type="button"
            className="tool-btn lang-btn"
            onClick={toggleLang}
            aria-label={t.switchLang}
            title={t.switchLang}
          >
            <Languages size={17} aria-hidden="true" />
            <span>{t.langLabel}</span>
          </button>
          <button
            type="button"
            className="tool-btn"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? t.switchThemeLight : t.switchThemeDark}
            title={theme === "dark" ? t.switchThemeLight : t.switchThemeDark}
          >
            {theme === "dark" ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
          </button>
          <a
            href="https://github.com/ramin-mahmoodi/ChainForge"
            target="_blank"
            rel="noreferrer"
            className="tool-btn"
            aria-label={t.githubTitle}
            title={t.githubTitle}
          >
            <Github size={17} aria-hidden="true" />
          </a>
        </div>
      </header>

      <main className="shell">
        <div className="workspace">
          {/* ------------------------------ Route ------------------------------ */}
          <section className="route" aria-labelledby="route-title">
            <div className="route-head">
              <div className="route-title">
                <h2 id="route-title">{t.route}</h2>
                <span className="count">{t.readyCount(filledCount, hops.length)}</span>
              </div>
              <div className="route-tools">
                <button type="button" className="text-btn" onClick={loadSample}>
                  <WandSparkles size={15} aria-hidden="true" /> {t.loadSample}
                </button>
                <button type="button" className="text-btn danger" onClick={reset}>
                  <RotateCcw size={15} aria-hidden="true" /> {t.reset}
                </button>
              </div>
            </div>

            <ol className={`rail ${routeReady ? "rail-ready" : ""}`}>
              <li className="stop">
                <span className="pin pin-end"><Laptop size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>{t.yourDevice}</strong>
                  <span>{t.localProxy}</span>
                </div>
              </li>

              {hops.map((hop, index) => (
                <Fragment key={hop.id}>
                <li className="slot">
                  <button
                    type="button"
                    className="slot-btn"
                    onClick={() => insertHop(index)}
                    aria-label={index === 0 ? t.insertEntry : t.insertHop}
                  >
                    <Plus size={13} strokeWidth={2.6} aria-hidden="true" />
                  </button>
                  <span className="slot-label">{index === 0 ? t.insertEntry : t.insertHop}</span>
                </li>
                <li className="stop">
                  <span className={`pin ${errors[hop.id] ? "pin-error" : hop.value.trim() ? "pin-filled" : ""}`}>
                    {index + 1}
                  </span>
                  <ProxyCard
                    id={hop.id}
                    index={index}
                    total={hops.length}
                    value={hop.value}
                    error={errors[hop.id]}
                    onChange={(value: string) => updateHop(hop.id, value)}
                    onClear={() => updateHop(hop.id, "")}
                    onDelete={() => removeHop(hop.id)}
                    onMove={(dir: -1 | 1) => moveHop(index, dir)}
                    canDelete={hops.length > 2}
                    t={t}
                    lang={lang}
                  />
                </li>
                </Fragment>
              ))}

              <li className="stop stop-add">
                <span className="pin pin-add"><Plus size={16} aria-hidden="true" /></span>
                <button type="button" className="add-hop" onClick={addHop}>{t.addAnotherHop}</button>
              </li>

              <li className="stop">
                <span className="pin pin-end"><Globe size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>{t.internet}</strong>
                  <span>{t.internetDesc}</span>
                </div>
              </li>
            </ol>
          </section>

          {/* ------------------------------ Config ------------------------------ */}
          <aside className="panel" ref={panelRef} aria-labelledby="config-title">
            <div className="panel-head">
              <h2 id="config-title">{t.config}</h2>
              <span className={`status status-${status}`}>
                {status === "empty" ? t.statusEmpty : status === "ready" ? t.statusReady : t.statusStale}
              </span>
            </div>

            <button type="button" className="generate" onClick={generate}>
              <span className="generate-text">
                <Zap size={17} className="generate-icon" aria-hidden="true" />
                <span>{t.generate}</span>
              </span>
              <kbd className="kbd" aria-hidden="true">Ctrl ↵</kbd>
            </button>

            {isStale && (
              <div className="stale-note" role="status">
                <AlertCircle size={15} aria-hidden="true" />
                <span>{t.staleNote}</span>
              </div>
            )}

            <div className={`code ${isStale ? "is-stale" : ""}`}>
              {json ? (
                <pre tabIndex={0} aria-label="Generated JSON config" dangerouslySetInnerHTML={{ __html: html }} />
              ) : (
                <div className="code-empty">
                  <Terminal size={20} aria-hidden="true" />
                  <p>{t.codeEmptyTitle}</p>
                  <span>{t.codeEmptyDesc}</span>
                </div>
              )}
            </div>

            <div className="panel-foot">
              <button type="button" className="out-btn" onClick={copy} disabled={!output}>
                {feedback === "copy" ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
                <span>{feedback === "copy" ? t.copied : t.copy}</span>
              </button>
              <button type="button" className="out-btn solid" onClick={download} disabled={!output}>
                {feedback === "download" ? <Check size={16} aria-hidden="true" /> : <Download size={16} aria-hidden="true" />}
                <span>{t.downloadJson}</span>
              </button>
            </div>

            <p className="panel-note">
              {jsonMeta ? t.panelNote(jsonMeta.lines, jsonMeta.kb) : t.panelNoteEmpty}
            </p>
          </aside>
        </div>
      </main>

      <footer className="footer">
        <span className="privacy">
          <LockKeyhole size={14} aria-hidden="true" /> {t.privacy}
        </span>
        <span>{t.license}</span>
      </footer>
    </div>
  );
}

interface ProxyCardProps {
  id: number;
  index: number;
  total: number;
  value: string;
  error?: string;
  onChange: (value: string) => void;
  onClear: () => void;
  onDelete: () => void;
  onMove: (direction: -1 | 1) => void;
  canDelete: boolean;
  t: TranslationDict;
  lang: Lang;
}

function ProxyCard({ id, index, total, value, error, onChange, onClear, onDelete, onMove, canDelete, t, lang }: ProxyCardProps) {
  const protocolInfo = useMemo(() => detectProtocol(value), [value]);
  const summary = useMemo(() => summarize(value), [value]);
  const taRef = useRef<HTMLTextAreaElement>(null);
  const role = roleOf(index, total, t);
  const message = error || (summary && !summary.ok ? summary.error : "");

  useLayoutEffect(() => {
    const el = taRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(Math.max(el.scrollHeight, 64), 220)}px`;
  }, [value]);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onChange(text);
        toast.success(t.pastedInto(index + 1));
      }
    } catch {
      toast.error(t.clipboardBlocked);
    }
  };

  return (
    <article className={`card ${message ? "has-error" : ""}`} aria-label={`${lang === "fa" ? `سرور ${index + 1}` : `Hop ${index + 1}`}, ${role}`}>
      <div className="card-top">
        <div className="card-heading">
          <label className="card-role" htmlFor={`proxy-${id}`}>{role}</label>
          {protocolInfo.badge && (
            <span className={`protocol-badge protocol-${protocolInfo.type}`}>{protocolInfo.badge}</span>
          )}
          <span className="card-hint">{roleHint(index, total, t)}</span>
        </div>

        <div className="card-actions">
          <button type="button" className="icon-btn" onClick={handlePaste} aria-label={t.paste} title={t.paste}>
            <ClipboardPaste size={15} aria-hidden="true" />
          </button>
          {value && (
            <button type="button" className="icon-btn" onClick={onClear} aria-label={t.clear} title={t.clear}>
              <X size={15} aria-hidden="true" />
            </button>
          )}
          <button type="button" className="icon-btn" onClick={() => onMove(-1)} disabled={index === 0} aria-label={t.moveUp} title={t.moveUp}>
            <ArrowUp size={15} aria-hidden="true" />
          </button>
          <button type="button" className="icon-btn" onClick={() => onMove(1)} disabled={index === total - 1} aria-label={t.moveDown} title={t.moveDown}>
            <ArrowDown size={15} aria-hidden="true" />
          </button>
          {canDelete && (
            <button type="button" className="icon-btn delete" onClick={onDelete} aria-label={t.removeHop} title={t.removeHop}>
              <Trash2 size={15} aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <textarea
        ref={taRef}
        id={`proxy-${id}`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={t.inputPlaceholder}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        aria-invalid={!!message}
        aria-describedby={message ? `proxy-${id}-msg` : undefined}
        rows={2}
      />

      {message ? (
        <p className="field-error" id={`proxy-${id}-msg`} role="alert">
          <AlertCircle size={15} aria-hidden="true" /> <span>{message}</span>
        </p>
      ) : summary && summary.ok ? (
        <div className="meta-row" aria-label="Server summary">
          <Check size={15} className="meta-ok" aria-label="Valid" />
          {summary.host && <span className="chip chip-host">{summary.host}{summary.port ? `:${summary.port}` : ""}</span>}
          {summary.network && <span className="chip">{summary.network}</span>}
          {summary.security && summary.security !== "none" && <span className="chip">{summary.security}</span>}
        </div>
      ) : null}
    </article>
  );
}
