/* ChainForge: Minimal, focused V2Ray chain builder */
import {
  Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState,
  type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent,
} from "react";
import {
  AlertCircle, Check, ChevronDown, ClipboardPaste, Copy, Download, Github, Globe,
  GitBranch, GripVertical, Laptop, LockKeyhole, Moon, Plus, RotateCcw, SlidersHorizontal, Sun, Terminal, Trash2,
  WandSparkles, X
} from "lucide-react";
import { toast, Toaster } from "sonner";
import { detectLang, dirOf, dict, fmtNum, LANG_KEY, makeT, type Lang, type TFn } from "../lib/strings";

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
  const pin = p.pinnedPeerCertSha256 || p.pinSha256 || p.pinnedPeerCert || p.cert;

  const stream: any = {
    network: network === "splithttp" ? "xhttp" : network,
    security: security === "reality" ? "reality" : security === "tls" ? "tls" : "none",
  };

  if (stream.security === "tls") {
    stream.tlsSettings = {
      serverName: sni,
      ...(fp ? { fingerprint: fp } : {}),
      ...(alpn ? { alpn } : {}),
      ...(pin ? { pinnedPeerCertSha256: pin } : {}),
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
      ...(p.host ? { host: p.host } : {})
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
  } else if (network === "httpupgrade") {
    stream.httpupgradeSettings = {
      host: p.host || sni || "",
      path: p.path || "/"
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
  if (!input) throw new Error("err.empty");
  
  if (input.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(input);
      let candidate;
      if (parsed.outbounds && Array.isArray(parsed.outbounds)) {
        candidate = parsed.outbounds.find((x: any) => !["direct", "block"].includes(x.tag)) || parsed.outbounds[0];
      } else if (parsed.protocol) {
        candidate = parsed;
      }
      if (!candidate) throw new Error("err.noOutbound");
      // Strip obsolete proxySettings and allowInsecure for modern Xray-core compatibility
      delete candidate.proxySettings;
      if (candidate.streamSettings) {
        if (candidate.streamSettings.tlsSettings && "allowInsecure" in candidate.streamSettings.tlsSettings) {
          delete candidate.streamSettings.tlsSettings.allowInsecure;
        }
        if (candidate.streamSettings.realitySettings && "allowInsecure" in candidate.streamSettings.realitySettings) {
          delete candidate.streamSettings.realitySettings.allowInsecure;
        }
        if ("allowInsecure" in candidate.streamSettings) {
          delete candidate.streamSettings.allowInsecure;
        }
        if (candidate.streamSettings.sockopt && "dialerProxy" in candidate.streamSettings.sockopt) {
          delete candidate.streamSettings.sockopt.dialerProxy;
        }
        // Upgrade legacy splithttp to xhttp
        if (candidate.streamSettings.network === "splithttp") {
          candidate.streamSettings.network = "xhttp";
          if (candidate.streamSettings.splithttpSettings && !candidate.streamSettings.xhttpSettings) {
            candidate.streamSettings.xhttpSettings = candidate.streamSettings.splithttpSettings;
            delete candidate.streamSettings.splithttpSettings;
          }
        }
        // Migrate legacy wsSettings headers.Host to modern independent host
        if (candidate.streamSettings.wsSettings) {
          if (candidate.streamSettings.wsSettings.headers?.Host && !candidate.streamSettings.wsSettings.host) {
            candidate.streamSettings.wsSettings.host = candidate.streamSettings.wsSettings.headers.Host;
            delete candidate.streamSettings.wsSettings.headers.Host;
            if (Object.keys(candidate.streamSettings.wsSettings.headers).length === 0) {
              delete candidate.streamSettings.wsSettings.headers;
            }
          }
        }
      }
      // Sanitize VLESS flow (remove legacy splice/direct/none or flow on non-TCP)
      if (candidate.protocol === "vless" && Array.isArray(candidate.settings?.vnext)) {
        const net = candidate.streamSettings?.network || "tcp";
        const sec = candidate.streamSettings?.security || "none";
        const isTcpTls = net === "tcp" && (sec === "tls" || sec === "reality");
        candidate.settings.vnext.forEach((vn: any) => {
          if (Array.isArray(vn.users)) {
            vn.users.forEach((u: any) => {
              if (u.flow) {
                const fl = String(u.flow).toLowerCase().trim();
                if (isTcpTls && fl.includes("vision")) {
                  u.flow = "xtls-rprx-vision";
                } else {
                  delete u.flow;
                }
              }
            });
          }
        });
      }
      return { ...candidate, tag: candidate.tag || fallbackTag };
    } catch (e: any) {
      throw new Error(e?.message === "err.noOutbound" ? e.message : "err.json");
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
      throw new Error("err.vmess");
    }
  }

  try {
    const uri = new URL(input.split("\n")[0].trim());
    const tag = decodeURIComponent(uri.hash.replace(/^#/, "")) || fallbackTag;
    const p = Object.fromEntries(uri.searchParams.entries());

    if (uri.protocol === "vless:") {
      const streamSettings = buildStreamSettings(p.type || p.network, p.security, p, uri.hostname);
      const rawFlow = (p.flow || "").toLowerCase().trim();
      const isTcp = streamSettings.network === "tcp";
      const isTlsOrReality = streamSettings.security === "tls" || streamSettings.security === "reality";
      const flow = isTcp && isTlsOrReality && rawFlow.includes("vision") ? "xtls-rprx-vision" : undefined;
      return { 
        tag, 
        protocol: "vless", 
        settings: { 
          vnext: [{ 
            address: uri.hostname, 
            port: Number(uri.port || 443), 
            users: [{ id: uri.username, encryption: "none", ...(flow ? { flow } : {}) }] 
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
    throw new Error(e instanceof TypeError ? "err.link" : e.message || "err.link");
  }

  throw new Error("err.unsupported");
}

type Settings = { socksPort: string; httpPort: string; logLevel: string; bypassLan: boolean };
const DEFAULT_SETTINGS: Settings = { socksPort: "10808", httpPort: "10809", logLevel: "warning", bypassLan: false };
const LOG_LEVELS = ["debug", "info", "warning", "error", "none"];
const SETTINGS_KEY = "chainforge-settings";

function loadSettings(): Settings {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "null");
    if (raw && typeof raw === "object") {
      return {
        socksPort: String(raw.socksPort ?? DEFAULT_SETTINGS.socksPort).replace(/\D/g, "").slice(0, 5),
        httpPort: String(raw.httpPort ?? DEFAULT_SETTINGS.httpPort).replace(/\D/g, "").slice(0, 5),
        logLevel: LOG_LEVELS.includes(raw.logLevel) ? raw.logLevel : DEFAULT_SETTINGS.logLevel,
        bypassLan: !!raw.bypassLan,
      };
    }
  } catch { /* storage unavailable or corrupt: use defaults */ }
  return DEFAULT_SETTINGS;
}

const isPort = (v: string) => /^\d{1,5}$/.test(v.trim()) && +v >= 1 && +v <= 65535;

/** Returns a dictionary key describing the problem, or null when the settings are usable. */
function settingsError(s: Settings): "errPort" | "errPortSame" | null {
  if (!isPort(s.socksPort) || !isPort(s.httpPort)) return "errPort";
  if (+s.socksPort === +s.httpPort) return "errPortSame";
  return null;
}

function buildConfig(hops: Hop[], settings: Settings) {
  const parsed = hops.map((hop, index) => makeOutbound(hop.value, `hop-${index + 1}`));
  const seen = new Set<string>();
  parsed.forEach((item, index) => { if (seen.has(item.tag)) item.tag = `${item.tag}-${index + 1}`; seen.add(item.tag); });
  const chained = parsed.map((item, index) => {
    if (index === 0) return item;
    const prevTag = parsed[index - 1].tag;
    const streamSettings = item.streamSettings ? { ...item.streamSettings } : {};
    const sockopt = { ...(streamSettings.sockopt || {}), dialerProxy: prevTag };
    return {
      ...item,
      streamSettings: {
        ...streamSettings,
        sockopt,
      },
    };
  });
  return {
    log: { loglevel: settings.logLevel },
    inbounds: [
      {
        tag: "socks-in",
        port: Number(settings.socksPort),
        listen: "127.0.0.1",
        protocol: "socks",
        settings: { auth: "noauth", udp: true },
        sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] }
      },
      {
        tag: "http-in",
        port: Number(settings.httpPort),
        listen: "127.0.0.1",
        protocol: "http",
        settings: {},
        sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] }
      },
    ],
    outbounds: [
      chained[chained.length - 1],
      ...chained.slice(0, -1).reverse(),
      { tag: "direct", protocol: "freedom", settings: {} },
      { tag: "block", protocol: "blackhole", settings: { response: { type: "none" } } }
    ],
    routing: {
      domainStrategy: "AsIs",
      rules: [
        ...(settings.bypassLan ? [{ type: "field", ip: ["geoip:private"], outboundTag: "direct" }] : []),
        { type: "field", outboundTag: chained[chained.length - 1].tag, network: "udp,tcp" },
      ]
    },
  };
}

/* ------------------------------------------------------------------ */
/* UI helpers                                                          */
/* ------------------------------------------------------------------ */
const roleKey = (index: number, total: number) =>
  index === 0 ? "roleEntry" : index === total - 1 ? "roleExit" : "roleRelay";

const hintKey = (index: number, total: number) =>
  index === 0 ? "hintEntry" : index === total - 1 ? "hintExit" : "hintRelay";

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
    return { ok: false as const, error: (e?.message as string) || "err.link" };
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

/* Elements that glide to their new place when the language (and so the layout direction) changes. */
const FLIP_SEL =
  ".logo, .tag, .lang-switch, .tool-btn, .route-title, .route-tools, .pin, .card, " +
  ".end-node, .slot-btn, .slot-label, .add-hop, .panel, .footer > span";
/* Text blocks that also fade in, so the swap of words is not a hard cut. */
const FADE_SEL =
  ".route-title, .route-tools, .card, .end-node, .slot-label, .add-hop, .panel, .footer > span";

const reduceMotion = () => !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/* ---- drag & drop sorting -------------------------------------------------------------- */
type DragUnit = { slot: HTMLElement | null; stop: HTMLElement; top: number; h: number };
type DragState = {
  from: number; target: number; dy: number; startY: number; lastY: number; startScroll: number;
  units: DragUnit[]; pointerId: number; raf: number; cleanup: () => void;
};

/** Positions every row for the current pointer: the dragged row follows, the rows it passes make room. */
function applyDrag(st: DragState) {
  const { units, from } = st;
  const d = units[from];
  const last = units[units.length - 1];
  let dy = st.lastY - st.startY + (window.scrollY - st.startScroll);
  dy = Math.max(units[0].top - d.top, Math.min(last.top + last.h - (d.top + d.h), dy));
  st.dy = dy;
  const center = d.top + d.h / 2 + dy;
  let target = 0;
  units.forEach((u, j) => { if (j !== from && u.top + u.h / 2 < center) target++; });
  st.target = target;
  units.forEach((u, j) => {
    let y = 0;
    if (j === from) y = dy;
    else if (target > from && j > from && j <= target) y = -d.h;
    else if (target < from && j >= target && j < from) y = d.h;
    const v = y ? `translateY(${y}px)` : "";
    u.stop.style.transform = v;
    if (u.slot) u.slot.style.transform = v;
  });
}

const focusHop = (id: number) => {
  const el = document.getElementById(`proxy-${id}`) as HTMLTextAreaElement | null;
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.focus({ preventScroll: true });
};

export default function Home() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    let saved: string | null = null;
    try { saved = localStorage.getItem("chainforge-theme"); } catch { /* storage unavailable */ }
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [lang, setLang] = useState<Lang>(detectLang);
  const [hops, setHops] = useState<Hop[]>([{ id: 1, value: "" }, { id: 2, value: "" }]);
  const [output, setOutput] = useState<any>(null);
  const [generatedKey, setGeneratedKey] = useState("");
  const [errors, setErrors] = useState<Record<number, string>>({});
  const [feedback, setFeedback] = useState<"copy" | "download" | null>(null);
  const nextId = useRef(3);
  const panelRef = useRef<HTMLElement>(null);
  const railRef = useRef<HTMLOListElement>(null);
  const genRef = useRef<HTMLButtonElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const hopFlip = useRef<Map<Element, DOMRect> | null>(null);
  const focusHandleId = useRef<number | null>(null);
  const [settings, setSettings] = useState<Settings>(loadSettings);
  const [advOpen, setAdvOpen] = useState(false);
  const [panelBtnVisible, setPanelBtnVisible] = useState(false);

  const t = useMemo(() => makeT(lang), [lang]);
  const dir = dirOf(lang);
  const fmt = (n: number, digits = 0) => fmtNum(lang, n, digits);
  /** Error messages thrown by the logic are dictionary keys ("err.*"); anything else is shown as-is. */
  const tr = (msg: string) => (msg.startsWith("err.") ? t(msg) : msg);

  const json = useMemo(() => (output ? JSON.stringify(output, null, 2) : ""), [output]);
  const html = useMemo(() => (json ? highlight(json) : ""), [json]);
  const hopsKey = useMemo(() => hops.map((h) => h.value.trim()).join("\n§\n"), [hops]);
  const configKey = useMemo(() => hopsKey + "\n#\n" + JSON.stringify(settings), [hopsKey, settings]);
  const settingsErr = settingsError(settings);
  const isCustomSettings = JSON.stringify(settings) !== JSON.stringify(DEFAULT_SETTINGS);
  const isStale = !!output && generatedKey !== configKey;
  const status: "empty" | "ready" | "stale" = !output ? "empty" : isStale ? "stale" : "ready";
  const jsonMeta = useMemo(() => {
    if (!json) return null;
    return { lines: json.split("\n").length, kb: new Blob([json]).size / 1024 };
  }, [json]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.style.colorScheme = theme;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", theme === "dark" ? "#0a101c" : "#e9eef2");
    try { localStorage.setItem("chainforge-theme", theme); } catch { /* ignore */ }
  }, [theme]);

  // Runs before paint: set lang/dir, then slide every tracked element from where it was to where it is now (FLIP).
  useLayoutEffect(() => {
    const root = document.documentElement;
    root.setAttribute("lang", lang);
    root.setAttribute("dir", dir);
    document.title = dict[lang].docTitle;
    document.querySelector('meta[name="description"]')?.setAttribute("content", dict[lang].docDesc);
    try { localStorage.setItem(LANG_KEY, lang); } catch { /* ignore */ }

    const before = flipRects.current;
    flipRects.current = null;
    if (!before) return;
    const vh = window.innerHeight;
    let i = 0;
    before.forEach((a, el) => {
      if (!el.isConnected) return;
      const b = el.getBoundingClientRect();
      const dx = a.left - b.left;
      const dy = a.top - b.top;
      if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
      if ((a.bottom < 0 && b.bottom < 0) || (a.top > vh && b.top > vh)) return;
      el.animate(
        [
          { transform: `translate(${dx}px, ${dy}px)`, opacity: el.matches(FADE_SEL) ? 0.3 : 1 },
          { transform: "translate(0, 0)", opacity: 1 },
        ],
        { duration: 520, delay: Math.min(i * 16, 160), easing: "cubic-bezier(0.22, 1, 0.36, 1)", fill: "backwards" }
      );
      i++;
    });
  }, [lang, dir]);

  useEffect(() => {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch { /* ignore */ }
  }, [settings]);

  // The bottom bar (narrow screens) is only needed while the panel's own Generate button is out of view.
  useEffect(() => {
    const el = genRef.current;
    if (!el || !("IntersectionObserver" in window)) return;
    const io = new IntersectionObserver(([entry]) => setPanelBtnVisible(entry.isIntersecting), { threshold: 0.6 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  // After hops are reordered: restore handle focus and glide every row from its old place to its new one.
  useLayoutEffect(() => {
    const fid = focusHandleId.current;
    if (fid != null) {
      focusHandleId.current = null;
      document.querySelector<HTMLElement>(`li.stop[data-hop="${fid}"] .drag-handle`)?.focus({ preventScroll: true });
    }
    const before = hopFlip.current;
    hopFlip.current = null;
    if (!before) return;
    before.forEach((a, el) => {
      if (!el.isConnected) return;
      const b = el.getBoundingClientRect();
      const dx = a.left - b.left;
      const dy = a.top - b.top;
      if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
      el.animate(
        [{ transform: `translate(${dx}px, ${dy}px)` }, { transform: "translate(0, 0)" }],
        { duration: 280, easing: "cubic-bezier(0.22, 1, 0.36, 1)" }
      );
    });
  }, [hops]);

  // Load the Persian font up front so the first switch does not shift when it arrives.
  useEffect(() => {
    (document as any).fonts?.load?.("400 16px Vazirmatn", "فا").catch?.(() => {});
    (document as any).fonts?.load?.("700 16px Vazirmatn", "فا").catch?.(() => {});
  }, []);

  const flipRects = useRef<Map<Element, DOMRect> | null>(null);
  const changeLang = (next: Lang) => {
    if (next === lang) return;
    if (!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      const rects = new Map<Element, DOMRect>();
      document.querySelectorAll(FLIP_SEL).forEach((el) => rects.set(el, el.getBoundingClientRect()));
      flipRects.current = rects;

      // The switch itself: the thumb stretches toward where it is going, the new label pops.
      const sw = document.querySelector(".lang-switch");
      const thumb = sw?.querySelector<HTMLElement>(".lang-thumb");
      if (thumb) {
        thumb.style.transformOrigin = next === "fa" ? "left center" : "right center";
        thumb.animate(
          [{ scale: "1 1" }, { scale: "1.6 0.84", offset: 0.38 }, { scale: "1 1" }],
          { duration: 460, easing: "cubic-bezier(0.22, 1, 0.36, 1)" }
        );
      }
      sw?.querySelector<HTMLElement>(`button[lang="${next}"]`)?.animate(
        [{ transform: "scale(0.78)" }, { transform: "scale(1.14)", offset: 0.55 }, { transform: "scale(1)" }],
        { duration: 420, easing: "ease-out" }
      );
    }
    setLang(next);
  };

  const toggleTheme = () => setTheme((x) => (x === "dark" ? "light" : "dark"));

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
    if (hops.length <= 2) return toast.error(t("toastMinTwo"));
    setHops((items) => items.filter((item) => item.id !== id));
    dropError(id);
  };

  const captureHopFlip = () => {
    if (reduceMotion()) return;
    const rects = new Map<Element, DOMRect>();
    railRef.current?.querySelectorAll(".stop[data-hop], .slot").forEach((el) => rects.set(el, el.getBoundingClientRect()));
    hopFlip.current = rects;
  };

  const reorderHops = (from: number, to: number) => {
    if (from === to) return;
    captureHopFlip();
    setHops((items) => {
      const next = [...items];
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });
  };

  const onHandleKey = (e: ReactKeyboardEvent<HTMLButtonElement>, index: number) => {
    const step = e.key === "ArrowUp" ? -1 : e.key === "ArrowDown" ? 1 : 0;
    if (!step) return;
    e.preventDefault();
    const to = index + step;
    if (to < 0 || to >= hops.length) return;
    focusHandleId.current = hops[index].id;
    reorderHops(index, to);
  };

  const onHandleDown = (e: ReactPointerEvent<HTMLButtonElement>, index: number) => {
    if (dragRef.current) return;
    if (e.pointerType === "mouse" && e.button !== 0) return;
    const rail = railRef.current;
    if (!rail || hops.length < 2) return;
    const stops = Array.from(rail.querySelectorAll<HTMLElement>("li.stop[data-hop]"));
    if (stops.length !== hops.length) return;
    e.preventDefault();

    const units: DragUnit[] = stops.map((stop) => {
      const prev = stop.previousElementSibling as HTMLElement | null;
      const slot = prev && prev.classList.contains("slot") ? prev : null;
      const r = stop.getBoundingClientRect();
      const top = slot ? slot.getBoundingClientRect().top : r.top;
      return { slot, stop, top, h: r.bottom - top };
    });
    try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* not supported */ }

    const st: DragState = {
      from: index, target: index, dy: 0, startY: e.clientY, lastY: e.clientY,
      startScroll: window.scrollY, units, pointerId: e.pointerId, raf: 0, cleanup: () => {},
    };
    dragRef.current = st;
    document.body.classList.add("is-dragging");
    rail.classList.add("is-sorting");
    units[index].stop.classList.add("is-dragged");

    const move = (ev: PointerEvent) => {
      if (ev.pointerId !== st.pointerId) return;
      st.lastY = ev.clientY;
      applyDrag(st);
    };
    const finish = (commit: boolean) => {
      if (dragRef.current !== st) return;
      dragRef.current = null;
      cancelAnimationFrame(st.raf);
      st.cleanup();
      const changed = commit && st.target !== st.from;
      const els = units.flatMap((u) => (u.slot ? [u.slot, u.stop] : [u.stop]));
      const tops = els.map((el) => el.getBoundingClientRect().top);
      if (changed) reorderHops(st.from, st.target); // records rects while the drag transforms are still applied
      rail.classList.remove("is-sorting");
      document.body.classList.remove("is-dragging");
      units.forEach((u) => {
        u.stop.style.transform = "";
        if (u.slot) u.slot.style.transform = "";
        u.stop.classList.remove("is-dragged");
      });
      if (!changed && !reduceMotion()) {
        els.forEach((el, i) => {
          const dy = tops[i] - el.getBoundingClientRect().top;
          if (Math.abs(dy) > 1) {
            el.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], { duration: 240, easing: "cubic-bezier(0.22, 1, 0.36, 1)" });
          }
        });
      }
    };
    const up = (ev: PointerEvent) => { if (ev.pointerId === st.pointerId) finish(true); };
    const abort = (ev: PointerEvent) => { if (ev.pointerId === st.pointerId) finish(false); };
    const esc = (ev: KeyboardEvent) => { if (ev.key === "Escape") finish(false); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", abort);
    window.addEventListener("keydown", esc);
    st.cleanup = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", abort);
      window.removeEventListener("keydown", esc);
    };

    // Scroll the page while the pointer is near the top or bottom edge.
    const tick = () => {
      if (dragRef.current !== st) return;
      const edge = 70;
      const vh = window.innerHeight;
      if (st.lastY < edge) window.scrollBy({ top: -Math.ceil((edge - st.lastY) / 4), behavior: "instant" });
      else if (st.lastY > vh - edge) window.scrollBy({ top: Math.ceil((st.lastY - (vh - edge)) / 4), behavior: "instant" });
      applyDrag(st);
      st.raf = requestAnimationFrame(tick);
    };
    st.raf = requestAnimationFrame(tick);
  };

  const generate = () => {
    const nextErrors: Record<number, string> = {};
    hops.forEach((hop) => {
      if (!hop.value.trim()) {
        nextErrors[hop.id] = "err.empty";
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
      toast.error(t("hopError", { n: fmt(firstBad + 1), msg: tr(nextErrors[hops[firstBad].id]) }));
      focusHop(hops[firstBad].id);
      return;
    }

    if (settingsErr) {
      setAdvOpen(true);
      toast.error(t("toastSettings"));
      return;
    }

    try {
      setOutput(buildConfig(hops, settings));
      setGeneratedKey(configKey);
      toast.success(t("toastGenerated"));
      // On narrow screens the bottom bar keeps Copy within reach, so the page stays where it is.
      if (window.matchMedia?.("(min-width: 921px)").matches) {
        window.setTimeout(() => {
          panelRef.current?.scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "nearest" });
        }, 60);
      }
    } catch (error: any) {
      toast.error(tr(error.message));
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
  }, [hops, lang, settings]);

  const flash = (kind: "copy" | "download") => {
    setFeedback(kind);
    window.setTimeout(() => setFeedback(null), 1800);
  };

  const copy = async () => {
    if (!json) return;
    try {
      await navigator.clipboard.writeText(json);
      flash("copy");
      toast.success(t("toastCopied"));
    } catch {
      toast.error(t("toastCopyFail"));
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
    toast.success(t("toastSaved"));
  };

  const loadSample = () => {
    setHops(SAMPLE.map((value, i) => ({ id: i + 1, value })));
    nextId.current = SAMPLE.length + 1;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    toast.info(t("toastSample"));
  };

  const reset = () => {
    setHops([{ id: 1, value: "" }, { id: 2, value: "" }]);
    nextId.current = 3;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    setFeedback(null);
    toast.success(t("toastCleared"));
  };

  const filledCount = hops.filter((h) => h.value.trim()).length;
  const routeReady = filledCount === hops.length && hops.every((h) => !errors[h.id]);

  return (
    <div className="app">
      <Toaster position="top-center" richColors theme={theme} dir={dir} />

      <header className="topbar">
        <a className="logo" href="./" aria-label={t("logoAria")}>
          <span className="logo-mark"><GitBranch size={18} aria-hidden="true" /></span>
          <span className="logo-name">ChainForge</span>
        </a>
        <div className="topbar-tools">
          <span className="tag">V2Ray · Xray</span>
          <div className="lang-switch" role="group" aria-label={t("langLabel")} data-lang={lang}>
            <span className="lang-thumb" aria-hidden="true" />
            <button
              type="button"
              lang="en"
              className={lang === "en" ? "on" : ""}
              aria-pressed={lang === "en"}
              title="English"
              onClick={() => changeLang("en")}
            >
              EN
            </button>
            <button
              type="button"
              lang="fa"
              className={lang === "fa" ? "on" : ""}
              aria-pressed={lang === "fa"}
              title="فارسی"
              onClick={() => changeLang("fa")}
            >
              فا
            </button>
          </div>
          <button
            type="button"
            className="tool-btn"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? t("themeToLight") : t("themeToDark")}
            title={theme === "dark" ? t("themeLightTitle") : t("themeDarkTitle")}
          >
            {theme === "dark" ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
          </button>
          <a
            href="https://github.com/ramin-mahmoodi/ChainForge"
            target="_blank"
            rel="noreferrer"
            className="tool-btn"
            aria-label={t("githubAria")}
            title={t("githubAria")}
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
                <h2 id="route-title">{t("route")}</h2>
                <span className="count">{t("ready", { n: fmt(filledCount), m: fmt(hops.length) })}</span>
              </div>
              <div className="route-tools">
                <button type="button" className="text-btn" onClick={loadSample}>
                  <WandSparkles size={15} aria-hidden="true" /> {t("loadSample")}
                </button>
                <button type="button" className="text-btn danger" onClick={reset}>
                  <RotateCcw size={15} aria-hidden="true" /> {t("reset")}
                </button>
              </div>
            </div>

            <ol className={`rail ${routeReady ? "rail-ready" : ""}`} ref={railRef}>
              <li className="stop">
                <span className="pin pin-end"><Laptop size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>{t("yourDevice")}</strong>
                  <span>
                    {t("localProxyOn")} <code>127.0.0.1:{settings.socksPort}</code> (SOCKS) {t("and")} <code>:{settings.httpPort}</code> (HTTP)
                  </span>
                </div>
              </li>

              {hops.map((hop, index) => (
                <Fragment key={hop.id}>
                  <li className="slot">
                    <button
                      type="button"
                      className="slot-btn"
                      onClick={() => insertHop(index)}
                      aria-label={index === 0 ? t("insertBeforeEntry") : t("insertAtPosition", { n: fmt(index + 1) })}
                    >
                      <Plus size={13} strokeWidth={2.6} aria-hidden="true" />
                    </button>
                    <span className="slot-label">{index === 0 ? t("insertAsEntry") : t("insertHere")}</span>
                  </li>
                  <li className="stop" data-hop={hop.id}>
                    <span className={`pin ${errors[hop.id] ? "pin-error" : hop.value.trim() ? "pin-filled" : ""}`}>
                      {fmt(index + 1)}
                    </span>
                    <ProxyCard
                      id={hop.id}
                      index={index}
                      total={hops.length}
                      value={hop.value}
                      error={errors[hop.id]}
                      t={t}
                      fmt={fmt}
                      tr={tr}
                      onChange={(value: string) => updateHop(hop.id, value)}
                      onClear={() => updateHop(hop.id, "")}
                      onDelete={() => removeHop(hop.id)}
                      onHandleDown={(e) => onHandleDown(e, index)}
                      onHandleKey={(e) => onHandleKey(e, index)}
                      canDelete={hops.length > 2}
                    />
                  </li>
                </Fragment>
              ))}

              <li className="stop stop-add">
                <span className="pin pin-add"><Plus size={16} aria-hidden="true" /></span>
                <button type="button" className="add-hop" onClick={addHop}>{t("addHop")}</button>
              </li>

              <li className="stop">
                <span className="pin pin-end"><Globe size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>{t("internet")}</strong>
                  <span>{t("internetHint")}</span>
                </div>
              </li>
            </ol>
          </section>

          {/* ------------------------------ Config ------------------------------ */}
          <aside className="panel" ref={panelRef} aria-labelledby="config-title">
            <div className="panel-head">
              <h2 id="config-title">{t("config")}</h2>
              <span className={`status status-${status}`}>
                {status === "empty" ? t("statusEmpty") : status === "ready" ? t("statusReady") : t("statusStale")}
              </span>
            </div>

            <button type="button" className="generate" onClick={generate} ref={genRef}>
              <span>{t("generate")}</span>
              <kbd className="kbd" aria-hidden="true">Ctrl ↵</kbd>
            </button>

            {isStale && (
              <div className="stale-note" role="status">
                <AlertCircle size={15} aria-hidden="true" />
                <span>{t("staleNote")}</span>
              </div>
            )}

            <div className={`adv ${advOpen ? "open" : ""}`}>
              <button
                type="button"
                className="adv-head"
                aria-expanded={advOpen}
                aria-controls="adv-body"
                onClick={() => setAdvOpen((o) => !o)}
              >
                <SlidersHorizontal size={15} aria-hidden="true" />
                <span>{t("advTitle")}</span>
                {settingsErr ? (
                  <AlertCircle size={14} className="adv-warn" aria-hidden="true" />
                ) : isCustomSettings ? (
                  <span className="adv-dot" aria-hidden="true" />
                ) : null}
                <ChevronDown size={16} className="adv-chev" aria-hidden="true" />
              </button>
              <div className="adv-body" id="adv-body" inert={!advOpen}>
                <div className="adv-inner">
                  <div className="adv-pad">
                    <div className="adv-grid">
                      <label className="field">
                        <span>{t("advSocks")}</span>
                        <input
                          id="adv-socks"
                          inputMode="numeric"
                          autoComplete="off"
                          value={settings.socksPort}
                          aria-invalid={!isPort(settings.socksPort) || settingsErr === "errPortSame"}
                          onChange={(e) => setSettings((x) => ({ ...x, socksPort: e.target.value.replace(/\D/g, "").slice(0, 5) }))}
                        />
                      </label>
                      <label className="field">
                        <span>{t("advHttp")}</span>
                        <input
                          id="adv-http"
                          inputMode="numeric"
                          autoComplete="off"
                          value={settings.httpPort}
                          aria-invalid={!isPort(settings.httpPort) || settingsErr === "errPortSame"}
                          onChange={(e) => setSettings((x) => ({ ...x, httpPort: e.target.value.replace(/\D/g, "").slice(0, 5) }))}
                        />
                      </label>
                      <label className="field wide">
                        <span>{t("advLog")}</span>
                        <select
                          id="adv-log"
                          value={settings.logLevel}
                          onChange={(e) => setSettings((x) => ({ ...x, logLevel: e.target.value }))}
                        >
                          {LOG_LEVELS.map((lv) => (
                            <option key={lv} value={lv}>{lv}</option>
                          ))}
                        </select>
                      </label>
                    </div>
                    <label className="check">
                      <input
                        id="adv-bypass"
                        type="checkbox"
                        checked={settings.bypassLan}
                        onChange={(e) => setSettings((x) => ({ ...x, bypassLan: e.target.checked }))}
                      />
                      <span>
                        {t("advBypass")}
                        <small>{t("advBypassHint")}</small>
                      </span>
                    </label>
                    {settingsErr && (
                      <p className="field-error" role="alert">
                        <AlertCircle size={15} aria-hidden="true" /> <span>{t(settingsErr)}</span>
                      </p>
                    )}
                    <button
                      type="button"
                      className="text-btn adv-reset"
                      onClick={() => setSettings(DEFAULT_SETTINGS)}
                      disabled={!isCustomSettings}
                    >
                      <RotateCcw size={14} aria-hidden="true" /> {t("advReset")}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className={`code ${isStale ? "is-stale" : ""}`}>
              {json ? (
                <pre tabIndex={0} aria-label={t("codeAria")} dangerouslySetInnerHTML={{ __html: html }} />
              ) : (
                <div className="code-empty">
                  <Terminal size={20} aria-hidden="true" />
                  <p>{t("emptyTitle")}</p>
                  <span>{t("emptyText")}</span>
                </div>
              )}
            </div>

            <div className="panel-foot">
              <button type="button" className="out-btn" onClick={copy} disabled={!output}>
                {feedback === "copy" ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
                <span>{feedback === "copy" ? t("copied") : t("copy")}</span>
              </button>
              <button type="button" className="out-btn solid" onClick={download} disabled={!output}>
                {feedback === "download" ? <Check size={16} aria-hidden="true" /> : <Download size={16} aria-hidden="true" />}
                <span>{t("download")}</span>
              </button>
            </div>

            <p className="panel-note">
              {jsonMeta ? <>{t("metaLine", { lines: fmt(jsonMeta.lines), kb: fmt(jsonMeta.kb, 1) })} </> : null}
              {t("clients")}
            </p>
          </aside>
        </div>
      </main>

      <footer className="footer">
        <span className="privacy">
          <LockKeyhole size={14} aria-hidden="true" /> {t("privacy")}
        </span>
        <span>{t("license")}</span>
      </footer>

      <div className={`mbar ${panelBtnVisible ? "" : "show"}`} inert={panelBtnVisible}>
        <button type="button" className="mbar-gen" onClick={generate}>{t("generate")}</button>
        <button type="button" className="mbar-copy" onClick={copy} disabled={!output}>
          {feedback === "copy" ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
          <span>{feedback === "copy" ? t("copied") : t("copy")}</span>
        </button>
      </div>
    </div>
  );
}

interface ProxyCardProps {
  id: number;
  index: number;
  total: number;
  value: string;
  error?: string;
  t: TFn;
  fmt: (n: number, digits?: number) => string;
  tr: (msg: string) => string;
  onChange: (value: string) => void;
  onClear: () => void;
  onDelete: () => void;
  onHandleDown: (e: ReactPointerEvent<HTMLButtonElement>) => void;
  onHandleKey: (e: ReactKeyboardEvent<HTMLButtonElement>) => void;
  canDelete: boolean;
}

function ProxyCard({ id, index, total, value, error, t, fmt, tr, onChange, onClear, onDelete, onHandleDown, onHandleKey, canDelete }: ProxyCardProps) {
  const protocolInfo = useMemo(() => detectProtocol(value), [value]);
  const summary = useMemo(() => summarize(value), [value]);
  const taRef = useRef<HTMLTextAreaElement>(null);
  const role = t(roleKey(index, total));
  const message = error || (summary && !summary.ok ? summary.error : "");

  // Auto-grow the textarea to fit its content
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
        toast.success(t("toastPasted", { n: fmt(index + 1) }));
      }
    } catch {
      toast.error(t("toastClipboardBlocked"));
    }
  };

  return (
    <article className={`card ${message ? "has-error" : ""}`} aria-label={t("hopLabel", { n: fmt(index + 1), role })}>
      <div className="card-top">
        <div className="card-heading">
          <label className="card-role" htmlFor={`proxy-${id}`}>{role}</label>
          {protocolInfo.badge && (
            <span className={`protocol-badge protocol-${protocolInfo.type}`}>{protocolInfo.badge}</span>
          )}
          <span className="card-hint">{t(hintKey(index, total))}</span>
        </div>

        <div className="card-actions">
          <button
            type="button"
            className="icon-btn drag-handle"
            onPointerDown={onHandleDown}
            onKeyDown={onHandleKey}
            aria-label={t("dragHandle")}
            title={t("dragHandle")}
          >
            <GripVertical size={16} aria-hidden="true" />
          </button>
          <button type="button" className="icon-btn" onClick={handlePaste} aria-label={t("pasteAria")} title={t("pasteAria")}>
            <ClipboardPaste size={15} aria-hidden="true" />
          </button>
          {value && (
            <button type="button" className="icon-btn" onClick={onClear} aria-label={t("clearAria")} title={t("clearTitle")}>
              <X size={15} aria-hidden="true" />
            </button>
          )}
          {canDelete && (
            <button type="button" className="icon-btn delete" onClick={onDelete} aria-label={t("removeAria")} title={t("removeTitle")}>
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
        placeholder={t("placeholder")}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        aria-invalid={!!message}
        aria-describedby={message ? `proxy-${id}-msg` : undefined}
        rows={2}
      />

      {message ? (
        <p className="field-error" id={`proxy-${id}-msg`} role="alert">
          <AlertCircle size={15} aria-hidden="true" /> <span>{tr(message)}</span>
        </p>
      ) : summary && summary.ok ? (
        <div className="meta-row" aria-label={t("summaryAria")}>
          <Check size={15} className="meta-ok" aria-label={t("valid")} />
          {summary.host && <span className="chip chip-host">{summary.host}{summary.port ? `:${summary.port}` : ""}</span>}
          {summary.network && <span className="chip">{summary.network}</span>}
          {summary.security && summary.security !== "none" && <span className="chip">{summary.security}</span>}
        </div>
      ) : null}
    </article>
  );
}
