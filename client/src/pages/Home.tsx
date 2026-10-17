/* ChainForge: Minimal, focused V2Ray chain builder */
import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle, ArrowDown, ArrowUp, Check, ClipboardPaste, Copy, Download, Github, Globe,
  GitBranch, Laptop, LockKeyhole, Moon, Plus, RotateCcw, Sun, Terminal, Trash2,
  WandSparkles, X
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
/* UI helpers                                                          */
/* ------------------------------------------------------------------ */
const roleOf = (index: number, total: number) =>
  index === 0 ? "Entry" : index === total - 1 ? "Exit" : "Relay";

const roleHint = (index: number, total: number) =>
  index === 0
    ? "First server your traffic reaches"
    : index === total - 1
      ? "Last hop, connects to the internet"
      : "Passes traffic between its neighbours";

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

  const json = useMemo(() => (output ? JSON.stringify(output, null, 2) : ""), [output]);
  const html = useMemo(() => (json ? highlight(json) : ""), [json]);
  const hopsKey = useMemo(() => hops.map((h) => h.value.trim()).join("\n§\n"), [hops]);
  const isStale = !!output && generatedKey !== hopsKey;
  const status: "empty" | "ready" | "stale" = !output ? "empty" : isStale ? "stale" : "ready";
  const jsonMeta = useMemo(() => {
    if (!json) return null;
    return { lines: json.split("\n").length, kb: (new Blob([json]).size / 1024).toFixed(1) };
  }, [json]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.style.colorScheme = theme;
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", theme === "dark" ? "#0a101c" : "#e9eef2");
    try { localStorage.setItem("chainforge-theme", theme); } catch { /* ignore */ }
  }, [theme]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

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
    if (hops.length <= 2) return toast.error("A chain needs at least two servers");
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
        nextErrors[hop.id] = "This field is empty";
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
      toast.error(`Hop ${firstBad + 1}: ${nextErrors[hops[firstBad].id]}`);
      focusHop(hops[firstBad].id);
      return;
    }

    try {
      setOutput(buildConfig(hops));
      setGeneratedKey(hopsKey);
      toast.success("Chain config generated");
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
  }, [hops]);

  const flash = (kind: "copy" | "download") => {
    setFeedback(kind);
    window.setTimeout(() => setFeedback(null), 1800);
  };

  const copy = async () => {
    if (!json) return;
    try {
      await navigator.clipboard.writeText(json);
      flash("copy");
      toast.success("Config copied");
    } catch {
      toast.error("Copy failed. Select the text and copy it manually");
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
    toast.success("File saved");
  };

  const loadSample = () => {
    setHops(SAMPLE.map((value, i) => ({ id: i + 1, value })));
    nextId.current = SAMPLE.length + 1;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    toast.info("Sample servers loaded");
  };

  const reset = () => {
    setHops([{ id: 1, value: "" }, { id: 2, value: "" }]);
    nextId.current = 3;
    setOutput(null);
    setGeneratedKey("");
    setErrors({});
    setFeedback(null);
    toast.success("Form cleared");
  };

  const filledCount = hops.filter((h) => h.value.trim()).length;
  const routeReady = filledCount === hops.length && hops.every((h) => !errors[h.id]);

  return (
    <div className="app">
      <Toaster position="top-center" richColors theme={theme} />

      <header className="topbar">
        <a className="logo" href="./" aria-label="ChainForge home">
          <span className="logo-mark"><GitBranch size={18} aria-hidden="true" /></span>
          <span className="logo-name">ChainForge</span>
        </a>
        <div className="topbar-tools">
          <span className="tag">V2Ray · Xray</span>
          <button
            type="button"
            className="tool-btn"
            onClick={toggleTheme}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            title={theme === "dark" ? "Light theme" : "Dark theme"}
          >
            {theme === "dark" ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
          </button>
          <a
            href="https://github.com/ramin-mahmoodi/ChainForge"
            target="_blank"
            rel="noreferrer"
            className="tool-btn"
            aria-label="View source on GitHub"
            title="View source on GitHub"
          >
            <Github size={17} aria-hidden="true" />
          </a>
        </div>
      </header>

      <main className="shell">
        <section className="hero">
          <h1>Build a multi-hop proxy chain in your browser.</h1>
          <p>
            Paste your server links in order. ChainForge writes one Xray / V2Ray config that sends traffic
            through every server in turn. Nothing leaves this page.
          </p>
        </section>

        <div className="workspace">
          {/* ------------------------------ Route ------------------------------ */}
          <section className="route" aria-labelledby="route-title">
            <div className="route-head">
              <div className="route-title">
                <h2 id="route-title">Route</h2>
                <span className="count">{filledCount}/{hops.length} ready</span>
              </div>
              <div className="route-tools">
                <button type="button" className="text-btn" onClick={loadSample}>
                  <WandSparkles size={15} aria-hidden="true" /> Load sample
                </button>
                <button type="button" className="text-btn danger" onClick={reset}>
                  <RotateCcw size={15} aria-hidden="true" /> Reset
                </button>
              </div>
            </div>

            <ol className={`rail ${routeReady ? "rail-ready" : ""}`}>
              <li className="stop">
                <span className="pin pin-end"><Laptop size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>Your device</strong>
                  <span>Local proxy on <code>127.0.0.1:10808</code> (SOCKS) and <code>:10809</code> (HTTP)</span>
                </div>
              </li>

              {hops.map((hop, index) => (
                <Fragment key={hop.id}>
                <li className="slot">
                  <button
                    type="button"
                    className="slot-btn"
                    onClick={() => insertHop(index)}
                    aria-label={index === 0 ? "Insert a hop before the entry" : `Insert a hop at position ${index + 1}`}
                  >
                    <Plus size={13} strokeWidth={2.6} aria-hidden="true" />
                  </button>
                  <span className="slot-label">{index === 0 ? "Insert as new entry" : "Insert hop here"}</span>
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
                  />
                </li>
                </Fragment>
              ))}

              <li className="stop stop-add">
                <span className="pin pin-add"><Plus size={16} aria-hidden="true" /></span>
                <button type="button" className="add-hop" onClick={addHop}>Add another hop</button>
              </li>

              <li className="stop">
                <span className="pin pin-end"><Globe size={17} aria-hidden="true" /></span>
                <div className="end-node">
                  <strong>Internet</strong>
                  <span>Traffic exits through the last server</span>
                </div>
              </li>
            </ol>
          </section>

          {/* ------------------------------ Config ------------------------------ */}
          <aside className="panel" ref={panelRef} aria-labelledby="config-title">
            <div className="panel-head">
              <h2 id="config-title">Config</h2>
              <span className={`status status-${status}`}>
                {status === "empty" ? "Not generated" : status === "ready" ? "Up to date" : "Outdated"}
              </span>
            </div>

            <button type="button" className="generate" onClick={generate}>
              <span>Generate chain config</span>
              <kbd className="kbd" aria-hidden="true">Ctrl ↵</kbd>
            </button>

            {isStale && (
              <div className="stale-note" role="status">
                <AlertCircle size={15} aria-hidden="true" />
                <span>Servers changed since this was generated. Generate again to update it.</span>
              </div>
            )}

            <div className={`code ${isStale ? "is-stale" : ""}`}>
              {json ? (
                <pre tabIndex={0} aria-label="Generated JSON config" dangerouslySetInnerHTML={{ __html: html }} />
              ) : (
                <div className="code-empty">
                  <Terminal size={20} aria-hidden="true" />
                  <p>Your config appears here.</p>
                  <span>Add at least two servers, then press Generate.</span>
                </div>
              )}
            </div>

            <div className="panel-foot">
              <button type="button" className="out-btn" onClick={copy} disabled={!output}>
                {feedback === "copy" ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
                <span>{feedback === "copy" ? "Copied" : "Copy"}</span>
              </button>
              <button type="button" className="out-btn solid" onClick={download} disabled={!output}>
                {feedback === "download" ? <Check size={16} aria-hidden="true" /> : <Download size={16} aria-hidden="true" />}
                <span>Download JSON</span>
              </button>
            </div>

            <p className="panel-note">
              {jsonMeta ? <>{jsonMeta.lines} lines · {jsonMeta.kb} KB. </> : null}
              Load the file in v2rayN, v2rayNG, Nekoray, MahsaNG or Streisand.
            </p>
          </aside>
        </div>
      </main>

      <footer className="footer">
        <span className="privacy">
          <LockKeyhole size={14} aria-hidden="true" /> Runs 100% in your browser. No servers, no uploads.
        </span>
        <span>MIT licensed</span>
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
}

function ProxyCard({ id, index, total, value, error, onChange, onClear, onDelete, onMove, canDelete }: ProxyCardProps) {
  const protocolInfo = useMemo(() => detectProtocol(value), [value]);
  const summary = useMemo(() => summarize(value), [value]);
  const taRef = useRef<HTMLTextAreaElement>(null);
  const role = roleOf(index, total);
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
        toast.success(`Pasted into hop ${index + 1}`);
      }
    } catch {
      toast.error("Clipboard access is blocked. Paste with Ctrl+V instead");
    }
  };

  return (
    <article className={`card ${message ? "has-error" : ""}`} aria-label={`Hop ${index + 1}, ${role}`}>
      <div className="card-top">
        <div className="card-heading">
          <label className="card-role" htmlFor={`proxy-${id}`}>{role}</label>
          {protocolInfo.badge && (
            <span className={`protocol-badge protocol-${protocolInfo.type}`}>{protocolInfo.badge}</span>
          )}
          <span className="card-hint">{roleHint(index, total)}</span>
        </div>

        <div className="card-actions">
          <button type="button" className="icon-btn" onClick={handlePaste} aria-label="Paste from clipboard" title="Paste from clipboard">
            <ClipboardPaste size={15} aria-hidden="true" />
          </button>
          {value && (
            <button type="button" className="icon-btn" onClick={onClear} aria-label="Clear this server" title="Clear">
              <X size={15} aria-hidden="true" />
            </button>
          )}
          <button type="button" className="icon-btn" onClick={() => onMove(-1)} disabled={index === 0} aria-label="Move up" title="Move up">
            <ArrowUp size={15} aria-hidden="true" />
          </button>
          <button type="button" className="icon-btn" onClick={() => onMove(1)} disabled={index === total - 1} aria-label="Move down" title="Move down">
            <ArrowDown size={15} aria-hidden="true" />
          </button>
          {canDelete && (
            <button type="button" className="icon-btn delete" onClick={onDelete} aria-label="Remove this hop" title="Remove hop">
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
        placeholder="Paste a vless://, vmess://, trojan://, socks5:// link or a JSON outbound"
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
