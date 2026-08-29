/* ChainForge: Minimal, focused V2Ray chain builder */
import { useEffect, useMemo, useState } from "react";
import {
  ArrowDown, ArrowLeft, ArrowUp, Check, CheckCircle2, Copy, Download,
  Github, GitBranch, LockKeyhole, Moon, Plus, RotateCcw, Sparkles, Sun, Eye, EyeOff,
  Trash2, Upload, WandSparkles, X, Terminal
} from "lucide-react";
import { toast } from "sonner";

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
  return { name: "ناشناخته", type: "unknown", badge: "UNKNOWN" };
}

function makeOutbound(raw: string, fallbackTag: string) {
  const input = tryBase64(raw);
  if (!input) throw new Error("یکی از فیلدها خالی است");
  
  if (input.trim().startsWith("{")) {
    try {
      const parsed = JSON.parse(input);
      let candidate;
      if (parsed.outbounds && Array.isArray(parsed.outbounds)) {
        candidate = parsed.outbounds.find((x: any) => !["direct", "block"].includes(x.tag)) || parsed.outbounds[0];
      } else if (parsed.protocol) {
        candidate = parsed;
      }
      if (!candidate) throw new Error("کانفیگ معتبری در JSON یافت نشد");
      return { ...candidate, tag: candidate.tag || fallbackTag };
    } catch {
      throw new Error("فرمت JSON نامعتبر است");
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
      throw new Error("فرمت لینک VMess نامعتبر است");
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
    throw new Error(e.message || "لینک اتصال نامعتبر است");
  }

  throw new Error("فرمت وارد شده پشتیبانی نمی‌شود (VLESS, VMess, Trojan, SOCKS, HTTP)");
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

export default function Home() {
  const [theme, setTheme] = useState(() => localStorage.getItem("chainforge-theme") || "dark");
  const [hops, setHops] = useState<Hop[]>([{ id: 1, value: "" }, { id: 2, value: "" }]);
  const [output, setOutput] = useState<any>(null);
  const [feedback, setFeedback] = useState<"copy" | "download" | null>(null);
  const [showOutput, setShowOutput] = useState(false);

  const json = useMemo(() => output ? JSON.stringify(output, null, 2) : "", [output]);
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("chainforge-theme", next);
  };

  const updateHop = (id: number, value: string) => {
    setHops((items) => items.map((item) => item.id === id ? { ...item, value } : item));
  };

  const addHop = () => {
    setHops((items) => [...items, { id: Date.now(), value: "" }]);
  };

  const removeHop = (id: number) => {
    if (hops.length <= 2) return toast.error("حداقل دو سرور برای ساخت زنجیره لازم است");
    setHops((items) => items.filter((item) => item.id !== id));
    setOutput(null);
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
    try {
      if (hops.some((hop) => !hop.value.trim())) {
        throw new Error("لطفاً تمام سرورها را وارد کنید");
      }
      setOutput(buildConfig(hops));
      setShowOutput(false);
      toast.success("کانفیگ زنجیره‌ای ساخته شد");
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
    await navigator.clipboard.writeText(json);
    flash("copy");
    toast.success("کانفیگ کپی شد");
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
    toast.success("فایل ذخیره شد");
  };

  const loadSample = () => {
    setHops(SAMPLE.map((value, i) => ({ id: i + 1, value })));
    setOutput(null);
    toast.info("نمونه بارگذاری شد");
  };

  const reset = () => {
    setHops([{ id: 1, value: "" }, { id: 2, value: "" }]);
    setOutput(null);
    setShowOutput(false);
    setFeedback(null);
    toast.success("فرم پاک شد");
  };

  return (
    <main className={`cf-shell ${theme === "light" ? "theme-light" : ""}`}>
      <div className="cf-grid" />
      
      {/* Clean Minimal Header */}
      <header className="cf-header">
        <div className="brand">
          <span className="brand-mark"><GitBranch size={18} /></span>
          <span className="brand-name">ChainForge</span>
        </div>
        <nav className="top-nav">
          <button className="theme-toggle" onClick={toggleTheme} aria-label="تغییر تم">
            {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          <a href="https://github.com/ramin-mahmoodi/ChainForge" target="_blank" rel="noreferrer" className="github-link" title="مشاهده در گیت‌هاب">
            <Github size={15} />
          </a>
        </nav>
      </header>

      <section className="builder-layout">
        <div className="builder-main">
          
          {/* Visual Minimal Flow Steps */}
          <div className="chain-flow" aria-label="مراحل زنجیره">
            {hops.map((hop, idx) => {
              const proto = detectProtocol(hop.value);
              const isFirst = idx === 0;
              const isLast = idx === hops.length - 1;
              const title = isFirst ? "۱. سرور مبدأ" : isLast ? `${idx + 1}. سرور مقصد` : `${idx + 1}. سرور میانی`;
              const isFilled = hop.value.trim().length > 0;

              return (
                <div key={hop.id} className="flow-step-wrap">
                  <div className={`flow-step ${isFilled ? "step-filled" : ""}`}>
                    <span className="flow-num">{idx + 1}</span>
                    <div className="flow-text">
                      <strong>{title}</strong>
                      <small>{proto.badge || (isFilled ? "آماده" : "خالی")}</small>
                    </div>
                  </div>
                  <div className="flow-arrow">›</div>
                </div>
              );
            })}

            {/* Output Node */}
            <div className={`flow-step ${output ? "step-ready" : "step-pending"}`}>
              <span className="flow-num">✓</span>
              <div className="flow-text">
                <strong>کانفیگ نهایی</strong>
                <small>{output ? "آماده استفاده" : "منتظر تولید"}</small>
              </div>
            </div>
          </div>

          {/* Workbench Action Header */}
          <div className="section-heading">
            <div className="heading-title">
              <h2>تنظیم پروکسی‌ها</h2>
              <span className="count-pill">{hops.length} سرور</span>
            </div>
            <div className="heading-actions">
              <button className="ghost-button" onClick={loadSample} title="بارگذاری نمونه">
                <WandSparkles size={14} /> <span>داده نمونه</span>
              </button>
              <button className="add-button" onClick={addHop}>
                <Plus size={15} /> <span>افزودن سرور</span>
              </button>
            </div>
          </div>

          {/* Hop List */}
          <div className="hop-list">
            {hops.map((hop, index) => (
              <div className="hop-row" key={hop.id}>
                <ProxyCard
                  number={index + 1}
                  isFirst={index === 0}
                  isLast={index === hops.length - 1}
                  value={hop.value}
                  onChange={(value: string) => updateHop(hop.id, value)}
                  onClear={() => updateHop(hop.id, "")}
                  onDelete={() => removeHop(hop.id)}
                  canDelete={hops.length > 2}
                />
                
                {/* Reorder Buttons */}
                <div className="reorder">
                  <button
                    onClick={() => moveHop(index, -1)}
                    disabled={index === 0}
                    title="انتقال به بالا"
                  >
                    <ArrowUp size={14} />
                  </button>
                  <button
                    onClick={() => moveHop(index, 1)}
                    disabled={index === hops.length - 1}
                    title="انتقال به پایین"
                  >
                    <ArrowDown size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Action Row */}
          <div className="action-row">
            <button className="primary-button" onClick={generate}>
              <Sparkles size={16} />
              <span>تولید کانفیگ زنجیره‌ای</span>
            </button>
            <button className="reset-button" onClick={reset}>
              <RotateCcw size={14} />
              <span>پاک‌سازی</span>
            </button>
          </div>

          {/* Output Panel */}
          <div className="output-panel">
            <div className="output-head">
              <div className="output-title">
                <Terminal size={15} />
                <h3>کانفیگ خروجی (V2Ray JSON)</h3>
              </div>
              <div className="output-actions-top">
                <button
                  className="secondary-button"
                  onClick={copy}
                  disabled={!output}
                >
                  {feedback === "copy" ? <Check size={14} /> : <Copy size={14} />}
                  <span>{feedback === "copy" ? "کپی شد" : "کپی"}</span>
                </button>
                <button
                  className="download-button"
                  onClick={download}
                  disabled={!output}
                >
                  {feedback === "download" ? <Check size={14} /> : <Download size={14} />}
                  <span>دانلود JSON</span>
                </button>
              </div>
            </div>

            <div className={`code-window ${showOutput ? "output-expanded" : "output-collapsed"}`}>
              <pre>
                {json || <span className="code-empty">// پس از وارد کردن سرورها، دکمه «تولید کانفیگ» را بزنید.</span>}
              </pre>
            </div>
            
            {output && (
              <div className="output-footer">
                <button
                  className="toggle-output-btn"
                  onClick={() => setShowOutput(!showOutput)}
                >
                  {showOutput ? <EyeOff size={13} /> : <Eye size={13} />}
                  <span>{showOutput ? "نمایش کمتر" : "نمایش تمام کد"}</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Clean Minimal Footer */}
      <footer className="cf-footer">
        <span>ChainForge — سازنده محلی کانفیگ‌های زنجیره‌ای</span>
        <span>پردازش ۱۰۰٪ در مرورگر شما انجام می‌شود</span>
      </footer>
    </main>
  );
}

function ProxyCard({ number, isFirst, isLast, value, onChange, onClear, onDelete, canDelete }: any) {
  const protocolInfo = useMemo(() => detectProtocol(value), [value]);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onChange(text);
        toast.success(`پروکسی ${number} جای‌گذاری شد`);
      }
    } catch {
      toast.error("دسترسی به کلیپ‌بورد ممکن نیست");
    }
  };

  const label = isFirst ? "سرور اول (مبدأ)" : isLast ? "سرور نهایی (مقصد)" : `سرور میانی (${number})`;

  return (
    <article className="proxy-card">
      <div className="card-top">
        <div className="card-title-group">
          <span className="card-number">{String(number).padStart(2, "0")}</span>
          <span className="card-label">{label}</span>
          {protocolInfo.badge && (
            <span className={`protocol-badge protocol-${protocolInfo.type}`}>
              {protocolInfo.badge}
            </span>
          )}
        </div>

        <div className="card-actions">
          <button className="icon-button paste-btn" onClick={handlePaste} title="جای‌گذاری از کلیپ‌بورد">
            <Upload size={13} /> <span>جای‌گذاری</span>
          </button>
          {value && (
            <button className="icon-button" onClick={onClear} title="پاک‌کردن">
              <X size={13} />
            </button>
          )}
          {canDelete && (
            <button className="icon-button delete" onClick={onDelete} title="حذف این سرور">
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>

      <div className="textarea-wrap">
        <textarea
          id={`proxy-${number}`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="لینک کانفیگ (vless://, vmess://, trojan://, socks5://) یا JSON را اینجا وارد کنید..."
          spellCheck={false}
        />
      </div>
    </article>
  );
}
