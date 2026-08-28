import { AlertCircle, Home } from "lucide-react";
import { useLocation } from "wouter";

export default function NotFound() {
  const [, setLocation] = useLocation();

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#0b0f12", color: "#eef4f2" }}>
      <div style={{ textAlign: "center", padding: "2rem" }}>
        <AlertCircle size={48} style={{ color: "#ff6b81", margin: "0 auto 1rem" }} />
        <h1 style={{ fontSize: "2rem", fontWeight: 700, margin: "0 0 0.5rem" }}>۴۰۴ - صفحه یافت نشد</h1>
        <p style={{ color: "#72848c", marginBottom: "1.5rem" }}>صفحه مورد نظر شما وجود ندارد.</p>
        <button
          onClick={() => setLocation("/")}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            background: "#8cffb0",
            color: "#07140d",
            padding: "10px 18px",
            borderRadius: "8px",
            fontWeight: 700,
            cursor: "pointer",
            border: 0
          }}
        >
          <Home size={16} /> بازگشت به صفحه اصلی
        </button>
      </div>
    </div>
  );
}

