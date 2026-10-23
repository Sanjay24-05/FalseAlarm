import { Link, Outlet, useLocation } from "react-router-dom";
import { cx } from "../lib/cx";

export function Layout() {
  const { pathname } = useLocation();
  const queueActive = pathname === "/" || pathname.startsWith("/alerts");

  return (
    <div className="min-h-screen bg-bg text-text">
      <header className="sticky top-0 z-30 border-b border-line bg-panel">
        <div className="mx-auto flex h-12 w-full max-w-[1600px] items-center gap-6 px-4">
          <Link to="/" className="flex items-baseline gap-2">
            <span className="text-[13px] font-semibold tracking-[0.14em]">FALSE ALARM</span>
            <span className="hidden text-[10px] uppercase tracking-[0.16em] text-faint sm:inline">SIEM console</span>
          </Link>
          <nav aria-label="Primary" className="flex items-center gap-1">
            <Link
              to="/"
              className={cx(
                "px-2 py-1 text-[11px] uppercase tracking-[0.14em]",
                queueActive ? "text-accent" : "text-muted hover:text-text",
              )}
              aria-current={queueActive ? "page" : undefined}
            >
              Alert queue
            </Link>
          </nav>
          <p className="ml-auto hidden font-mono text-[10px] text-faint md:block">/api → 127.0.0.1:8000</p>
        </div>
      </header>
      <main className="mx-auto w-full max-w-[1600px] px-4 py-4">
        <Outlet />
      </main>
    </div>
  );
}
