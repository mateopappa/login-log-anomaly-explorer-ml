import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api, type LiveSnapshot, type SocSummary } from "../api/client";

const links = [
  { to: "/", label: "Console", end: true },
  { to: "/cases", label: "Cases" },
  { to: "/detection", label: "Live" },
  { to: "/pipeline", label: "Pipeline" },
  { to: "/evaluation", label: "Scores" },
  { to: "/threat-lab", label: "Threat" },
];

function utcClock() {
  return new Date().toISOString().slice(11, 19) + " UTC";
}

type TriageStatus = {
  sim: string;
  openCases: number;
  live: boolean;
};

export function Layout() {
  const [clock, setClock] = useState(utcClock);
  const [triage, setTriage] = useState<TriageStatus>({ sim: "idle", openCases: 0, live: false });

  useEffect(() => {
    const id = window.setInterval(() => setClock(utcClock()), 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [live, summary]: [LiveSnapshot, SocSummary] = await Promise.all([api.liveStatus(), api.summary()]);
        if (cancelled) return;
        const sim = live.active ? String(live.state || "running") : "idle";
        setTriage({
          sim,
          openCases: summary.cases_open ?? 0,
          live: sim === "running" || sim === "paused",
        });
      } catch {
        if (!cancelled) setTriage((prev) => ({ ...prev, sim: "offline" }));
      }
    }

    void poll();
    const id = window.setInterval(() => void poll(), 4000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const simLabel =
    triage.sim === "running"
      ? "Sim running"
      : triage.sim === "paused"
        ? "Sim paused"
        : triage.sim === "completed"
          ? "Sim done"
          : triage.sim === "offline"
            ? "API down"
            : "Sim idle";

  return (
    <div className="app-shell">
      <header className="topbar-wrap">
        <nav className="topbar" aria-label="Primary">
          <Link to="/" className="topbar-brand" aria-label="Login Anomaly Explorer">
            <BrandMark />
          </Link>

          <div className="topbar-links">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) => (isActive ? "topbar-link active" : "topbar-link")}
              >
                {link.label}
              </NavLink>
            ))}
          </div>

          <div className="topbar-meta">
            <Link
              to="/detection"
              className={`topbar-status ${triage.live ? "live" : triage.sim === "offline" ? "down" : ""}`}
              title="SOC Live simulation status"
            >
              <span className={`pulse-dot ${triage.live && triage.sim === "running" ? "on" : ""}`} />
              <span>{simLabel}</span>
              <span className="topbar-status-sep">·</span>
              <span>{triage.openCases} open</span>
            </Link>
            <span className="topbar-clock mono">{clock}</span>
            <span className="topbar-divider" aria-hidden />
            <Link to="/story" className="topbar-action" title="Presenter mode">
              Present
            </Link>
          </div>
        </nav>
      </header>

      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

function BrandMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M12 3l7 4v5c0 4.5-3 8.2-7 9.5C8 20.2 5 16.5 5 12V7l7-4z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path d="M9.5 12h5M12 9.5v5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}
