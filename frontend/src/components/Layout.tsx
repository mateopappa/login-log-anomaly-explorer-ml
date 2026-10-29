import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useSearchParams } from "react-router-dom";
import { api, type LiveSnapshot, type SocSummary } from "../api/client";
import { StoryPage } from "../pages/StoryPage";

const links = [
  { to: "/", label: "Console", end: true },
  { to: "/cases", label: "Cases" },
  { to: "/detection", label: "Live" },
  { to: "/pipeline", label: "Pipeline" },
  { to: "/evaluation", label: "Scores" },
  { to: "/threat-lab", label: "Threat" },
];

type TriageStatus = {
  sim: string;
  openCases: number;
  live: boolean;
};

function applyLive(live: LiveSnapshot, openCases?: number): TriageStatus {
  const sim = live.active ? String(live.state || "running") : "idle";
  return {
    sim,
    openCases: openCases ?? live.summary?.cases_open ?? 0,
    live: sim === "running" || sim === "paused",
  };
}

export function Layout() {
  const [params, setParams] = useSearchParams();
  const present = params.get("present") === "1";
  const [triage, setTriage] = useState<TriageStatus>({ sim: "idle", openCases: 0, live: false });
  const simRef = useRef(triage.sim);
  simRef.current = triage.sim;

  // Status + advance live in the shell so leaving Live (dossier, Cases, …) does not pause the sim.
  useEffect(() => {
    let cancelled = false;
    let inFlight = false;

    async function tick() {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        if (simRef.current === "running") {
          const live = await api.liveControl({ action: "advance" });
          if (!cancelled) setTriage((prev) => applyLive(live, live.summary?.cases_open ?? prev.openCases));
          return;
        }
        const [live, summary]: [LiveSnapshot, SocSummary] = await Promise.all([
          api.liveStatus(),
          api.summary(),
        ]);
        const openCases = live.active ? live.summary?.cases_open : summary.cases_open;
        if (!cancelled) setTriage(applyLive(live, openCases ?? 0));
      } catch {
        if (!cancelled) setTriage((prev) => ({ ...prev, sim: "offline", live: false }));
      } finally {
        inFlight = false;
      }
    }

    void tick();
    const id = window.setInterval(() => void tick(), 1000);
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

  const canToggle = triage.sim === "running" || triage.sim === "paused";

  async function toggleSim() {
    try {
      const live = await api.liveControl({ action: triage.sim === "running" ? "pause" : "resume" });
      setTriage((prev) => applyLive(live, live.summary?.cases_open ?? prev.openCases));
    } catch {
      setTriage((prev) => ({ ...prev, sim: "offline", live: false }));
    }
  }

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
            {canToggle ? (
              <button
                type="button"
                className={`topbar-status ${triage.live ? "live" : ""}`}
                onClick={() => void toggleSim()}
              >
                <span className={`pulse-dot ${triage.sim === "running" ? "on" : ""}`} />
                <span>{triage.sim === "running" ? "Pause sim" : "Resume sim"}</span>
                <span className="topbar-status-sep">·</span>
                <span>{triage.openCases} open</span>
              </button>
            ) : (
              <span className={`topbar-status ${triage.sim === "offline" ? "down" : ""}`}>
                <span className="pulse-dot" />
                <span>{simLabel}</span>
                <span className="topbar-status-sep">·</span>
                <span>{triage.openCases} open</span>
              </span>
            )}
            <span className="topbar-divider" aria-hidden />
            <button
              type="button"
              className="topbar-action"
              title="Presenter mode"
              aria-pressed={present}
              onClick={() => {
                const next = new URLSearchParams(params);
                if (present) next.delete("present");
                else next.set("present", "1");
                setParams(next);
              }}
            >
              Present
            </button>
          </div>
        </nav>
      </header>

      <main className="content">
        <Outlet />
      </main>
      {present && (
        <StoryPage
          onClose={() => {
            const next = new URLSearchParams(params);
            next.delete("present");
            setParams(next, { replace: true });
          }}
        />
      )}
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
