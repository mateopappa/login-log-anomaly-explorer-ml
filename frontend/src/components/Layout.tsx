import { NavLink, Outlet } from "react-router-dom";

const links = [
  { to: "/", label: "SOC Console", end: true },
  { to: "/cases", label: "Cases" },
  { to: "/detection", label: "Detection Lab" },
  { to: "/pipeline", label: "Pipeline" },
  { to: "/evaluation", label: "Evaluation Lab" },
  { to: "/threat-lab", label: "Threat Lab" },
];

export function Layout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <strong>Login Anomaly Explorer</strong>
          <span>Detect · investigate · prove</span>
        </div>
        <nav className="nav">
          <NavLink to="/story" className="nav-presenter">
            Presenter
          </NavLink>
          {links.map((link) => (
            <NavLink key={link.to} to={link.to} end={link.end} className={({ isActive }) => (isActive ? "active" : undefined)}>
              {link.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
