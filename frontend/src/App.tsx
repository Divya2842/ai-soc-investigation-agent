import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { auth } from "./services/auth";

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      className={({ isActive }) =>
        `px-3 py-2 rounded-md text-sm font-medium ${
          isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white hover:bg-slate-900"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

export default function App() {
  const navigate = useNavigate();
  const logout = () => { auth.logout(); navigate("/login"); };
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-blue-600 flex items-center justify-center font-bold text-sm">
              AI
            </div>
            <div>
              <div className="font-semibold leading-tight">SOC Investigation Agent</div>
              <div className="text-xs text-slate-500 leading-tight">
                Evidence-driven IOC enrichment &amp; MITRE mapping
              </div>
            </div>
          </div>
          <nav className="flex gap-1">
            <NavItem to="/" label="Overview" />
            <NavItem to="/alerts" label="Alerts" />
            <NavItem to="/iocs" label="IOC Lookup" />
            <button onClick={logout} className="px-3 py-2 rounded-md text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-900">Logout</button>
          </nav>
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
