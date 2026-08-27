import type { View } from "../../app/types";
import { primaryNavigation, secondaryNavigation } from "../../app/navigation";
import { Activity, CircleHelp, Cloud, Files, History, LayoutDashboard, LifeBuoy, Settings, Trash2 } from "lucide-react";

const icons = { dashboard: LayoutDashboard, files: Files, trash: Trash2, storage: Cloud, activity: History, recovery: LifeBuoy, settings: Settings, help: CircleHelp } as const;

export function Sidebar({ view, onNavigate }: { view: View; onNavigate: (view: View) => void }) {
  const renderItem = ({ key, icon, label }: { key: View; icon: string; label: string }) => (
    <button className={view === key ? "nav-item active" : "nav-item"} key={key} aria-current={view === key ? "page" : undefined} onClick={() => onNavigate(key)}>
      {(() => { const Icon = icons[icon as keyof typeof icons]; return <Icon size={19} strokeWidth={1.8} aria-hidden="true" />; })()}{label}
    </button>
  );

  return <aside className="sidebar">
    <div className="brand"><span className="brand-mark" aria-hidden="true">U</span><span>Undercloud</span></div>
    <p className="sidebar-caption">Private backup, made clear.</p>
    <nav aria-label="Main navigation">{primaryNavigation.map(renderItem)}</nav>
    <div className="sidebar-bottom">{secondaryNavigation.map(renderItem)}</div>
  </aside>;
}
