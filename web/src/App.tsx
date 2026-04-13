import { Routes, Route, NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Scan, Gauge, Map, FileText,
} from 'lucide-react';
import { useLanguage } from './hooks/useLanguage';
import { getLanguages } from './i18n';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import Benchmark from './pages/Benchmark';
import Roadmap from './pages/Roadmap';
import Report from './pages/Report';

export default function App() {
  const { lang, switchLang, t } = useLanguage();
  const location = useLocation();

  const navItems = [
    { path: '/', icon: LayoutDashboard, label: t('nav_dashboard') },
    { path: '/scanner', icon: Scan, label: t('nav_scanner') },
    { path: '/benchmark', icon: Gauge, label: t('nav_benchmark') },
    { path: '/roadmap', icon: Map, label: t('nav_roadmap') },
    { path: '/report', icon: FileText, label: t('nav_report') },
  ];

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>VN-PQC Analyzer</h1>
          <p>{t('app_subtitle')}</p>
        </div>
        <nav className="sidebar-nav">
          {navItems.map(({ path, icon: Icon, label }) => (
            <NavLink
              key={path}
              to={path}
              className={location.pathname === path ? 'active' : ''}
              end={path === '/'}
            >
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="lang-toggle">
            {getLanguages().map(({ code, label }) => (
              <button
                key={code}
                className={lang === code ? 'active' : ''}
                onClick={() => switchLang(code)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard t={t} lang={lang} />} />
          <Route path="/scanner" element={<Scanner t={t} lang={lang} />} />
          <Route path="/benchmark" element={<Benchmark t={t} lang={lang} />} />
          <Route path="/roadmap" element={<Roadmap t={t} lang={lang} />} />
          <Route path="/report" element={<Report t={t} lang={lang} />} />
        </Routes>
      </main>
    </div>
  );
}
