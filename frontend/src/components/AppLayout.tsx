// ═══════════════════════════════════════════════════
// Sentinel AI — App Layout with Sidebar Navigation
// Matches the reference design's left sidebar pattern
// ═══════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { Outlet, NavLink, useParams, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Scan, GitBranch, Bell,
  ChevronLeft, ChevronRight, Download, Search,
  ArrowRight,
} from 'lucide-react';
import { downloadReport, checkBackendHealth } from '../api/client';
import toast from 'react-hot-toast';

export default function AppLayout() {
  const { id } = useParams<{ id: string }>();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);
  const [assetsCount, setAssetsCount] = useState(12976);

  // Check backend health on mount
  useEffect(() => {
    checkBackendHealth().then(setBackendOnline);
  }, []);

  // Simulate incrementing asset count (reference design has this)
  useEffect(() => {
    const interval = setInterval(() => {
      setAssetsCount((c) => c + Math.floor(Math.random() * 3));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const hasScan = !!id;
  const isHome = location.pathname === '/';

  const handleDownloadPdf = async () => {
    if (!id) return;
    try {
      await downloadReport(id);
      toast.success('Report downloaded');
    } catch {
      toast.error('Failed to download report');
    }
  };

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: hasScan ? `/scan/${id}/live` : '/', icon: Scan, label: 'Scan' },
    { to: hasScan ? `/scan/${id}/chain` : '/', icon: GitBranch, label: 'Attack Paths' },
    { to: hasScan ? `/scan/${id}/dashboard` : '/', icon: Bell, label: 'Alerts' },
  ];

  return (
    <div className="flex h-full min-h-screen">
      {/* Sidebar */}
      <aside
        className={`sidebar flex flex-col m-3 p-4 transition-all duration-300 shrink-0 ${
          collapsed ? 'w-[72px]' : 'w-[240px]'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 mb-8 px-2">
          <div className="w-9 h-9 rounded-full bg-sentinel-accent/20 flex items-center justify-center shrink-0">
            <div className="w-4 h-4 rounded-full bg-sentinel-accent" />
          </div>
          {!collapsed && (
            <div className="animate-fade-in">
              <div className="font-semibold text-[15px] text-sentinel-text">
                Sentinel AI
              </div>
              <div className="text-[11px] text-sentinel-text-muted">
                You make the web safer
              </div>
            </div>
          )}
        </div>

        {/* Nav Items */}
        <nav className="flex flex-col gap-1 flex-1">
          {navItems.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              className={({ isActive }) =>
                `sidebar-item ${isActive ? 'active' : ''}`
              }
              title={collapsed ? item.label : undefined}
            >
              <item.icon size={18} />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}

          {hasScan && (
            <NavLink
              to={`/scan/${id}/chat`}
              className={({ isActive }) =>
                `sidebar-item ${isActive ? 'active' : ''}`
              }
              title={collapsed ? 'Chat' : undefined}
            >
              <Search size={18} />
              {!collapsed && <span>Chat</span>}
            </NavLink>
          )}
        </nav>

        {/* Bottom section */}
        {!collapsed && (
          <div className="text-[12px] text-sentinel-text-muted leading-relaxed px-2 mb-4 animate-fade-in">
            Sentinel is your quiet guardian across network, code, web and camera
            surfaces — chaining signals into a single line of defense.
          </div>
        )}

        <button
          onClick={() => setCollapsed(!collapsed)}
          className="sidebar-item justify-center"
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Bar */}
        <div className="topbar flex items-center gap-4 m-3 mb-0 px-5 py-3">
          <div
            className="flex items-center gap-2 flex-1 cursor-pointer hover:opacity-80 transition-opacity"
            onClick={() => {
              if (location.pathname !== '/') {
                window.location.href = '/';
              } else {
                document.getElementById('scan-target-input')?.focus();
              }
            }}
          >
            <Search size={16} className="text-sentinel-text-dim" />
            <span className="text-sm text-sentinel-text-dim font-mono text-[13px]">
              Scan an IP, URL, repo, or camera...
            </span>
            <ArrowRight size={14} className="text-sentinel-text-dim ml-auto" />
          </div>

          <div className="flex items-center gap-5">
            {/* Status indicator */}
            <div className="flex items-center gap-2">
              <span className="status-dot elevated" />
              <span className="text-[13px] font-semibold text-sev-high tracking-wide">
                ELEVATED
              </span>
            </div>

            {/* Assets counter */}
            <div className="text-right">
              <div className="text-[10px] text-sentinel-text-dim tracking-widest uppercase">
                Assets Scanned
              </div>
              <div className="text-lg font-semibold text-[#2a2e24] tabular-nums">
                {assetsCount.toLocaleString()}
              </div>
            </div>

            {/* AI Engine status */}
            <div className="flex items-center gap-2 bg-sentinel-sidebar text-sentinel-text text-xs px-3 py-1.5 rounded-full">
              <span className="w-2 h-2 rounded-full bg-green-400" />
              AI engine · live
            </div>

            {/* Download PDF */}
            {hasScan && (
              <button
                onClick={handleDownloadPdf}
                className="btn-outline text-xs"
              >
                <Download size={14} />
                Download PDF
              </button>
            )}
          </div>
        </div>

        {/* Backend offline banner */}
        {!backendOnline && (
          <div className="mx-3 mt-3 px-4 py-3 rounded-xl bg-sev-critical/10 border border-sev-critical/20 flex items-center gap-3 animate-fade-in">
            <span className="status-dot critical" />
            <span className="text-sm text-sev-critical font-medium">
              Backend offline — running in mock mode
            </span>
            <button
              onClick={() => checkBackendHealth().then(setBackendOnline)}
              className="ml-auto text-xs btn-outline border-sev-critical/30 text-sev-critical"
            >
              Retry
            </button>
          </div>
        )}

        {/* Page content */}
        <div className="flex-1 overflow-y-auto p-3">
          {isHome && !hasScan ? (
            <Outlet />
          ) : (
            <Outlet />
          )}
        </div>
      </main>
    </div>
  );
}
