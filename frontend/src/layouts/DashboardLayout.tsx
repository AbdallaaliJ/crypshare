import React, { useEffect, useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Shield, History, LogOut, User, HardDrive, Users, Contact, UploadCloud, Building2, LockKeyhole, Search, LayoutDashboard, AlertTriangle, RadioTower, Menu, X } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { IconButton } from '../components/ui/IconButton';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import {
  AUTO_PREKEY_REFILL_COOLDOWN_MS,
  LOW_PREKEY_THRESHOLD,
  autoPreKeyRefillKey,
  fetchPreKeyStatus,
  replenishPreKeys
} from '../utils/prekeys';
import { CrypShareLogo } from '../components/brand/CrypShareLogo';
import { ThemeToggle } from '../components/theme/ThemeToggle';

interface WorkspaceSummary {
  id: string;
  name: string;
  role: string;
  status: string;
}

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState('');
  const [globalSearch, setGlobalSearch] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const selectedWorkspace = workspaces.find((workspace) => workspace.id === activeWorkspaceId);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;

    fetch(apiUrl('/workspaces'), { headers: authHeaders(user.token) })
      .then(async (res) => {
        const data = await res.json() as { workspaces?: WorkspaceSummary[] };
        if (!res.ok || !Array.isArray(data.workspaces) || cancelled) return;
        setWorkspaces(data.workspaces);
        setActiveWorkspaceId((current) => {
          const saved = window.localStorage.getItem(`crypshare.active-workspace:${user.username}`) || '';
          const candidate = current || saved || data.workspaces?.[0]?.id || '';
          return data.workspaces?.some((workspace) => workspace.id === candidate) ? candidate : data.workspaces?.[0]?.id || '';
        });
      })
      .catch((err) => {
        console.error('Failed to load workspaces for app shell.', err);
      });

    return () => {
      cancelled = true;
    };
  }, [user]);

  useEffect(() => {
    if (!user || !activeWorkspaceId) return;
    window.localStorage.setItem(`crypshare.active-workspace:${user.username}`, activeWorkspaceId);
  }, [activeWorkspaceId, user]);

  useEffect(() => {
    if (!user?.kek) return;
    let cancelled = false;

    const refillKey = autoPreKeyRefillKey(user.username);
    const lastAttempt = Number(window.localStorage.getItem(refillKey) || '0');
    if (Date.now() - lastAttempt < AUTO_PREKEY_REFILL_COOLDOWN_MS) return;

    fetchPreKeyStatus(user)
      .then(async (status) => {
        if (cancelled || status.available >= LOW_PREKEY_THRESHOLD) return;
        window.localStorage.setItem(refillKey, String(Date.now()));
        await replenishPreKeys(user);
        if (!cancelled) {
          showToast('Pre-key inventory was refilled automatically.', 'success');
        }
      })
      .catch((err) => {
        console.error('Automatic pre-key refill failed.', err);
      });

    return () => {
      cancelled = true;
    };
  }, [showToast, user]);

  const handleGlobalSearch = (event: React.FormEvent) => {
    event.preventDefault();
    const query = globalSearch.trim();
    navigate(query ? `/dashboard/files?search=${encodeURIComponent(query)}` : '/dashboard/files');
    setSidebarOpen(false);
  };

  const handleLogout = async () => {
    if (user?.token) {
      try {
        await fetch(apiUrl('/sessions/current'), {
          method: 'DELETE',
          headers: authHeaders(user.token)
        });
      } catch (err) {
        console.error('Failed to revoke server session during logout.', err);
      }
    }

    logout();
    navigate('/login');
  };

  const navItems = [
    { to: '/dashboard/overview', icon: LayoutDashboard, label: 'Overview' },
    { to: '/dashboard/files', icon: HardDrive, label: 'Files' },
    { to: '/dashboard/shared', icon: Users, label: 'Shared' },
    { to: '/dashboard/p2p', icon: RadioTower, label: 'P2P Transfer' },
    { to: '/dashboard/contacts', icon: Contact, label: 'Contacts' },
    { to: '/dashboard/activity', icon: History, label: 'Activity' },
    { to: '/dashboard/workspace-admin', icon: Building2, label: 'Workspace Admin' },
    { to: '/dashboard/security', icon: LockKeyhole, label: 'Security' }
  ];

  const sidebar = (
    <>
      <div className="p-5 border-b border-[var(--app-border)] flex items-center justify-between gap-3">
        <div>
          <CrypShareLogo markSize={38} wordmarkClassName="text-xl" />
          <p className="mt-2 text-[10px] uppercase tracking-widest text-[var(--app-muted)] font-bold">Secure Drive</p>
        </div>
        <button
          type="button"
          onClick={() => setSidebarOpen(false)}
          className="lg:hidden theme-toggle !p-2"
          aria-label="Close navigation"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1.5">
        {navItems.map((item) => (
          <NavLink key={item.to} to={item.to} style={{ textDecoration: 'none' }} onClick={() => setSidebarOpen(false)}>
            {({ isActive }) => <IconButton icon={item.icon} label={item.label} active={isActive} />}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-[var(--app-border)] space-y-4">
        <div className="flex items-center gap-3 bg-[var(--app-surface)] p-3 rounded-lg border border-[var(--app-border)] shadow-sm">
          <div className="w-8 h-8 rounded-lg bg-[color-mix(in_srgb,var(--brand-cyan)_14%,var(--app-surface))] flex items-center justify-center">
            <User className="w-4 h-4 text-[var(--brand-cyan)]" />
          </div>
          <div className="overflow-hidden">
            <p className="text-xs font-bold text-[var(--app-text)] truncate">{user?.username || "anonymous"}</p>
            <p className="text-[10px] text-[var(--success-color)] uppercase tracking-tighter font-bold">Identity active</p>
          </div>
        </div>
        <button onClick={handleLogout} className="w-full flex items-center justify-center gap-2 py-3 text-xs font-bold text-[var(--app-muted)] hover:text-red-600 transition-colors uppercase tracking-widest">
          <LogOut className="w-4 h-4" /> Lock Vault
        </button>
      </div>
    </>
  );

  return (
    <div className="app-shell min-h-screen flex selection:bg-cyan-200/60">
      {sidebarOpen && (
        <button
          type="button"
          className="fixed inset-0 z-30 bg-black/40 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-label="Close navigation overlay"
        />
      )}

      <aside className="app-sidebar hidden w-64 border-r lg:flex flex-col fixed inset-y-0 left-0 z-40">
        {sidebar}
      </aside>

      <aside className={`app-sidebar fixed inset-y-0 left-0 z-40 flex w-72 max-w-[86vw] flex-col border-r transition-transform duration-200 lg:hidden ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        {sidebar}
      </aside>

      <div className="flex-1 lg:ml-64 min-w-0">
        <header className="app-header sticky top-0 z-30 min-h-16 border-b backdrop-blur-xl flex flex-wrap items-center gap-3 px-4 py-3 lg:flex-nowrap lg:px-8 lg:py-0 shadow-sm">
          <button
            type="button"
            onClick={() => setSidebarOpen(true)}
            className="theme-toggle !p-2 lg:hidden"
            aria-label="Open navigation"
          >
            <Menu className="w-4 h-4" />
          </button>
          <div className="lg:hidden mr-auto">
            <CrypShareLogo markSize={32} compact />
          </div>
          <select
            value={activeWorkspaceId}
            onChange={(event) => setActiveWorkspaceId(event.target.value)}
            className="app-field order-3 w-full rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-[var(--brand-cyan)] sm:order-none sm:w-56"
          >
            {workspaces.length === 0 ? (
              <option value="">No workspace</option>
            ) : (
              workspaces.map((workspace) => (
                <option key={workspace.id} value={workspace.id}>
                  {workspace.name} · {workspace.status}
                </option>
              ))
            )}
          </select>
          {selectedWorkspace?.status === 'pending' && (
            <button
              onClick={() => navigate('/dashboard/workspace-admin')}
              className="hidden lg:inline-flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700 hover:bg-amber-100"
            >
              <AlertTriangle className="w-4 h-4" /> Workspace pending
            </button>
          )}
          <form onSubmit={handleGlobalSearch} className="relative order-4 w-full flex-1 sm:order-none sm:min-w-[220px] lg:max-w-xl">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--app-muted)]" />
            <input
              value={globalSearch}
              onChange={(event) => setGlobalSearch(event.target.value)}
              placeholder="Search encrypted file names"
              className="app-field w-full rounded-lg py-2 pl-10 pr-4 text-sm placeholder:text-[var(--app-subtle)] focus:outline-none focus:border-[var(--brand-cyan)]"
            />
          </form>
          <button
            onClick={() => navigate('/dashboard/files')}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--brand-navy)] px-3 py-2 text-sm font-bold text-white hover:bg-[var(--brand-navy-2)] transition-colors shadow-sm sm:px-4"
          >
            <UploadCloud className="w-4 h-4" /> <span className="hidden sm:inline">Upload</span>
          </button>
          <div className="hidden xl:flex items-center gap-2 rounded-lg border border-[color-mix(in_srgb,var(--brand-cyan)_42%,var(--app-border))] bg-[color-mix(in_srgb,var(--brand-cyan)_14%,var(--app-surface))] px-3 py-2 text-xs text-[var(--app-text)] font-semibold">
            <Shield className="w-4 h-4 text-[var(--brand-cyan)]" /> Fingerprint-gated sharing
          </div>
          <ThemeToggle compact />
        </header>

        <main className="app-main min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
