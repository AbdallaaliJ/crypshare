import React, { useEffect, useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { History, LogOut, User, Folder, Users, Contact, UploadCloud, Building2, ShieldCheck, Search, LayoutDashboard, AlertTriangle, RadioTower, FolderKanban, Settings } from 'lucide-react';
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
import { useP2P } from '../hooks/useP2P';

interface WorkspaceSummary {
  id: string;
  name: string;
  role: string;
  status: string;
}

export interface DashboardOutletContext {
  workspaces: WorkspaceSummary[];
  activeWorkspaceId: string;
  selectedWorkspace?: WorkspaceSummary;
}

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const { showToast } = useToast();
  const { socketReady, pendingInvites, unreadCount, markInviteRead, declineInvite } = useP2P();
  const navigate = useNavigate();
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState('');
  const [globalSearch, setGlobalSearch] = useState('');
  const [p2pInboxOpen, setP2PInboxOpen] = useState(false);
  const selectedWorkspace = workspaces.find((workspace) => workspace.id === activeWorkspaceId);

  const loadShellWorkspaces = React.useCallback(() => {
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

  useEffect(() => loadShellWorkspaces(), [loadShellWorkspaces]);

  useEffect(() => {
    window.addEventListener('crypshare.workspaces-changed', loadShellWorkspaces);
    return () => window.removeEventListener('crypshare.workspaces-changed', loadShellWorkspaces);
  }, [loadShellWorkspaces]);

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
  };

  const handleLogout = async () => {
    if (user) {
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

  const openP2PInvite = (sessionId: string) => {
    markInviteRead(sessionId);
    setP2PInboxOpen(false);
    navigate('/dashboard/p2p');
  };

  const navItems = [
    { to: '/dashboard/overview', icon: LayoutDashboard, label: 'Overview' },
    { to: '/dashboard/files', icon: Folder, label: 'Files' },
    { to: '/dashboard/shared', icon: Users, label: 'Shared with Me' },
    { to: '/dashboard/workspace-share', icon: FolderKanban, label: 'Workspace Share' },
    { to: '/dashboard/p2p', icon: RadioTower, label: 'P2P Transfer' },
    { to: '/dashboard/contacts', icon: Contact, label: 'Contacts' },
    { to: '/dashboard/activity', icon: History, label: 'Activity' },
    { to: '/dashboard/workspace-admin', icon: Building2, label: 'Workspace Admin' },
    { to: '/dashboard/security', icon: ShieldCheck, label: 'Security' },
    { to: '/dashboard/settings', icon: Settings, label: 'Settings' }
  ];

  const sidebar = (
    <>
      <div className="p-5 border-b border-[var(--app-border)]">
        <div>
          <CrypShareLogo markSize={38} wordmarkClassName="text-xl" />
          <p className="mt-2 text-xs text-[var(--app-muted)] font-medium">Enterprise Secure Drive</p>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1.5">
        {navItems.map((item) => (
          <NavLink key={item.to} to={item.to} style={{ textDecoration: 'none' }}>
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
        <button onClick={handleLogout} className="w-full flex items-center justify-center gap-2 py-3 text-sm font-semibold text-[var(--app-muted)] hover:text-red-500 transition-colors cursor-pointer rounded-lg focus-visible:ring-2 focus-visible:ring-red-500/30 outline-none">
          <LogOut className="w-4 h-4" /> Lock Vault
        </button>
      </div>
    </>
  );

  return (
    <div className="app-shell min-h-screen flex selection:bg-cyan-200/60">
      <aside className="app-sidebar hidden w-56 border-r md:flex flex-col fixed inset-y-0 left-0 z-40">
        {sidebar}
      </aside>

      <div className="flex-1 md:ml-56 min-w-0">
        <header className="app-header sticky top-0 z-30 min-h-16 border-b backdrop-blur-xl flex flex-wrap items-center gap-3 px-4 py-3 lg:flex-nowrap lg:px-6 lg:py-0 shadow-sm">
          <div className="md:hidden mr-auto">
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
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--brand-blue)] px-3 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition-colors sm:px-4 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-cyan)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--app-bg)]"
          >
            <UploadCloud className="w-4 h-4" /> <span className="hidden sm:inline">Upload</span>
          </button>
          <div className="relative">
            <button
              type="button"
              onClick={() => setP2PInboxOpen((current) => !current)}
              className="theme-toggle relative !p-2"
              aria-label="P2P inbox"
              title={socketReady ? 'P2P online' : 'P2P reconnecting'}
            >
              <RadioTower className="w-4 h-4" />
              <span className={`absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border border-[var(--app-header-bg)] ${socketReady ? 'bg-[var(--success-color)]' : 'bg-[var(--warning-color)]'}`} />
              {unreadCount > 0 && (
                <span className="absolute -right-2 -top-2 flex h-5 min-w-5 items-center justify-center rounded-full bg-[var(--danger-color)] px-1 text-[10px] font-bold text-white">
                  {unreadCount}
                </span>
              )}
            </button>
            {p2pInboxOpen && (
              <div className="absolute right-0 top-11 z-50 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-[var(--app-border)] bg-[var(--app-elevated)] p-3 shadow-[var(--app-shadow)]">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-[var(--app-text)]">P2P Inbox</p>
                    <p className="text-xs text-[var(--app-muted)]">{socketReady ? 'Online for transfer requests' : 'Reconnecting signaling'}</p>
                  </div>
                  <span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${socketReady ? 'bg-green-500/10 text-[var(--success-color)]' : 'bg-amber-500/10 text-[var(--warning-color)]'}`}>
                    {socketReady ? 'Online' : 'Offline'}
                  </span>
                </div>

                {pendingInvites.length === 0 ? (
                  <div className="rounded-lg border border-dashed border-[var(--app-border)] p-4 text-center">
                    <p className="text-sm font-medium text-[var(--app-text)]">No pending P2P requests</p>
                    <p className="mt-1 text-xs leading-5 text-[var(--app-muted)]">You can receive P2P invites while using any dashboard page.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {pendingInvites.map((invite) => (
                      <div key={invite.sessionId} className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="truncate text-sm font-semibold text-[var(--app-text)]">{invite.senderUsername}</p>
                            <p className="mt-1 text-xs text-[var(--app-muted)]">Incoming encrypted transfer request</p>
                          </div>
                          {invite.unread && <span className="rounded-full bg-[var(--brand-blue)] px-2 py-1 text-[10px] font-semibold text-white">New</span>}
                        </div>
                        <div className="mt-3 grid grid-cols-2 gap-2">
                          <button
                            type="button"
                            onClick={() => declineInvite(invite.sessionId)}
                            className="rounded-lg border border-[var(--app-border)] px-3 py-2 text-xs font-semibold text-[var(--app-muted)] hover:text-[var(--danger-color)]"
                          >
                            Decline
                          </button>
                          <button
                            type="button"
                            onClick={() => openP2PInvite(invite.sessionId)}
                            className="rounded-lg bg-[var(--brand-blue)] px-3 py-2 text-xs font-semibold text-white hover:bg-blue-700"
                          >
                            Open P2P
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          <ThemeToggle compact />
        </header>

        <main className="app-main min-h-[calc(100vh-4rem)] p-4 sm:p-6 lg:p-8">
          <Outlet context={{ workspaces, activeWorkspaceId, selectedWorkspace } satisfies DashboardOutletContext} />
        </main>
      </div>
    </div>
  );
};
