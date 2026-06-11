import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2, Copy, KeyRound, MonitorCheck, RefreshCw, ShieldAlert, ShieldCheck, ShieldX, UserPlus, UserX, Users } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { GlassCard } from '../components/ui/GlassCard';
import { ActionButton } from '../components/ui/ActionButton';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { generatePreKeys } from '../utils/crypto';
import { getErrorMessage } from '../utils/errors';
import { createIdentityInvite, formatFingerprint, identityFingerprint } from '../utils/trust';
import type { DirectoryUser } from '../types/api';

interface PreKeyStatus {
  total: number;
  available: number;
  consumed: number;
}

interface SessionInfo {
  id: string;
  createdAt: number;
  expiresAt: number;
  userAgent: string;
  current: boolean;
}

interface Workspace {
  id: string;
  name: string;
  inviteCode: string;
  createdBy: string;
  createdAt: number;
  role: 'owner' | 'admin' | 'member';
  status: 'pending' | 'active' | 'revoked';
  memberCount: number;
  pendingCount: number;
}

interface WorkspaceMember extends DirectoryUser {
  workspaceId: string;
  role: 'owner' | 'admin' | 'member';
  status: 'pending' | 'active' | 'revoked';
  joinedAt: number;
  approvedAt?: number | null;
  approvedBy?: string | null;
  fingerprint?: string;
}

export const SettingsPage: React.FC = () => {
  const { user, logout } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [preKeyStatus, setPreKeyStatus] = useState<PreKeyStatus | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [replenishing, setReplenishing] = useState(false);
  const [revokingSessions, setRevokingSessions] = useState(false);
  const [revokingIdentity, setRevokingIdentity] = useState(false);
  const [ownFingerprint, setOwnFingerprint] = useState('');
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState('');
  const [workspaceMembers, setWorkspaceMembers] = useState<WorkspaceMember[]>([]);
  const [pendingMembers, setPendingMembers] = useState<WorkspaceMember[]>([]);
  const [workspaceName, setWorkspaceName] = useState('');
  const [joinWorkspaceId, setJoinWorkspaceId] = useState('');
  const [joinInviteCode, setJoinInviteCode] = useState('');
  const [workspaceAction, setWorkspaceAction] = useState<string | null>(null);

  useEffect(() => {
    if (!user) return;

    identityFingerprint({
      username: user.username,
      identityPublicKeyECDH: user.identityPublicKeyECDH,
      identityPublicKeyECDSA: user.identityPublicKeyECDSA
    }).then(setOwnFingerprint).catch(() => setOwnFingerprint(''));
  }, [user]);

  const loadPreKeyStatus = useCallback(async () => {
    if (!user) return;

    setLoadingStatus(true);
    try {
      const res = await fetch(apiUrl(`/prekeys/${user.username}/status`), { headers: authHeaders(user.token) });
      const data = await res.json() as PreKeyStatus & { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to fetch pre-key status.');
      setPreKeyStatus(data);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to fetch pre-key status.'), 'error');
    } finally {
      setLoadingStatus(false);
    }
  }, [showToast, user]);

  useEffect(() => {
    loadPreKeyStatus();
  }, [loadPreKeyStatus]);

  const loadSessions = useCallback(async () => {
    if (!user) return;

    try {
      const res = await fetch(apiUrl('/sessions'), { headers: authHeaders(user.token) });
      const data = await res.json() as { sessions: SessionInfo[]; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to fetch active sessions.');
      setSessions(data.sessions);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to fetch active sessions.'), 'error');
    }
  }, [showToast, user]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const loadWorkspaceDetails = useCallback(async (workspaceId: string, role?: Workspace['role'], status?: Workspace['status']) => {
    if (!user || !workspaceId || status === 'pending') {
      setWorkspaceMembers([]);
      setPendingMembers([]);
      return;
    }

    try {
      const membersRes = await fetch(apiUrl(`/workspaces/${workspaceId}/members`), { headers: authHeaders(user.token) });
      const membersData = await membersRes.json() as { members: WorkspaceMember[]; error?: string };
      if (!membersRes.ok) throw new Error(membersData.error || 'Unable to fetch workspace members.');

      const membersWithFingerprints = await Promise.all(membersData.members.map(async (member) => ({
        ...member,
        fingerprint: await identityFingerprint(member)
      })));
      setWorkspaceMembers(membersWithFingerprints);

      if (role === 'owner' || role === 'admin') {
        const pendingRes = await fetch(apiUrl(`/workspaces/${workspaceId}/pending-members`), { headers: authHeaders(user.token) });
        const pendingData = await pendingRes.json() as { pending: WorkspaceMember[]; error?: string };
        if (!pendingRes.ok) throw new Error(pendingData.error || 'Unable to fetch pending workspace members.');
        const pendingWithFingerprints = await Promise.all(pendingData.pending.map(async (member) => ({
          ...member,
          fingerprint: await identityFingerprint(member)
        })));
        setPendingMembers(pendingWithFingerprints);
      } else {
        setPendingMembers([]);
      }
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to fetch workspace details.'), 'error');
    }
  }, [showToast, user]);

  const loadWorkspaces = useCallback(async () => {
    if (!user) return;

    try {
      const res = await fetch(apiUrl('/workspaces'), { headers: authHeaders(user.token) });
      const data = await res.json() as { workspaces: Workspace[]; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to fetch workspaces.');
      setWorkspaces(data.workspaces);

      const nextSelected = selectedWorkspaceId && data.workspaces.some((workspace) => workspace.id === selectedWorkspaceId)
        ? selectedWorkspaceId
        : data.workspaces[0]?.id || '';
      setSelectedWorkspaceId(nextSelected);

      const selectedWorkspace = data.workspaces.find((workspace) => workspace.id === nextSelected);
      if (selectedWorkspace) {
        await loadWorkspaceDetails(selectedWorkspace.id, selectedWorkspace.role, selectedWorkspace.status);
      } else {
        setWorkspaceMembers([]);
        setPendingMembers([]);
      }
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to fetch workspaces.'), 'error');
    }
  }, [loadWorkspaceDetails, selectedWorkspaceId, showToast, user]);

  useEffect(() => {
    loadWorkspaces();
  }, [loadWorkspaces]);

  const selectedWorkspace = workspaces.find((workspace) => workspace.id === selectedWorkspaceId);

  const handleCreateWorkspace = async () => {
    if (!user || !workspaceName.trim()) return;

    setWorkspaceAction('create');
    try {
      const res = await fetch(apiUrl('/workspaces'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ name: workspaceName.trim() })
      });
      const data = await res.json() as { workspace?: Workspace; error?: string };
      if (!res.ok || !data.workspace) throw new Error(data.error || 'Unable to create workspace.');
      setWorkspaceName('');
      setSelectedWorkspaceId(data.workspace.id);
      showToast('Workspace created. Share its ID and invite code with trusted users.', 'success');
      await loadWorkspaces();
      setSelectedWorkspaceId(data.workspace.id);
      await loadWorkspaceDetails(data.workspace.id, data.workspace.role, data.workspace.status);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to create workspace.'), 'error');
    } finally {
      setWorkspaceAction(null);
    }
  };

  const handleJoinWorkspace = async () => {
    if (!user || !joinWorkspaceId.trim() || !joinInviteCode.trim()) return;

    setWorkspaceAction('join');
    try {
      const res = await fetch(apiUrl(`/workspaces/${joinWorkspaceId.trim()}/join`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ inviteCode: joinInviteCode.trim() })
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to request workspace access.');
      setJoinWorkspaceId('');
      setJoinInviteCode('');
      showToast('Workspace join request submitted.', 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to request workspace access.'), 'error');
    } finally {
      setWorkspaceAction(null);
    }
  };

  const handleApproveMember = async (username: string) => {
    if (!user || !selectedWorkspace) return;

    setWorkspaceAction(`approve:${username}`);
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/members/${username}/approve`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to approve workspace member.');
      showToast(`${username} approved for ${selectedWorkspace.name}.`, 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to approve workspace member.'), 'error');
    } finally {
      setWorkspaceAction(null);
    }
  };

  const handleRevokeMember = async (username: string) => {
    if (!user || !selectedWorkspace) return;

    const confirmed = window.confirm(`Revoke ${username} from workspace "${selectedWorkspace.name}"?`);
    if (!confirmed) return;

    setWorkspaceAction(`revoke:${username}`);
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/members/${username}/revoke`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to revoke workspace member.');
      showToast(`${username} revoked from ${selectedWorkspace.name}.`, 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke workspace member.'), 'error');
    } finally {
      setWorkspaceAction(null);
    }
  };

  const handleCopyToken = () => {
    if (user?.identityPublicKeyECDH) {
      navigator.clipboard.writeText(user.identityPublicKeyECDH);
      showToast('Public Identity Token copied to clipboard!', 'success');
    }
  };

  const handleCopySigningKey = () => {
    if (user?.identityPublicKeyECDSA) {
      navigator.clipboard.writeText(user.identityPublicKeyECDSA);
      showToast('Signing public key copied.', 'success');
    }
  };

  const handleCopyFingerprint = () => {
    if (ownFingerprint) {
      navigator.clipboard.writeText(formatFingerprint(ownFingerprint));
      showToast('Identity fingerprint copied.', 'success');
    }
  };

  const handleCopyInvite = () => {
    if (user && ownFingerprint) {
      navigator.clipboard.writeText(createIdentityInvite(user.username, ownFingerprint));
      showToast('Identity invite copied.', 'success');
    }
  };

  const handleCopyWorkspaceInvite = () => {
    if (!selectedWorkspace) return;
    navigator.clipboard.writeText(`Workspace: ${selectedWorkspace.name}\nID: ${selectedWorkspace.id}\nInvite code: ${selectedWorkspace.inviteCode}`);
    showToast('Workspace invite copied.', 'success');
  };

  const handleReplenishPreKeys = async () => {
    if (!user?.kek) {
      showToast('Session key missing. Log in again.', 'error');
      return;
    }

    setReplenishing(true);
    try {
      showToast('Generating one-time pre-keys...', 'info');
      const preKeys = await generatePreKeys(user.kek, 100);
      const res = await fetch(apiUrl('/upload-prekeys'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ username: user.username, preKeys })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to upload pre-keys.');

      setPreKeyStatus((prev) => ({
        total: (prev?.total || 0) + preKeys.length,
        available: data.remaining,
        consumed: prev?.consumed || 0
      }));
      showToast('Pre-key bundle replenished.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to replenish pre-keys.'), 'error');
    } finally {
      setReplenishing(false);
    }
  };

  const handleRevokeOtherSessions = async () => {
    if (!user) return;

    setRevokingSessions(true);
    try {
      const res = await fetch(apiUrl('/sessions/revoke-others'), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to revoke other sessions.');

      showToast(`${data.revoked} other session${data.revoked === 1 ? '' : 's'} revoked.`, 'success');
      await loadSessions();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke other sessions.'), 'error');
    } finally {
      setRevokingSessions(false);
    }
  };

  const handleRevokeIdentity = async () => {
    if (!user) return;

    const confirmed = window.confirm(
      `Revoke identity "${user.username}"? This blocks new logins and removes this identity from recipient discovery.`
    );
    if (!confirmed) return;

    setRevokingIdentity(true);
    try {
      const res = await fetch(apiUrl(`/identity/${user.username}/revoke`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ reason: 'Emergency revocation from identity settings' })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to revoke identity.');

      showToast('Identity revoked. Session locked.', 'success');
      logout();
      navigate('/login');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke identity.'), 'error');
    } finally {
      setRevokingIdentity(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <h2 className="text-3xl font-bold text-white mb-8">Identity Management</h2>
      <GlassCard className="p-8 space-y-6">
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Identity Fingerprint</h4>
            <p className="text-xs text-slate-500 mt-1 font-mono break-all max-w-sm">
              {ownFingerprint ? formatFingerprint(ownFingerprint) : 'Calculating fingerprint...'}
            </p>
          </div>
          <div className="flex gap-2">
            <ActionButton variant="secondary" onClick={handleCopyFingerprint} disabled={!ownFingerprint}>
              <Copy className="w-4 h-4" /> Copy
            </ActionButton>
            <ActionButton variant="secondary" onClick={handleCopyInvite} disabled={!ownFingerprint}>
              Invite
            </ActionButton>
          </div>
        </div>
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Public Identity Token (ECDH)</h4>
            <p className="text-xs text-slate-500 mt-1 font-mono break-all max-w-sm">
              {user?.identityPublicKeyECDH}
            </p>
          </div>
          <ActionButton variant="secondary" onClick={handleCopyToken}>
            <Copy className="w-4 h-4" /> Copy
          </ActionButton>
        </div>
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Public Signing Token (ECDSA)</h4>
            <p className="text-xs text-slate-500 mt-1 font-mono break-all max-w-sm">
              {user?.identityPublicKeyECDSA}
            </p>
          </div>
          <ActionButton variant="secondary" onClick={handleCopySigningKey}>
            <Copy className="w-4 h-4" /> Copy
          </ActionButton>
        </div>
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Encryption Engine</h4>
            <p className="text-xs text-slate-500 mt-1">v4.2.1-stable (AES-GCM-256) • {user?.role === 'admin' ? 'Admin' : 'Member'}</p>
          </div>
          <div className="bg-cyan-500/10 text-cyan-400 px-3 py-1 rounded-full text-[10px] font-bold border border-cyan-500/20">Active</div>
        </div>
        <div className="pb-6 border-b border-white/5 space-y-5">
          <div className="flex justify-between items-start gap-6">
            <div>
              <h4 className="text-white font-medium flex items-center gap-2">
                <Building2 className="w-4 h-4 text-cyan-400" /> Workspace Administration
              </h4>
              <p className="text-xs text-slate-500 mt-1">
                Create a protected workspace, invite trusted identities, then approve members after fingerprint verification.
              </p>
            </div>
            <button
              onClick={loadWorkspaces}
              className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
              title="Refresh workspaces"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>

          <div className="grid md:grid-cols-2 gap-3">
            <div className="space-y-2">
              <input
                type="text"
                value={workspaceName}
                onChange={(event) => setWorkspaceName(event.target.value)}
                placeholder="New workspace name"
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
              />
              <ActionButton
                variant="secondary"
                onClick={handleCreateWorkspace}
                loading={workspaceAction === 'create'}
                disabled={!workspaceName.trim()}
                className="w-full"
              >
                <Building2 className="w-4 h-4" /> Create Workspace
              </ActionButton>
            </div>
            <div className="space-y-2">
              <input
                type="text"
                value={joinWorkspaceId}
                onChange={(event) => setJoinWorkspaceId(event.target.value)}
                placeholder="Workspace ID"
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
              />
              <div className="flex gap-2">
                <input
                  type="text"
                  value={joinInviteCode}
                  onChange={(event) => setJoinInviteCode(event.target.value)}
                  placeholder="Invite code"
                  className="min-w-0 flex-1 bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
                />
                <ActionButton
                  variant="secondary"
                  onClick={handleJoinWorkspace}
                  loading={workspaceAction === 'join'}
                  disabled={!joinWorkspaceId.trim() || !joinInviteCode.trim()}
                  className="shrink-0"
                >
                  <UserPlus className="w-4 h-4" /> Join
                </ActionButton>
              </div>
            </div>
          </div>

          {workspaces.length === 0 ? (
            <div className="rounded-xl border border-white/5 bg-black/20 p-4 text-sm text-slate-500">
              No workspaces yet. Create one to become its owner, or join one with a workspace ID and invite code.
            </div>
          ) : (
            <div className="space-y-4">
              <select
                value={selectedWorkspaceId}
                onChange={async (event) => {
                  const workspaceId = event.target.value;
                  setSelectedWorkspaceId(workspaceId);
                  const workspace = workspaces.find((item) => item.id === workspaceId);
                  if (workspace) {
                    await loadWorkspaceDetails(workspace.id, workspace.role, workspace.status);
                  }
                }}
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
              >
                {workspaces.map((workspace) => (
                  <option key={workspace.id} value={workspace.id}>
                    {workspace.name} - {workspace.role} - {workspace.status}
                  </option>
                ))}
              </select>

              {selectedWorkspace && (
                <div className="space-y-4">
                  <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <p className="text-sm text-white font-medium">{selectedWorkspace.name}</p>
                        <p className="text-[10px] text-slate-500 font-mono break-all mt-1">ID: {selectedWorkspace.id}</p>
                        <p className="text-[10px] text-slate-500 font-mono break-all">Invite: {selectedWorkspace.inviteCode}</p>
                      </div>
                      <ActionButton variant="secondary" onClick={handleCopyWorkspaceInvite} className="text-xs shrink-0">
                        <Copy className="w-4 h-4" /> Copy
                      </ActionButton>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-bold uppercase tracking-widest">
                      <span className="px-2 py-1 rounded-full border border-emerald-500/20 bg-emerald-500/10 text-emerald-400">
                        {selectedWorkspace.memberCount} active
                      </span>
                      <span className="px-2 py-1 rounded-full border border-amber-500/20 bg-amber-500/10 text-amber-400">
                        {selectedWorkspace.pendingCount} pending
                      </span>
                    </div>
                  </div>

                  {selectedWorkspace.status === 'pending' ? (
                    <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-200">
                      Your join request is pending. A workspace admin must verify your fingerprint and approve you before sharing is enabled.
                    </div>
                  ) : (
                    <>
                      {(selectedWorkspace.role === 'owner' || selectedWorkspace.role === 'admin') && (
                        <div className="space-y-2">
                          <p className="text-xs uppercase text-slate-500 font-bold tracking-widest flex items-center gap-2">
                            <UserPlus className="w-3 h-3" /> Pending Members
                          </p>
                          {pendingMembers.length === 0 ? (
                            <div className="rounded-xl border border-white/5 bg-black/20 p-4 text-sm text-slate-500">
                              No pending workspace requests.
                            </div>
                          ) : (
                            pendingMembers.map((member) => (
                              <div key={member.username} className="flex items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/20 p-4">
                                <div className="min-w-0">
                                  <p className="text-sm text-white font-medium flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-amber-400" /> {member.username}
                                  </p>
                                  <p className="text-[10px] text-slate-500 font-mono mt-1 break-all">
                                    {member.fingerprint ? formatFingerprint(member.fingerprint) : 'Calculating fingerprint...'}
                                  </p>
                                </div>
                                <ActionButton
                                  variant="secondary"
                                  onClick={() => handleApproveMember(member.username)}
                                  loading={workspaceAction === `approve:${member.username}`}
                                  className="text-xs shrink-0"
                                >
                                  <ShieldCheck className="w-4 h-4" /> Approve
                                </ActionButton>
                              </div>
                            ))
                          )}
                        </div>
                      )}

                      <div className="space-y-2">
                        <p className="text-xs uppercase text-slate-500 font-bold tracking-widest flex items-center gap-2">
                          <Users className="w-3 h-3" /> Active Members
                        </p>
                        {workspaceMembers.map((member) => (
                          <div key={member.username} className="flex items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/20 p-4">
                            <div className="min-w-0">
                              <p className="text-sm text-white font-medium">
                                {member.username} <span className="text-[10px] text-cyan-400 uppercase">{member.role}</span>
                              </p>
                              <p className="text-[10px] text-slate-500 font-mono mt-1 break-all">
                                {member.fingerprint ? formatFingerprint(member.fingerprint) : 'Calculating fingerprint...'}
                              </p>
                            </div>
                            {(selectedWorkspace.role === 'owner' || selectedWorkspace.role === 'admin') && member.username !== user?.username && member.role !== 'owner' && (
                              <ActionButton
                                variant="secondary"
                                onClick={() => handleRevokeMember(member.username)}
                                loading={workspaceAction === `revoke:${member.username}`}
                                className="text-xs text-red-400 border-red-400/20 hover:bg-red-400/10 shrink-0"
                              >
                                <UserX className="w-4 h-4" /> Revoke
                              </ActionButton>
                            )}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
        <div className="pb-6 border-b border-white/5 space-y-4">
          <div className="flex justify-between items-start gap-6">
            <div>
              <h4 className="text-white font-medium flex items-center gap-2">
                <MonitorCheck className="w-4 h-4 text-cyan-400" /> Active Sessions
              </h4>
              <p className="text-xs text-slate-500 mt-1">
                Revoke stale browser sessions when a device is lost or shared.
              </p>
            </div>
            <ActionButton
              variant="secondary"
              onClick={handleRevokeOtherSessions}
              loading={revokingSessions}
              disabled={sessions.filter((session) => !session.current).length === 0}
              className="text-xs"
            >
              <ShieldX className="w-4 h-4" /> Revoke Others
            </ActionButton>
          </div>

          <div className="space-y-2">
            {sessions.map((session) => (
              <div key={session.id} className="flex items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/20 p-4">
                <div className="min-w-0">
                  <p className="text-sm text-white font-medium truncate">
                    {session.userAgent}
                  </p>
                  <p className="text-[10px] text-slate-500 font-mono mt-1">
                    Expires {new Date(session.expiresAt).toLocaleString()}
                  </p>
                </div>
                <span className={`shrink-0 px-3 py-1 rounded-full text-[10px] font-bold border ${
                  session.current
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : 'bg-slate-500/10 text-slate-400 border-white/10'
                }`}>
                  {session.current ? 'Current' : 'Active'}
                </span>
              </div>
            ))}
          </div>
        </div>
        <div className="pt-2 space-y-4">
          <div className="flex justify-between items-start gap-6">
            <div>
              <h4 className="text-white font-medium flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-emerald-400" /> One-Time Pre-Key Inventory
              </h4>
              <p className="text-xs text-slate-500 mt-1">
                Recipients need available pre-keys before others can send encrypted files to you.
              </p>
            </div>
            <button
              onClick={loadPreKeyStatus}
              disabled={loadingStatus || replenishing}
              className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
              title="Refresh pre-key status"
            >
              <RefreshCw className={`w-4 h-4 ${loadingStatus ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-xl border border-white/5 bg-black/20 p-4">
              <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Available</p>
              <p className="text-2xl font-bold text-emerald-400 mt-1">{preKeyStatus?.available ?? '--'}</p>
            </div>
            <div className="rounded-xl border border-white/5 bg-black/20 p-4">
              <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Consumed</p>
              <p className="text-2xl font-bold text-slate-300 mt-1">{preKeyStatus?.consumed ?? '--'}</p>
            </div>
            <div className="rounded-xl border border-white/5 bg-black/20 p-4">
              <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Total</p>
              <p className="text-2xl font-bold text-slate-300 mt-1">{preKeyStatus?.total ?? '--'}</p>
            </div>
          </div>

          <ActionButton
            variant="secondary"
            onClick={handleReplenishPreKeys}
            loading={replenishing}
            disabled={loadingStatus}
            className="w-full"
          >
            Generate 100 New Pre-Keys
          </ActionButton>
        </div>
        <div className="pt-6 border-t border-white/5 space-y-4">
          <div>
            <h4 className="text-red-400 font-medium flex items-center gap-2">
              <ShieldAlert className="w-4 h-4" /> Emergency Identity Revocation
            </h4>
            <p className="text-xs text-slate-500 mt-1">
              Revoked identities cannot create new sessions or receive new encrypted dispatches.
            </p>
          </div>
          <ActionButton
            variant="secondary"
            onClick={handleRevokeIdentity}
            loading={revokingIdentity}
            className="w-full text-red-400 border-red-400/20 hover:bg-red-400/10"
          >
            Revoke This Identity
          </ActionButton>
        </div>
      </GlassCard>
    </div>
  );
};
