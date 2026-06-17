import React, { useCallback, useEffect, useState } from 'react';
import { Building2, CheckCircle2, Clock, Copy, KeyRound, Link2, RefreshCw, ShieldAlert, ShieldCheck, UserPlus, UserX, Users } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getErrorMessage } from '../utils/errors';
import { createWorkspaceInvitePackage, formatFingerprint, identityFingerprint, parseWorkspaceInvitePackage } from '../utils/trust';
import type { DirectoryUser } from '../types/api';

interface Workspace {
  id: string;
  name: string;
  inviteCode: string;
  inviteExpiresAt: number;
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

interface WorkspaceInvitePreview {
  workspaceName: string;
  workspaceId: string;
  inviteCode: string;
  inviterUsername: string;
  fingerprint: string;
  expiresAt: number | null;
}

export const WorkspaceAdminPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState('');
  const [workspaceMembers, setWorkspaceMembers] = useState<WorkspaceMember[]>([]);
  const [pendingMembers, setPendingMembers] = useState<WorkspaceMember[]>([]);
  const [workspaceName, setWorkspaceName] = useState('');
  const [joinWorkspaceId, setJoinWorkspaceId] = useState('');
  const [joinInviteCode, setJoinInviteCode] = useState('');
  const [joinPackageText, setJoinPackageText] = useState('');
  const [joinInvitePreview, setJoinInvitePreview] = useState<WorkspaceInvitePreview | null>(null);
  const [showManualJoin, setShowManualJoin] = useState(false);
  const [ownFingerprint, setOwnFingerprint] = useState('');
  const [action, setAction] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const selectedWorkspace = workspaces.find((workspace) => workspace.id === selectedWorkspaceId);
  const canAdmin = selectedWorkspace?.status === 'active' && ['owner', 'admin'].includes(selectedWorkspace.role);
  const canOwner = selectedWorkspace?.status === 'active' && selectedWorkspace.role === 'owner';

  const addFingerprints = async (members: WorkspaceMember[]) => Promise.all(members.map(async (member) => ({
    ...member,
    fingerprint: await identityFingerprint(member)
  })));

  const applyInviteInput = useCallback((value: string) => {
    setJoinPackageText(value);
    const parsed = parseWorkspaceInvitePackage(value);
    const expiresAt = Number(parsed.expires);
    const preview = parsed.workspaceId && parsed.inviteCode
      ? {
          workspaceName: parsed.workspaceName,
          workspaceId: parsed.workspaceId,
          inviteCode: parsed.inviteCode,
          inviterUsername: parsed.inviterUsername,
          fingerprint: parsed.fingerprint,
          expiresAt: Number.isFinite(expiresAt) ? expiresAt : null
        }
      : null;

    setJoinInvitePreview(preview);
    if (parsed.workspaceId) setJoinWorkspaceId(parsed.workspaceId);
    if (parsed.inviteCode) setJoinInviteCode(parsed.inviteCode);
  }, []);

  const loadWorkspaceDetails = useCallback(async (workspace: Workspace | undefined) => {
    if (!user || !workspace || workspace.status !== 'active') {
      setWorkspaceMembers([]);
      setPendingMembers([]);
      return;
    }

    const membersRes = await fetch(apiUrl(`/workspaces/${workspace.id}/members`), { headers: authHeaders(user.token) });
    const membersData = await membersRes.json() as { members: WorkspaceMember[]; error?: string };
    if (!membersRes.ok) throw new Error(membersData.error || 'Unable to fetch workspace members.');
    setWorkspaceMembers(await addFingerprints(membersData.members));

    if (workspace.role === 'owner' || workspace.role === 'admin') {
      const pendingRes = await fetch(apiUrl(`/workspaces/${workspace.id}/pending-members`), { headers: authHeaders(user.token) });
      const pendingData = await pendingRes.json() as { pending: WorkspaceMember[]; error?: string };
      if (!pendingRes.ok) throw new Error(pendingData.error || 'Unable to fetch pending members.');
      setPendingMembers(await addFingerprints(pendingData.pending));
    } else {
      setPendingMembers([]);
    }
  }, [user]);

  const loadWorkspaces = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const res = await fetch(apiUrl('/workspaces'), { headers: authHeaders(user.token) });
      const data = await res.json() as { workspaces: Workspace[]; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to fetch workspaces.');

      setWorkspaces(data.workspaces);
      const nextSelected = selectedWorkspaceId && data.workspaces.some((workspace) => workspace.id === selectedWorkspaceId)
        ? selectedWorkspaceId
        : data.workspaces[0]?.id || '';
      setSelectedWorkspaceId(nextSelected);
      await loadWorkspaceDetails(data.workspaces.find((workspace) => workspace.id === nextSelected));
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load workspaces.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [loadWorkspaceDetails, selectedWorkspaceId, showToast, user]);

  useEffect(() => {
    loadWorkspaces();
  }, [loadWorkspaces]);

  useEffect(() => {
    if (!user) return;

    identityFingerprint({
      username: user.username,
      identityPublicKeyECDH: user.identityPublicKeyECDH,
      identityPublicKeyECDSA: user.identityPublicKeyECDSA
    }).then(setOwnFingerprint).catch(() => setOwnFingerprint(''));
  }, [user]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const parsed = parseWorkspaceInvitePackage(window.location.href);
    if (parsed.workspaceId || parsed.inviteCode) {
      applyInviteInput(window.location.href);
    }
  }, [applyInviteInput]);

  const handleJoinPackageChange = (value: string) => {
    applyInviteInput(value);
  };

  const handleCreateWorkspace = async () => {
    if (!user || !workspaceName.trim()) return;

    setAction('create');
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
      window.dispatchEvent(new Event('crypshare.workspaces-changed'));
      showToast('Workspace created.', 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to create workspace.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleJoinWorkspace = async () => {
    if (!user || !joinWorkspaceId.trim() || !joinInviteCode.trim()) return;

    setAction('join');
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
      setSelectedWorkspaceId(joinWorkspaceId.trim());
      setJoinWorkspaceId('');
      setJoinInviteCode('');
      setJoinPackageText('');
      setJoinInvitePreview(null);
      window.dispatchEvent(new Event('crypshare.workspaces-changed'));
      showToast('Workspace join request submitted.', 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to request workspace access.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleApproveMember = async (username: string) => {
    if (!user || !selectedWorkspace) return;

    setAction(`approve:${username}`);
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/members/${username}/approve`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to approve member.');
      showToast(`${username} approved.`, 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to approve member.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleRevokeMember = async (username: string) => {
    if (!user || !selectedWorkspace) return;
    const confirmed = window.confirm(`Revoke ${username} from "${selectedWorkspace.name}"?`);
    if (!confirmed) return;

    setAction(`revoke:${username}`);
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/members/${username}/revoke`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to revoke member.');
      showToast(`${username} revoked.`, 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke member.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleChangeMemberRole = async (username: string, role: 'admin' | 'member') => {
    if (!user || !selectedWorkspace) return;

    setAction(`role:${username}:${role}`);
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/members/${username}/role`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ role })
      });
      const data = await res.json() as { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to update member role.');
      showToast(`${username} is now a workspace ${role}.`, 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to update member role.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleRotateInvite = async () => {
    if (!user || !selectedWorkspace) return;
    const confirmed = window.confirm(`Rotate the invite code for "${selectedWorkspace.name}"? The old code will stop working.`);
    if (!confirmed) return;

    setAction('rotate-invite');
    try {
      const res = await fetch(apiUrl(`/workspaces/${selectedWorkspace.id}/invite/rotate`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json() as { workspace?: Workspace; error?: string };
      if (!res.ok || !data.workspace) throw new Error(data.error || 'Unable to rotate invite.');
      setSelectedWorkspaceId(data.workspace.id);
      showToast('Workspace invite rotated. Share the new code only through a trusted channel.', 'success');
      await loadWorkspaces();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to rotate invite.'), 'error');
    } finally {
      setAction(null);
    }
  };

  const handleCopyInvite = () => {
    if (!selectedWorkspace || !user || !ownFingerprint) return;
    navigator.clipboard.writeText(createWorkspaceInvitePackage({
      workspaceName: selectedWorkspace.name,
      workspaceId: selectedWorkspace.id,
      inviteCode: selectedWorkspace.inviteCode,
      inviteExpiresAt: selectedWorkspace.inviteExpiresAt,
      inviterUsername: user.username,
      inviterFingerprint: ownFingerprint
    }));
    showToast('Workspace invite URL copied.', 'success');
  };

  const inviteExpired = selectedWorkspace ? selectedWorkspace.inviteExpiresAt <= Date.now() : false;

  return (
    <div className="max-w-6xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Workspaces</h2>
          <p className="text-slate-400">Create, join, and manage trusted collaboration spaces.</p>
        </div>
        <button
          onClick={loadWorkspaces}
          disabled={loading}
          className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
          title="Refresh workspaces"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 mb-6">
        <GlassCard className="p-6 space-y-4">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <Building2 className="w-5 h-5 text-cyan-400" /> Create Workspace
          </h3>
          <input
            type="text"
            value={workspaceName}
            onChange={(event) => setWorkspaceName(event.target.value)}
            placeholder="Workspace name"
            className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
          />
          <ActionButton onClick={handleCreateWorkspace} loading={action === 'create'} disabled={!workspaceName.trim()} className="w-full">
            Create Workspace
          </ActionButton>
        </GlassCard>

        <GlassCard className="p-6 space-y-4">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <UserPlus className="w-5 h-5 text-emerald-400" /> Join Another Workspace
          </h3>
          <textarea
            value={joinPackageText}
            onChange={(event) => handleJoinPackageChange(event.target.value)}
            placeholder="Paste secure workspace invite URL..."
            className="min-h-28 w-full resize-none rounded-xl border border-white/5 bg-black/30 p-4 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
          />
          {joinInvitePreview ? (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-300" />
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white">
                    {joinInvitePreview.workspaceName || 'Workspace invite'}
                  </p>
                  <p className="mt-1 text-xs text-emerald-100/80">
                    {joinInvitePreview.inviterUsername ? `Invited by ${joinInvitePreview.inviterUsername}. ` : ''}
                    {joinInvitePreview.expiresAt ? `Expires ${new Date(joinInvitePreview.expiresAt).toLocaleString()}.` : 'Review the invite before requesting access.'}
                  </p>
                  <p className="mt-2 text-xs text-emerald-100/70">
                    Joining requests workspace approval. It does not automatically trust anyone's identity fingerprint.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">
              Paste a workspace invite link. You can belong to multiple workspaces and switch between them from the top bar.
            </p>
          )}
          <button
            type="button"
            onClick={() => setShowManualJoin((current) => !current)}
            className="inline-flex items-center gap-2 text-xs font-semibold text-cyan-300 hover:text-cyan-100"
          >
            <Link2 className="h-3.5 w-3.5" /> {showManualJoin ? 'Hide manual fields' : 'Use manual workspace ID/code'}
          </button>
          {showManualJoin && (
            <div className="grid md:grid-cols-2 gap-3">
              <input
                type="text"
                value={joinWorkspaceId}
                onChange={(event) => setJoinWorkspaceId(event.target.value)}
                placeholder="Workspace ID"
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
              />
              <input
                type="text"
                value={joinInviteCode}
                onChange={(event) => setJoinInviteCode(event.target.value)}
                placeholder="Invite code"
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
              />
            </div>
          )}
          <ActionButton variant="secondary" onClick={handleJoinWorkspace} loading={action === 'join'} disabled={!joinWorkspaceId.trim() || !joinInviteCode.trim()} className="w-full">
            Request Access
          </ActionButton>
        </GlassCard>
      </div>

      <GlassCard className="p-6">
        {workspaces.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/10 p-12 text-center text-slate-500">
            Create a workspace or join one with an invite to enable secure sharing.
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h3 className="text-white font-semibold">Your Workspaces</h3>
                <p className="text-xs text-slate-500">You can belong to more than one workspace. Pick one to manage or review.</p>
              </div>
              <select
                value={selectedWorkspaceId}
                onChange={async (event) => {
                  const workspaceId = event.target.value;
                  setSelectedWorkspaceId(workspaceId);
                  await loadWorkspaceDetails(workspaces.find((workspace) => workspace.id === workspaceId));
                }}
                className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50 lg:w-80"
              >
                {workspaces.map((workspace) => (
                  <option key={workspace.id} value={workspace.id}>{workspace.name} - {workspace.status}</option>
                ))}
              </select>
            </div>

            <div className="flex flex-wrap gap-2">
              {workspaces.map((workspace) => (
                <button
                  key={workspace.id}
                  type="button"
                  onClick={async () => {
                    setSelectedWorkspaceId(workspace.id);
                    await loadWorkspaceDetails(workspace);
                  }}
                  className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition-colors ${
                    workspace.id === selectedWorkspaceId
                      ? 'border-cyan-400/40 bg-cyan-400/15 text-cyan-100'
                      : 'border-white/10 bg-white/5 text-slate-400 hover:text-white'
                  }`}
                >
                  {workspace.name} · {workspace.status}
                </button>
              ))}
            </div>

            {selectedWorkspace && (
              <>
                <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-5">
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                    <div className="min-w-0">
                      <p className="text-white font-semibold">{selectedWorkspace.name}</p>
                      <p className="mt-1 text-xs text-cyan-100/80">
                        {selectedWorkspace.role} · {selectedWorkspace.memberCount} member{selectedWorkspace.memberCount === 1 ? '' : 's'}
                        {selectedWorkspace.pendingCount ? ` · ${selectedWorkspace.pendingCount} pending` : ''}
                      </p>
                      <p className={`text-xs mt-3 flex items-center gap-2 ${inviteExpired ? 'text-red-200' : 'text-cyan-100/80'}`}>
                        <Clock className="w-3.5 h-3.5" />
                        {inviteExpired ? 'Invite expired' : `Invite expires ${new Date(selectedWorkspace.inviteExpiresAt).toLocaleString()}`}
                      </p>
                      {canAdmin && (
                        <details className="mt-3 text-xs text-cyan-100/80">
                          <summary className="cursor-pointer font-semibold">Advanced invite details</summary>
                          <p className="font-mono break-all mt-2">Workspace ID: {selectedWorkspace.id}</p>
                          <p className="font-mono break-all">Invite code: {selectedWorkspace.inviteCode}</p>
                        </details>
                      )}
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2 shrink-0">
                      {canAdmin && (
                        <>
                          <ActionButton variant="secondary" onClick={handleCopyInvite} disabled={!ownFingerprint} className="text-xs">
                            <Copy className="w-4 h-4" /> Copy Invite
                          </ActionButton>
                          <ActionButton
                            variant="secondary"
                            onClick={handleRotateInvite}
                            loading={action === 'rotate-invite'}
                            className="text-xs"
                          >
                            <KeyRound className="w-4 h-4" /> Rotate
                          </ActionButton>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {selectedWorkspace.status === 'pending' ? (
                  <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-5 text-sm text-amber-100">
                    Your join request is pending. Sharing remains disabled until a workspace admin approves your membership.
                  </div>
                ) : (
                  <div className="grid lg:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <h3 className="text-white font-semibold flex items-center gap-2">
                        <Users className="w-5 h-5 text-cyan-400" /> Active Members
                      </h3>
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
                          {member.username !== user?.username && member.role !== 'owner' && (
                            <div className="flex flex-col sm:flex-row gap-2 shrink-0">
                              {canOwner && (
                                <ActionButton
                                  variant="secondary"
                                  onClick={() => handleChangeMemberRole(member.username, member.role === 'admin' ? 'member' : 'admin')}
                                  loading={action === `role:${member.username}:${member.role === 'admin' ? 'member' : 'admin'}`}
                                  className="text-xs"
                                >
                                  <ShieldCheck className="w-4 h-4" /> {member.role === 'admin' ? 'Remove Admin' : 'Make Admin'}
                                </ActionButton>
                              )}
                              {canAdmin && (
                                <ActionButton
                                  variant="secondary"
                                  onClick={() => handleRevokeMember(member.username)}
                                  loading={action === `revoke:${member.username}`}
                                  className="text-xs text-red-300 border-red-400/20 hover:bg-red-400/10"
                                >
                                  <UserX className="w-4 h-4" /> Revoke
                                </ActionButton>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>

                    <div className="space-y-3">
                      <h3 className="text-white font-semibold flex items-center gap-2">
                        <UserPlus className="w-5 h-5 text-amber-400" /> Pending Requests
                      </h3>
                      {!canAdmin ? (
                        <div className="rounded-xl border border-white/5 bg-black/20 p-4 text-sm text-slate-500">
                          Only workspace owners/admins can approve members.
                        </div>
                      ) : pendingMembers.length === 0 ? (
                        <div className="rounded-xl border border-white/5 bg-black/20 p-4 text-sm text-slate-500">
                          No pending requests.
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
                              <p className="text-[10px] text-slate-600 mt-1">Requested {new Date(member.joinedAt).toLocaleString()}</p>
                            </div>
                            <ActionButton
                              variant="secondary"
                              onClick={() => handleApproveMember(member.username)}
                              loading={action === `approve:${member.username}`}
                              className="text-xs shrink-0"
                            >
                              <ShieldCheck className="w-4 h-4" /> Approve
                            </ActionButton>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </GlassCard>
    </div>
  );
};
