import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Copy, KeyRound, MonitorCheck, RefreshCw, ShieldAlert, ShieldX, Fingerprint, Database } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getErrorMessage } from '../utils/errors';
import { fetchPreKeyStatus, LOW_PREKEY_THRESHOLD, PREKEY_REFILL_COUNT, replenishPreKeys, type PreKeyStatus } from '../utils/prekeys';
import { createIdentityInvite, formatFingerprint, identityFingerprint } from '../utils/trust';

interface SessionInfo {
  id: string;
  createdAt: number;
  expiresAt: number;
  userAgent: string;
  current: boolean;
}

interface AuditAnchor {
  version: number;
  exportedAt: number;
  blockCount: number;
  latestHash: string | null;
  ledgerDigest: string;
}

export const SecurityPage: React.FC = () => {
  const { user, logout } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const [fingerprint, setFingerprint] = useState('');
  const [preKeyStatus, setPreKeyStatus] = useState<PreKeyStatus | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [anchor, setAnchor] = useState<AuditAnchor | null>(null);
  const [loading, setLoading] = useState(false);
  const [replenishing, setReplenishing] = useState(false);
  const [revokingSessions, setRevokingSessions] = useState(false);
  const [revokingIdentity, setRevokingIdentity] = useState(false);

  const identityInvite = useMemo(() => {
    if (!user || !fingerprint) return '';
    return createIdentityInvite(user.username, fingerprint);
  }, [fingerprint, user]);

  useEffect(() => {
    if (!user) return;

    identityFingerprint({
      username: user.username,
      identityPublicKeyECDH: user.identityPublicKeyECDH,
      identityPublicKeyECDSA: user.identityPublicKeyECDSA
    }).then(setFingerprint).catch(() => setFingerprint(''));
  }, [user]);

  const loadSecurityState = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const [preKeys, sessionsRes, anchorRes] = await Promise.all([
        fetchPreKeyStatus(user),
        fetch(apiUrl('/sessions'), { headers: authHeaders(user.token) }),
        fetch(apiUrl('/audit-anchor'), { headers: authHeaders(user.token) })
      ]);

      const sessionData = await sessionsRes.json() as { sessions: SessionInfo[]; error?: string };
      const anchorData = await anchorRes.json() as AuditAnchor & { error?: string };

      if (!sessionsRes.ok) throw new Error(sessionData.error || 'Unable to load sessions.');
      if (!anchorRes.ok) throw new Error(anchorData.error || 'Unable to load audit anchor.');

      setPreKeyStatus(preKeys);
      setSessions(sessionData.sessions);
      setAnchor(anchorData);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load security state.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast, user]);

  useEffect(() => {
    loadSecurityState();
  }, [loadSecurityState]);

  const copyText = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`${label} copied.`, 'success');
  };

  const handleReplenishPreKeys = async () => {
    if (!user?.kek) {
      showToast('Session key missing. Log in again.', 'error');
      return;
    }

    setReplenishing(true);
    try {
      await replenishPreKeys(user);
      await loadSecurityState();
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
      const data = await res.json() as { revoked?: number; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to revoke other sessions.');
      showToast(`${data.revoked || 0} other session${data.revoked === 1 ? '' : 's'} revoked.`, 'success');
      await loadSecurityState();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke sessions.'), 'error');
    } finally {
      setRevokingSessions(false);
    }
  };

  const handleRevokeIdentity = async () => {
    if (!user) return;
    const confirmed = window.confirm(`Revoke identity "${user.username}"? This blocks new logins and new encrypted shares.`);
    if (!confirmed) return;

    setRevokingIdentity(true);
    try {
      const res = await fetch(apiUrl(`/identity/${user.username}/revoke`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({ reason: 'Emergency revocation from Security page' })
      });
      const data = await res.json() as { error?: string };
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
    <div className="max-w-6xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Security</h2>
          <p className="text-slate-400">Identity controls, session hygiene, pre-key health, and audit evidence.</p>
        </div>
        <button
          onClick={loadSecurityState}
          disabled={loading}
          className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
          title="Refresh security state"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <GlassCard className="p-6 space-y-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-white font-semibold flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-cyan-400" /> Identity Fingerprint
              </h3>
              <p className="text-xs text-slate-500 mt-1">Compare this out-of-band before anyone trusts your identity.</p>
            </div>
            <ActionButton variant="secondary" onClick={() => copyText(identityInvite, 'Identity invite')} disabled={!identityInvite} className="text-xs">
              <Copy className="w-4 h-4" /> Invite
            </ActionButton>
          </div>
          <p className="font-mono text-xs text-slate-300 break-all rounded-xl border border-white/5 bg-black/20 p-4">
            {fingerprint ? formatFingerprint(fingerprint) : 'Calculating fingerprint...'}
          </p>
        </GlassCard>

        <GlassCard className="p-6 space-y-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-white font-semibold flex items-center gap-2">
                <KeyRound className="w-5 h-5 text-emerald-400" /> One-Time Pre-Keys
              </h3>
              <p className="text-xs text-slate-500 mt-1">CrypShare auto-refills low inventory after login; use manual refill if sharing is blocked.</p>
            </div>
            <ActionButton variant="secondary" onClick={handleReplenishPreKeys} loading={replenishing} className="text-xs">
              Refill {PREKEY_REFILL_COUNT}
            </ActionButton>
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
          {preKeyStatus && preKeyStatus.available < LOW_PREKEY_THRESHOLD && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-100">
              Low pre-key inventory. Automatic refill may run shortly; refill now if workspace members need to share with you immediately.
            </div>
          )}
        </GlassCard>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 mt-6">
        <GlassCard className="p-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-white font-semibold flex items-center gap-2">
                <MonitorCheck className="w-5 h-5 text-cyan-400" /> Active Sessions
              </h3>
              <p className="text-xs text-slate-500 mt-1">Revoke stale browser sessions when a device is lost or shared.</p>
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
                  <p className="text-sm text-white font-medium truncate">{session.userAgent}</p>
                  <p className="text-[10px] text-slate-500 font-mono mt-1">Expires {new Date(session.expiresAt).toLocaleString()}</p>
                </div>
                <span className={`shrink-0 px-3 py-1 rounded-full text-[10px] font-bold border ${
                  session.current ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-slate-500/10 text-slate-400 border-white/10'
                }`}>
                  {session.current ? 'Current' : 'Active'}
                </span>
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard className="p-6 space-y-5">
          <div>
            <h3 className="text-white font-semibold flex items-center gap-2">
              <Database className="w-5 h-5 text-cyan-400" /> Audit Evidence
            </h3>
            <p className="text-xs text-slate-500 mt-1">Export anchors externally to prove the audit chain later.</p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-white/5 bg-black/20 p-4">
              <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Blocks</p>
              <p className="text-2xl font-bold text-white mt-1">{anchor?.blockCount ?? '--'}</p>
            </div>
            <div className="rounded-xl border border-white/5 bg-black/20 p-4 min-w-0">
              <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Digest</p>
              <p className="font-mono text-xs text-cyan-400 mt-2 break-all">{anchor?.ledgerDigest?.slice(0, 28) || '--'}...</p>
            </div>
          </div>
          <ActionButton variant="secondary" onClick={() => anchor && copyText(JSON.stringify(anchor, null, 2), 'Audit anchor')} disabled={!anchor}>
            <Copy className="w-4 h-4" /> Export Anchor
          </ActionButton>
          <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4">
            <h4 className="text-red-300 font-medium flex items-center gap-2">
              <ShieldAlert className="w-4 h-4" /> Emergency Revocation
            </h4>
            <p className="text-xs text-red-100/70 mt-1">Revoked identities cannot create new sessions or receive new encrypted shares.</p>
            <ActionButton
              variant="secondary"
              onClick={handleRevokeIdentity}
              loading={revokingIdentity}
              className="mt-4 w-full text-red-300 border-red-400/20 hover:bg-red-400/10"
            >
              Revoke This Identity
            </ActionButton>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};
