import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, CheckCircle2, Contact, FileUp, HardDrive, KeyRound, ShieldCheck, Users, AlertTriangle } from 'lucide-react';
import { GlassCard } from '../components/ui/GlassCard';
import { ActionButton } from '../components/ui/ActionButton';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getTrustedIdentities } from '../utils/trust';
import { getErrorMessage } from '../utils/errors';

interface SecuritySummary {
  workspaces: {
    active: number;
    pending: number;
  };
  preKeys: {
    total: number;
    available: number;
    consumed: number;
  };
  sessions: {
    active: number;
  };
  audit: {
    blocks: number;
    latestHash: string | null;
  };
  files: {
    owned: number;
    shared: number;
  };
}

const LOW_PREKEY_THRESHOLD = 20;

export const OverviewPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [loading, setLoading] = useState(false);

  const trustedContactCount = useMemo(() => {
    if (!user) return 0;
    return Object.keys(getTrustedIdentities(user.username)).length;
  }, [user]);

  const loadSummary = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const res = await fetch(apiUrl('/security-summary'), { headers: authHeaders(user.token) });
      const data = await res.json() as SecuritySummary & { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to load overview.');
      setSummary(data);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load overview.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast, user]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  const checklist = [
    {
      label: 'Create or join a workspace',
      done: !!summary && summary.workspaces.active > 0,
      detail: summary?.workspaces.pending ? `${summary.workspaces.pending} pending workspace request${summary.workspaces.pending === 1 ? '' : 's'}` : 'Workspace approval unlocks sharing.',
      to: '/dashboard/workspace-admin'
    },
    {
      label: 'Keep pre-keys available',
      done: !!summary && summary.preKeys.available >= LOW_PREKEY_THRESHOLD,
      detail: `${summary?.preKeys.available ?? 0} available pre-key${summary?.preKeys.available === 1 ? '' : 's'}`,
      to: '/dashboard/security'
    },
    {
      label: 'Trust a contact fingerprint',
      done: trustedContactCount > 0,
      detail: trustedContactCount > 0 ? `${trustedContactCount} trusted contact${trustedContactCount === 1 ? '' : 's'}` : 'Import an invite after out-of-band verification.',
      to: '/dashboard/contacts'
    },
    {
      label: 'Upload your first encrypted file',
      done: !!summary && summary.files.owned > 0,
      detail: `${summary?.files.owned ?? 0} private file${summary?.files.owned === 1 ? '' : 's'} stored`,
      to: '/dashboard/files'
    },
    {
      label: 'Review audit activity',
      done: !!summary && summary.audit.blocks > 0,
      detail: `${summary?.audit.blocks ?? 0} audit block${summary?.audit.blocks === 1 ? '' : 's'}`,
      to: '/dashboard/activity'
    }
  ];

  const completeCount = checklist.filter((item) => item.done).length;

  return (
    <div className="max-w-7xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Overview</h2>
          <p className="text-slate-400">First-run readiness for your encrypted workspace drive.</p>
        </div>
        <ActionButton variant="secondary" onClick={loadSummary} loading={loading}>
          Refresh
        </ActionButton>
      </div>

      <div className="grid lg:grid-cols-[1.2fr_0.8fr] gap-6 mb-6">
        <GlassCard className="p-6">
          <div className="flex items-center justify-between gap-4 mb-6">
            <div>
              <h3 className="text-white font-semibold">Setup Checklist</h3>
              <p className="text-xs text-slate-500 mt-1">{completeCount} of {checklist.length} readiness steps complete.</p>
            </div>
            <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-300">
              Public beta
            </span>
          </div>
          <div className="space-y-3">
            {checklist.map((item) => (
              <Link
                key={item.label}
                to={item.to}
                className="flex items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/20 p-4 hover:bg-white/[0.04] transition-colors no-underline"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                    item.done ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-amber-500/10 border-amber-500/20'
                  }`}>
                    {item.done ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <AlertTriangle className="w-5 h-5 text-amber-400" />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm text-white font-medium">{item.label}</p>
                    <p className="text-xs text-slate-500 mt-1">{item.detail}</p>
                  </div>
                </div>
                <span className="text-xs text-cyan-300 shrink-0">{item.done ? 'Open' : 'Fix'}</span>
              </Link>
            ))}
          </div>
        </GlassCard>

        <GlassCard className="p-6">
          <h3 className="text-white font-semibold mb-4">Recommended Next Action</h3>
          {!summary ? (
            <p className="text-sm text-slate-500">Loading readiness signals...</p>
          ) : summary.workspaces.active === 0 ? (
            <div>
              <p className="text-sm text-slate-300 mb-4">Start by creating or joining a workspace. Sharing is disabled until workspace approval is active.</p>
              <Link to="/dashboard/workspace-admin">
                <ActionButton className="w-full"><Users className="w-4 h-4" /> Open Workspace Admin</ActionButton>
              </Link>
            </div>
          ) : summary.files.owned === 0 ? (
            <div>
              <p className="text-sm text-slate-300 mb-4">Your workspace is ready. Upload a file to start using CrypShare as a secure drive.</p>
              <Link to="/dashboard/files">
                <ActionButton className="w-full"><FileUp className="w-4 h-4" /> Upload First File</ActionButton>
              </Link>
            </div>
          ) : trustedContactCount === 0 ? (
            <div>
              <p className="text-sm text-slate-300 mb-4">Files are ready. Add a trusted contact before sharing encrypted access.</p>
              <Link to="/dashboard/contacts">
                <ActionButton className="w-full"><Contact className="w-4 h-4" /> Trust Contact</ActionButton>
              </Link>
            </div>
          ) : (
            <div>
              <p className="text-sm text-slate-300 mb-4">Your core setup is ready. Review Activity periodically and keep pre-keys healthy.</p>
              <Link to="/dashboard/activity">
                <ActionButton className="w-full"><Activity className="w-4 h-4" /> Review Activity</ActionButton>
              </Link>
            </div>
          )}
        </GlassCard>
      </div>

      <div className="grid md:grid-cols-2 xl:grid-cols-5 gap-4">
        <GlassCard className="p-5">
          <HardDrive className="w-5 h-5 text-cyan-400 mb-3" />
          <p className="text-2xl font-bold text-white">{summary?.files.owned ?? '--'}</p>
          <p className="text-xs text-slate-500 mt-1">Private files</p>
        </GlassCard>
        <GlassCard className="p-5">
          <Users className="w-5 h-5 text-cyan-400 mb-3" />
          <p className="text-2xl font-bold text-white">{summary?.workspaces.active ?? '--'}</p>
          <p className="text-xs text-slate-500 mt-1">Active workspaces</p>
        </GlassCard>
        <GlassCard className="p-5">
          <KeyRound className="w-5 h-5 text-emerald-400 mb-3" />
          <p className={`text-2xl font-bold ${summary && summary.preKeys.available < LOW_PREKEY_THRESHOLD ? 'text-amber-400' : 'text-white'}`}>
            {summary?.preKeys.available ?? '--'}
          </p>
          <p className="text-xs text-slate-500 mt-1">Available pre-keys</p>
        </GlassCard>
        <GlassCard className="p-5">
          <ShieldCheck className="w-5 h-5 text-emerald-400 mb-3" />
          <p className="text-2xl font-bold text-white">{trustedContactCount}</p>
          <p className="text-xs text-slate-500 mt-1">Trusted contacts</p>
        </GlassCard>
        <GlassCard className="p-5">
          <Activity className="w-5 h-5 text-cyan-400 mb-3" />
          <p className="text-2xl font-bold text-white">{summary?.audit.blocks ?? '--'}</p>
          <p className="text-xs text-slate-500 mt-1">Audit blocks</p>
        </GlassCard>
      </div>
    </div>
  );
};
