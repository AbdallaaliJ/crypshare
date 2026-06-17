import React, { useCallback, useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Activity, RefreshCw, Clock, User, Copy, Database } from 'lucide-react';
import { GlassCard } from '../components/ui/GlassCard';
import { ActionButton } from '../components/ui/ActionButton';
import { useToast } from '../components/ui/useToast';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { getErrorMessage } from '../utils/errors';
import { hashSHA256 } from '../utils/crypto';

interface AuditEntry {
  timestamp: number;
  userId: string;
  action: string;
  previousHash: string;
  hash: string;
  actorId?: string | null;
  subjectId?: string | null;
  workspaceId?: string | null;
  visibility?: string | null;
}

interface AuditAnchor {
  version: number;
  exportedAt: number;
  blockCount: number;
  firstTimestamp: number | null;
  latestTimestamp: number | null;
  firstHash: string | null;
  latestHash: string | null;
  ledgerDigest: string;
  scope?: string;
}

type AuditFilter = 'all' | 'sharing' | 'workspace' | 'identity' | 'sessions';

function auditCategory(action: string): Exclude<AuditFilter, 'all'> {
  if (action.includes('Workspace')) return 'workspace';
  if (action.includes('Share') || action.includes('Vault File')) return 'sharing';
  if (action.includes('Identity') || action.includes('Registration')) return 'identity';
  return 'sessions';
}

function auditBadgeClass(category: Exclude<AuditFilter, 'all'>) {
  const classes = {
    sharing: 'border-cyan-500/20 bg-cyan-500/10 text-cyan-300',
    workspace: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300',
    identity: 'border-amber-500/20 bg-amber-500/10 text-amber-300',
    sessions: 'border-slate-500/20 bg-slate-500/10 text-slate-300'
  };
  return classes[category];
}

export const AuditVault: React.FC = () => {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [auditFilter, setAuditFilter] = useState<AuditFilter>('all');
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [anchor, setAnchor] = useState<AuditAnchor | null>(null);
  const [anchorInput, setAnchorInput] = useState('');
  const [anchorCheck, setAnchorCheck] = useState<{
    status: 'idle' | 'matched' | 'failed';
    message: string;
  }>({ status: 'idle', message: '' });
  const [verificationResult, setVerificationResult] = useState<{
    status: 'idle' | 'verified' | 'failed';
    message: string;
    mismatchedIndex?: number;
  }>({ status: 'idle', message: '' });

  const { showToast } = useToast();
  const { user } = useAuth();
  const filteredLogs = logs.filter((entry) => auditFilter === 'all' || auditCategory(entry.action) === auditFilter);

  const fetchAuditLogs = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    setVerificationResult({ status: 'idle', message: '' });
    try {
      const res = await fetch(apiUrl('/audit-log'), { headers: authHeaders(user.token) });
      if (!res.ok) throw new Error('Failed to fetch visible activity.');
      const data = await res.json() as AuditEntry[];
      setLogs(data);

      const anchorRes = await fetch(apiUrl('/audit-anchor'), { headers: authHeaders(user.token) });
      if (!anchorRes.ok) throw new Error('Failed to fetch audit anchor.');
      const anchorData = await anchorRes.json() as AuditAnchor;
      setAnchor(anchorData);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Error querying activity.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast, user]);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  const handleVerifyIntegrity = async () => {
    if (logs.length === 0) {
      showToast('No visible activity entries to verify.', 'info');
      return;
    }

    setVerifying(true);
    setVerificationResult({ status: 'idle', message: '' });

    // Artificial delay for futuristic micro-animation feel
    await new Promise((resolve) => setTimeout(resolve, 800));

    try {
      const GENESIS_HASH = "0".repeat(64);
      let expectedPrevHash = GENESIS_HASH;

      for (let i = 0; i < logs.length; i++) {
        const entry = logs[i];
        
        // 1. Verify previous hash linkage
        if (entry.previousHash !== expectedPrevHash) {
          setVerificationResult({
            status: 'failed',
            message: `Visible activity link broken at entry #${i}. Previous hash expected "${expectedPrevHash.substring(0, 10)}..." but got "${entry.previousHash.substring(0, 10)}...".`,
            mismatchedIndex: i
          });
          showToast('Visible activity verification failed.', 'error');
          setVerifying(false);
          return;
        }

        // 2. Recalculate visible entry hash
        const payload = JSON.stringify([
          entry.timestamp,
          entry.userId,
          entry.action,
          entry.actorId || entry.userId,
          entry.subjectId || entry.userId,
          entry.workspaceId || null,
          entry.visibility || 'user'
        ]) + entry.previousHash;
        const computedHash = await hashSHA256(payload);

        if (computedHash !== entry.hash) {
          setVerificationResult({
            status: 'failed',
            message: `Hash mismatch at entry #${i}. Stored hash: "${entry.hash.substring(0, 10)}...", recalculated hash: "${computedHash.substring(0, 10)}...". Visible activity changed.`,
            mismatchedIndex: i
          });
          showToast('Visible activity verification failed.', 'error');
          setVerifying(false);
          return;
        }

        expectedPrevHash = computedHash;
      }

      setVerificationResult({
        status: 'verified',
        message: `Verification complete. Checked ${logs.length} visible activity entries sequentially against SHA-256.`
      });
      showToast('Visible activity integrity verified.', 'success');
    } catch (err: unknown) {
      setVerificationResult({
        status: 'failed',
        message: `Verification encountered error: ${getErrorMessage(err, 'Unknown verification error')}`
      });
      showToast('Verification aborted due to error.', 'error');
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    showToast(`${label} copied to clipboard`, 'success');
  };

  const handleCopyAnchor = () => {
    if (!anchor) return;
    copyToClipboard(JSON.stringify(anchor, null, 2), 'Audit anchor');
  };

  const handleCheckAnchor = () => {
    if (!anchor) return;

    try {
      const parsed = JSON.parse(anchorInput) as Partial<AuditAnchor>;
      if (!parsed.latestHash || !parsed.ledgerDigest || typeof parsed.blockCount !== 'number') {
        throw new Error('Missing anchor fields.');
      }

      if (parsed.latestHash === anchor.latestHash && parsed.ledgerDigest === anchor.ledgerDigest && parsed.blockCount === anchor.blockCount) {
        setAnchorCheck({
          status: 'matched',
          message: 'Checkpoint matches the current visible activity digest and count.'
        });
        showToast('Activity checkpoint matches.', 'success');
        return;
      }

      setAnchorCheck({
        status: 'failed',
        message: 'Checkpoint does not match the current visible activity. The view changed or the checkpoint came from another account.'
      });
      showToast('Activity checkpoint mismatch.', 'error');
    } catch (err: unknown) {
      setAnchorCheck({
        status: 'failed',
        message: getErrorMessage(err, 'Invalid anchor JSON.')
      });
      showToast('Invalid anchor.', 'error');
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Security Activity</h2>
          <p className="text-slate-400">Your security activity plus workspace events you are allowed to administer.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchAuditLogs} 
            disabled={loading || verifying}
            className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
            title="Refresh activity"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <ActionButton 
            onClick={handleVerifyIntegrity} 
            loading={verifying} 
            disabled={loading || logs.length === 0}
            variant="primary"
          >
            <ShieldCheck className="w-4 h-4" /> Verify Visible Activity
          </ActionButton>
        </div>
      </div>

      {/* Verification Banner */}
      {verificationResult.status !== 'idle' && (
        <div className={`mb-8 p-5 rounded-2xl border animate-in fade-in duration-300 flex items-start gap-4 
          ${verificationResult.status === 'verified' 
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
            : 'bg-red-500/10 border-red-500/20 text-red-400'}`}
        >
          <div className="mt-1">
            {verificationResult.status === 'verified' ? (
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-6 h-6 text-red-400" />
            )}
          </div>
          <div className="flex-1">
            <h4 className="font-bold text-sm uppercase tracking-wide mb-1">
              {verificationResult.status === 'verified' ? 'Visible Activity Integrity Intact' : 'Visible Activity Integrity Failed'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {verificationResult.message}
            </p>
          </div>
        </div>
      )}

      {anchor && (
        <GlassCard className="p-6 mb-8">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="min-w-0">
              <h3 className="text-white font-medium mb-2">Visible Activity Checkpoint</h3>
              <p className="text-xs text-slate-500 mb-4">
                Store this checkpoint outside CrypShare to compare your visible activity view later. It does not expose other public users.
              </p>
              <div className="grid md:grid-cols-3 gap-3">
                <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                  <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Entries</p>
                  <p className="text-2xl font-bold text-white mt-1">{anchor.blockCount}</p>
                </div>
                <div className="rounded-xl border border-white/5 bg-black/20 p-4 min-w-0">
                  <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Root Hash</p>
                  <p className="font-mono text-xs text-emerald-400 mt-2 break-all">{anchor.latestHash?.slice(0, 24)}...</p>
                </div>
                <div className="rounded-xl border border-white/5 bg-black/20 p-4 min-w-0">
                  <p className="text-[10px] uppercase text-slate-500 font-bold tracking-widest">Digest</p>
                  <p className="font-mono text-xs text-cyan-400 mt-2 break-all">{anchor.ledgerDigest.slice(0, 24)}...</p>
                </div>
              </div>
            </div>
            <div className="flex flex-col gap-2 shrink-0">
              <ActionButton variant="secondary" onClick={() => copyToClipboard(anchor.latestHash || '', 'Visible activity hash')} disabled={!anchor.latestHash}>
                <Copy className="w-4 h-4" /> View Hash
              </ActionButton>
              <ActionButton variant="secondary" onClick={handleCopyAnchor}>
                <Copy className="w-4 h-4" /> Export Anchor
              </ActionButton>
            </div>
          </div>

          <div className="mt-6 border-t border-white/5 pt-6">
            <textarea
              value={anchorInput}
              onChange={(event) => setAnchorInput(event.target.value)}
              placeholder="Paste a previously exported audit anchor JSON..."
              className="min-h-28 w-full resize-none rounded-xl border border-white/5 bg-black/30 p-4 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
            <div className="mt-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
              <ActionButton variant="secondary" onClick={handleCheckAnchor} disabled={!anchorInput.trim()}>
                Compare Anchor
              </ActionButton>
              {anchorCheck.status !== 'idle' && (
                <p className={`text-xs font-mono ${anchorCheck.status === 'matched' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {anchorCheck.message}
                </p>
              )}
            </div>
          </div>
        </GlassCard>
      )}

      {/* Main Activity List */}
      <GlassCard className="p-6 overflow-hidden">
        <div className="mb-6 pb-6 border-b border-white/5">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-5 h-5 text-cyan-400" />
            <h3 className="text-white font-medium">Visible Security Activity</h3>
            <span className="ml-auto bg-cyan-500/10 text-cyan-400 px-3 py-1 rounded-full text-[10px] font-bold border border-cyan-500/20">
              {filteredLogs.length} of {logs.length} Entries
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {(['all', 'sharing', 'workspace', 'identity', 'sessions'] as AuditFilter[]).map((filter) => (
              <button
                key={filter}
                onClick={() => setAuditFilter(filter)}
                className={`rounded-xl border px-3 py-2 text-xs font-bold capitalize transition-colors ${
                  auditFilter === filter
                    ? 'border-cyan-500/30 bg-cyan-500/15 text-cyan-200'
                    : 'border-white/10 bg-white/5 text-slate-400 hover:text-white'
                }`}
              >
                {filter}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="p-16 text-center">
            <Activity className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-400 text-sm font-medium">Retrieving activity...</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-16 text-center text-slate-500 border border-dashed border-white/5 rounded-2xl">
            Security activity is empty. Register, upload, share, or manage a workspace to populate your visible events.
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-16 text-center text-slate-500 border border-dashed border-white/5 rounded-2xl">
            No security activity matches this filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/5 text-slate-500 text-[10px] uppercase font-bold tracking-wider">
                  <th className="py-4 px-4 w-12 text-center">Entry</th>
                  <th className="py-4 px-4 w-36">Timestamp</th>
                  <th className="py-4 px-4 w-32">Actor</th>
                  <th className="py-4 px-4 w-44">Action Event</th>
                  <th className="py-4 px-4">Previous Hash</th>
                  <th className="py-4 px-4">Entry Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredLogs.map((entry) => {
                  const idx = logs.indexOf(entry);
                  const category = auditCategory(entry.action);
                  const isMismatched = verificationResult.status === 'failed' && verificationResult.mismatchedIndex === idx;
                  return (
                    <tr 
                      key={idx} 
                      className={`hover:bg-white/5 transition-colors font-mono text-xs
                        ${isMismatched ? 'bg-red-500/5 hover:bg-red-500/10' : ''}`}
                    >
                      <td className="py-4 px-4 text-center font-bold text-slate-400">#{idx}</td>
                      <td className="py-4 px-4 text-slate-400 whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-slate-500" />
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-white">
                        <span className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-cyan-400" />
                          {entry.actorId || entry.userId}
                        </span>
                      </td>
                      <td className="py-4 px-4 font-sans font-semibold text-slate-200">
                        <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-bold ${auditBadgeClass(category)}`}>
                          {category}
                        </span>
                        <span className="ml-2">{entry.action}</span>
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2 group/hash">
                          <span className="text-slate-500 tracking-tight">
                            {entry.previousHash.substring(0, 10)}...
                          </span>
                          <button 
                            onClick={() => copyToClipboard(entry.previousHash, `Previous Hash #${idx}`)}
                            className="opacity-0 group-hover/hash:opacity-100 p-1 hover:bg-white/10 rounded transition-all text-slate-400 hover:text-white"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2 group/hash">
                          <span className={`${isMismatched ? 'text-red-400 font-bold' : 'text-emerald-400'} tracking-tight`}>
                            {entry.hash.substring(0, 10)}...
                          </span>
                          <button 
                            onClick={() => copyToClipboard(entry.hash, `Entry Hash #${idx}`)}
                            className="opacity-0 group-hover/hash:opacity-100 p-1 hover:bg-white/10 rounded transition-all text-slate-400 hover:text-white"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
};
