import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Activity, RefreshCw, Clock, User, Copy, Database } from 'lucide-react';
import { GlassCard } from '../components/ui/GlassCard';
import { ActionButton } from '../components/ui/ActionButton';
import { useToast } from '../components/ui/ToastContext';
import { hashSHA256 } from '../utils/crypto';

interface AuditEntry {
  timestamp: number;
  userId: string;
  action: string;
  previousHash: string;
  hash: string;
}

export const AuditVault: React.FC = () => {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    status: 'idle' | 'verified' | 'failed';
    message: string;
    mismatchedIndex?: number;
  }>({ status: 'idle', message: '' });

  const { showToast } = useToast();

  const fetchAuditLogs = async () => {
    setLoading(true);
    setVerificationResult({ status: 'idle', message: '' });
    try {
      const res = await fetch('http://localhost:3001/audit-log');
      if (!res.ok) throw new Error('Failed to fetch audit vault ledger.');
      const data = await res.json();
      setLogs(data);
    } catch (err: any) {
      showToast(err.message || 'Error querying audit ledger.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const handleVerifyIntegrity = async () => {
    if (logs.length === 0) {
      showToast('No entries in the ledger to verify.', 'info');
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
            message: `Chain link broken at block #${i}. Previous hash expected "${expectedPrevHash.substring(0, 10)}..." but got "${entry.previousHash.substring(0, 10)}...".`,
            mismatchedIndex: i
          });
          showToast('Ledger verification failed! Block link broken.', 'error');
          setVerifying(false);
          return;
        }

        // 2. Recalculate block hash
        const payload = JSON.stringify([entry.timestamp, entry.userId, entry.action]) + entry.previousHash;
        const computedHash = await hashSHA256(payload);

        if (computedHash !== entry.hash) {
          setVerificationResult({
            status: 'failed',
            message: `Hash mismatch at block #${i}. Stored hash: "${entry.hash.substring(0, 10)}...", Recalculated hash: "${computedHash.substring(0, 10)}...". Payload has been tampered with!`,
            mismatchedIndex: i
          });
          showToast('Ledger verification failed! Data tampered with.', 'error');
          setVerifying(false);
          return;
        }

        expectedPrevHash = computedHash;
      }

      setVerificationResult({
        status: 'verified',
        message: `Verification complete. Cryptographic signature chain is 100% authentic. Checked ${logs.length} blocks sequentially against SHA-256 KDF.`
      });
      showToast('Ledger integrity verified successfully!', 'success');
    } catch (err: any) {
      setVerificationResult({
        status: 'failed',
        message: `Verification encountered error: ${err.message}`
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

  return (
    <div className="max-w-5xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Audit Vault</h2>
          <p className="text-slate-400">Cryptographically linked ledger verifying node operations.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchAuditLogs} 
            disabled={loading || verifying}
            className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
            title="Refresh Ledger"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <ActionButton 
            onClick={handleVerifyIntegrity} 
            loading={verifying} 
            disabled={loading || logs.length === 0}
            variant="primary"
          >
            <ShieldCheck className="w-4 h-4" /> Verify Ledger Integrity
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
              {verificationResult.status === 'verified' ? 'Chain Integrity Intact' : 'Ledger Integrity Compromised'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {verificationResult.message}
            </p>
          </div>
        </div>
      )}

      {/* Main Ledger List */}
      <GlassCard className="p-6 overflow-hidden">
        <div className="flex items-center gap-3 mb-6 pb-6 border-b border-white/5">
          <Database className="w-5 h-5 text-cyan-400" />
          <h3 className="text-white font-medium">Tamper-Proof Block Ledger</h3>
          <span className="ml-auto bg-cyan-500/10 text-cyan-400 px-3 py-1 rounded-full text-[10px] font-bold border border-cyan-500/20">
            {logs.length} Blocks
          </span>
        </div>

        {loading ? (
          <div className="p-16 text-center">
            <Activity className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-400 text-sm font-medium">Retrieving Ledger Blocks...</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-16 text-center text-slate-500 border border-dashed border-white/5 rounded-2xl">
            Audit Vault ledger is empty. Complete a dispatch or register an identity to populate blocks.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/5 text-slate-500 text-[10px] uppercase font-bold tracking-wider">
                  <th className="py-4 px-4 w-12 text-center">Block</th>
                  <th className="py-4 px-4 w-36">Timestamp</th>
                  <th className="py-4 px-4 w-32">Operator</th>
                  <th className="py-4 px-4 w-44">Action Event</th>
                  <th className="py-4 px-4">Previous Hash</th>
                  <th className="py-4 px-4">Block Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {logs.map((entry, idx) => {
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
                          {entry.userId}
                        </span>
                      </td>
                      <td className="py-4 px-4 font-sans font-semibold text-slate-200">
                        {entry.action}
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
                            onClick={() => copyToClipboard(entry.hash, `Block Hash #${idx}`)}
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
