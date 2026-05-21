import React from 'react';
import { Lock } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../components/ui/ToastContext';
import { GlassCard } from '../components/ui/GlassCard';
import { ActionButton } from '../components/ui/ActionButton';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();

  const handleCopyToken = () => {
    if (user?.identityPublicKeyECDH) {
      navigator.clipboard.writeText(user.identityPublicKeyECDH);
      showToast('Public Identity Token copied to clipboard!', 'success');
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <h2 className="text-3xl font-bold text-white mb-8">Identity Management</h2>
      <GlassCard className="p-8 space-y-6">
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Public Identity Token (ECDH)</h4>
            <p className="text-xs text-slate-500 mt-1 font-mono break-all max-w-sm">
              {user?.identityPublicKeyECDH}
            </p>
          </div>
          <ActionButton variant="secondary" onClick={handleCopyToken}>Copy</ActionButton>
        </div>
        <div className="flex justify-between items-center pb-6 border-b border-white/5">
          <div>
            <h4 className="text-white font-medium">Encryption Engine</h4>
            <p className="text-xs text-slate-500 mt-1">v4.2.1-stable (AES-GCM-256)</p>
          </div>
          <div className="bg-cyan-500/10 text-cyan-400 px-3 py-1 rounded-full text-[10px] font-bold border border-cyan-500/20">Active</div>
        </div>
        <div className="pt-4">
          <h4 className="text-red-400 font-medium mb-2 flex items-center gap-2">
            <Lock className="w-4 h-4" /> Security Zone
          </h4>
          <p className="text-xs text-slate-500 mb-4">
            Warning: Rotating your keys or master secret will make old sharded files inaccessible.
          </p>
          <ActionButton variant="secondary" className="text-red-400 border-red-400/20 hover:bg-red-400/10" disabled>
            Rotate Identity Keys (Coming Soon)
          </ActionButton>
        </div>
      </GlassCard>
    </div>
  );
};
