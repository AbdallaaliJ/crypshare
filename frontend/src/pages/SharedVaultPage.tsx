import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, Download, FileCheck, Folder, RefreshCw, Search, ShieldCheck, ShieldAlert } from 'lucide-react';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getErrorMessage } from '../utils/errors';
import {
  decryptFileChunked,
  decryptFileData,
  decryptFileKeyWithX3DH,
  importECDSAPublicKey,
  verifySignature
} from '../utils/crypto';

interface SharedVaultRecord {
  id: string;
  vaultFileId: string;
  ownerUsername: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  signature: string;
  encryptedPrivatePreKey: string | null;
  preKeyIv: string | null;
  createdAt: number;
  fileSize: number;
  encryptedMetadata: string;
  metadataIv: string;
  ownerIdentityPublicKeyECDH: string;
  ownerIdentityPublicKeyECDSA: string;
}

interface SharedMetadata {
  name: string;
  type: string;
  size: number;
  uploadedAt: number;
  folder?: string;
}

interface SharedVaultView extends SharedVaultRecord {
  metadata: SharedMetadata | null;
  signatureValid: boolean | null;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function getFolderName(metadata: SharedMetadata | null) {
  return metadata?.folder?.trim() || 'Vault';
}

export const SharedVaultPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [files, setFiles] = useState<SharedVaultView[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeGrantId, setActiveGrantId] = useState<string | null>(null);

  const openSharedRecord = useCallback(async (file: SharedVaultRecord): Promise<SharedVaultView> => {
    if (!user?.kek || !user.privateKeyECDH || !file.encryptedPrivatePreKey || !file.preKeyIv) {
      return { ...file, metadata: null, signatureValid: null };
    }

    try {
      const ownerSigningKey = await importECDSAPublicKey(file.ownerIdentityPublicKeyECDSA);
      const signaturePayload = `${file.vaultFileId}:${file.wrappedFileKey}:${file.metadataIv}`;
      const signatureValid = await verifySignature(ownerSigningKey, file.signature, signaturePayload);
      if (!signatureValid) return { ...file, metadata: null, signatureValid };

      const fileKey = await decryptFileKeyWithX3DH(
        file.wrappedFileKey,
        file.ephemeralPublicKey,
        file.ownerIdentityPublicKeyECDH,
        user.privateKeyECDH,
        file.encryptedPrivatePreKey,
        file.preKeyIv,
        user.kek
      );
      const metadataText = await decryptFileData(fileKey, file.encryptedMetadata, file.metadataIv);
      return { ...file, metadata: JSON.parse(metadataText) as SharedMetadata, signatureValid };
    } catch {
      return { ...file, metadata: null, signatureValid: false };
    }
  }, [user]);

  const loadSharedFiles = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const res = await fetch(apiUrl('/shared-vault-files'), { headers: authHeaders(user.token) });
      const data = await res.json() as { files: SharedVaultRecord[]; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to load shared vault files.');

      const opened = await Promise.all(data.files.map(openSharedRecord));
      setFiles(opened);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load shared vault files.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [openSharedRecord, showToast, user]);

  useEffect(() => {
    loadSharedFiles();
  }, [loadSharedFiles]);

  const filteredFiles = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return files;

    return files.filter((file) => [
      file.metadata?.name || '',
      file.metadata?.type || '',
      getFolderName(file.metadata),
      file.ownerUsername
    ].join(' ').toLowerCase().includes(query));
  }, [files, searchQuery]);

  const handleDownload = async (file: SharedVaultView) => {
    if (!user?.kek || !user.privateKeyECDH || !file.encryptedPrivatePreKey || !file.preKeyIv) return;

    setActiveGrantId(file.id);
    try {
      const ownerSigningKey = await importECDSAPublicKey(file.ownerIdentityPublicKeyECDSA);
      const signaturePayload = `${file.vaultFileId}:${file.wrappedFileKey}:${file.metadataIv}`;
      const signatureValid = await verifySignature(ownerSigningKey, file.signature, signaturePayload);
      if (!signatureValid) throw new Error('Owner signature verification failed.');

      const fileKey = await decryptFileKeyWithX3DH(
        file.wrappedFileKey,
        file.ephemeralPublicKey,
        file.ownerIdentityPublicKeyECDH,
        user.privateKeyECDH,
        file.encryptedPrivatePreKey,
        file.preKeyIv,
        user.kek
      );
      const blobRes = await fetch(apiUrl(`/shared-vault-files/${file.id}/download`), { headers: authHeaders(user.token) });
      if (!blobRes.ok) throw new Error('Encrypted shared blob unavailable.');

      const encryptedBlob = await blobRes.blob();
      const plainBlob = await decryptFileChunked(fileKey, encryptedBlob);
      const url = URL.createObjectURL(plainBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.metadata?.name || 'shared-vault-file';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showToast('Shared file decrypted.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to decrypt shared file.'), 'error');
    } finally {
      setActiveGrantId(null);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Shared With Me</h2>
          <p className="text-slate-400">Encrypted vault grants from trusted identities.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search shared..."
              className="w-64 bg-black/30 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
          </div>
          <button
            onClick={loadSharedFiles}
            disabled={loading}
            className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
            title="Refresh shared files"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="grid gap-3">
        {loading ? (
          <GlassCard className="p-12 text-center">
            <Activity className="w-10 h-10 text-cyan-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-400 text-sm">Opening shared grants...</p>
          </GlassCard>
        ) : files.length === 0 ? (
          <GlassCard className="p-12 text-center text-slate-500">
            No vault files have been shared with you yet.
          </GlassCard>
        ) : filteredFiles.length === 0 ? (
          <GlassCard className="p-12 text-center text-slate-500">
            No shared files match this search.
          </GlassCard>
        ) : (
          filteredFiles.map((file) => (
            <div key={file.id} className="flex items-center justify-between gap-4 p-5 bg-slate-900/40 border border-white/5 rounded-2xl hover:border-white/10 transition-all">
              <div className="flex items-center gap-4 min-w-0">
                <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center">
                  <FileCheck className="w-6 h-6 text-slate-400" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className="text-white font-medium truncate">{file.metadata?.name || 'Encrypted metadata unavailable'}</h4>
                    {file.signatureValid ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-red-400" />}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    Shared by {file.ownerUsername} • {formatBytes(file.metadata?.size || file.fileSize)} • {new Date(file.createdAt).toLocaleString()}
                  </p>
                  <p className="text-[10px] text-cyan-300/80 mt-1 inline-flex items-center gap-1">
                    <Folder className="w-3 h-3" /> {getFolderName(file.metadata)}
                  </p>
                </div>
              </div>
              <button
                onClick={() => handleDownload(file)}
                disabled={activeGrantId !== null || file.signatureValid !== true}
                className="p-3 bg-white/5 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-400 rounded-xl border border-white/10 hover:border-emerald-500/20 transition-colors disabled:opacity-50"
                title="Decrypt and download"
              >
                {activeGrantId === file.id ? <Activity className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
