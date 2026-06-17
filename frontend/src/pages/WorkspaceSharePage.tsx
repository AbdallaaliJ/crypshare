import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { Activity, ArrowRight, Download, FileCheck, FolderKanban, RefreshCw, Search, ShieldAlert, ShieldCheck, UploadCloud, Users } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import type { DashboardOutletContext } from '../layouts/DashboardLayout';
import { getErrorMessage } from '../utils/errors';
import { formatBytes } from '../utils/uploadLimits';
import {
  decryptFileChunked,
  decryptFileData,
  decryptFileKeyWithX3DH,
  importECDSAPublicKey,
  unwrapFileKeyForOwner,
  verifySignature
} from '../utils/crypto';

interface WorkspaceMember {
  username: string;
  role: string;
  status: string;
}

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

interface VaultFileRecord {
  id: string;
  fileSize: number;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrappedFileKeyIv: string;
  createdAt: number;
  sharedWithCount?: number;
}

interface VaultGrantRecord {
  id: string;
  vaultFileId: string;
  recipientUsername: string;
  createdAt: number;
}

interface FileMetadata {
  name: string;
  type: string;
  size: number;
  uploadedAt: number;
  folder?: string;
}

interface ReceivedWorkspaceFile extends SharedVaultRecord {
  metadata: FileMetadata | null;
  signatureValid: boolean | null;
}

interface OwnedWorkspaceFile extends VaultFileRecord {
  metadata: FileMetadata | null;
  workspaceRecipients: string[];
}

function folderName(metadata: FileMetadata | null) {
  return metadata?.folder?.trim() || 'Vault';
}

export const WorkspaceSharePage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const { activeWorkspaceId, selectedWorkspace } = useOutletContext<DashboardOutletContext>();
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [receivedFiles, setReceivedFiles] = useState<ReceivedWorkspaceFile[]>([]);
  const [ownedFiles, setOwnedFiles] = useState<OwnedWorkspaceFile[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeDownloadId, setActiveDownloadId] = useState<string | null>(null);

  const activeMembers = useMemo(
    () => members.filter((member) => member.status === 'active'),
    [members]
  );
  const openReceivedRecord = useCallback(async (file: SharedVaultRecord): Promise<ReceivedWorkspaceFile> => {
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
      return { ...file, metadata: JSON.parse(metadataText) as FileMetadata, signatureValid };
    } catch {
      return { ...file, metadata: null, signatureValid: false };
    }
  }, [user]);

  const openOwnedRecord = useCallback(async (
    file: VaultFileRecord,
    grants: VaultGrantRecord[],
    memberNames: Set<string>
  ): Promise<OwnedWorkspaceFile> => {
    let metadata: FileMetadata | null = null;

    try {
      if (user?.kek) {
        const fileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv);
        const metadataText = await decryptFileData(fileKey, file.encryptedMetadata, file.metadataIv);
        metadata = JSON.parse(metadataText) as FileMetadata;
      }
    } catch {
      metadata = null;
    }

    return {
      ...file,
      metadata,
      workspaceRecipients: grants
        .map((grant) => grant.recipientUsername)
        .filter((recipient) => memberNames.has(recipient))
    };
  }, [user?.kek]);

  const loadWorkspaceShare = useCallback(async () => {
    if (!user || !activeWorkspaceId || selectedWorkspace?.status !== 'active') return;

    setLoading(true);
    try {
      const memberRes = await fetch(apiUrl(`/workspaces/${activeWorkspaceId}/members`), { headers: authHeaders(user.token) });
      const memberData = await memberRes.json() as { members?: WorkspaceMember[]; error?: string };
      if (!memberRes.ok || !Array.isArray(memberData.members)) {
        throw new Error(memberData.error || 'Unable to load workspace members.');
      }
      setMembers(memberData.members);

      const memberNames = new Set(memberData.members.filter((member) => member.status === 'active').map((member) => member.username));

      const sharedRes = await fetch(apiUrl('/shared-vault-files'), { headers: authHeaders(user.token) });
      const sharedData = await sharedRes.json() as { files?: SharedVaultRecord[]; error?: string };
      if (!sharedRes.ok || !Array.isArray(sharedData.files)) {
        throw new Error(sharedData.error || 'Unable to load shared workspace files.');
      }
      const openedReceived = await Promise.all(
        sharedData.files
          .filter((file) => memberNames.has(file.ownerUsername))
          .map(openReceivedRecord)
      );
      setReceivedFiles(openedReceived);

      const vaultRes = await fetch(apiUrl('/vault-files'), { headers: authHeaders(user.token) });
      const vaultData = await vaultRes.json() as { files?: VaultFileRecord[]; error?: string };
      if (!vaultRes.ok || !Array.isArray(vaultData.files)) {
        throw new Error(vaultData.error || 'Unable to load your vault files.');
      }

      const openedOwned = await Promise.all(vaultData.files.map(async (file) => {
        const grantsRes = await fetch(apiUrl(`/vault-files/${file.id}/grants`), { headers: authHeaders(user.token) });
        const grantsData = await grantsRes.json() as { grants?: VaultGrantRecord[]; error?: string };
        if (!grantsRes.ok || !Array.isArray(grantsData.grants)) {
          throw new Error(grantsData.error || 'Unable to load file grants.');
        }
        return openOwnedRecord(file, grantsData.grants, memberNames);
      }));
      setOwnedFiles(openedOwned.filter((file) => file.workspaceRecipients.length > 0));
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load workspace share.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [activeWorkspaceId, openOwnedRecord, openReceivedRecord, selectedWorkspace?.status, showToast, user]);

  useEffect(() => {
    loadWorkspaceShare();
  }, [loadWorkspaceShare]);

  const filteredReceived = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return receivedFiles;
    return receivedFiles.filter((file) => [
      file.metadata?.name || '',
      folderName(file.metadata),
      file.ownerUsername
    ].join(' ').toLowerCase().includes(normalized));
  }, [query, receivedFiles]);

  const filteredOwned = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return ownedFiles;
    return ownedFiles.filter((file) => [
      file.metadata?.name || '',
      folderName(file.metadata),
      file.workspaceRecipients.join(' ')
    ].join(' ').toLowerCase().includes(normalized));
  }, [ownedFiles, query]);

  const handleDownload = async (file: ReceivedWorkspaceFile) => {
    if (!user?.kek || !user.privateKeyECDH || !file.encryptedPrivatePreKey || !file.preKeyIv) return;

    setActiveDownloadId(file.id);
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
      link.download = file.metadata?.name || 'workspace-file';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showToast('Workspace file decrypted.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to decrypt workspace file.'), 'error');
    } finally {
      setActiveDownloadId(null);
    }
  };

  if (!activeWorkspaceId || !selectedWorkspace) {
    return (
      <div className="max-w-5xl mx-auto py-12">
        <GlassCard className="p-10 text-center">
          <FolderKanban className="w-12 h-12 text-[var(--brand-cyan)] mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-[var(--app-text)] mb-2">No Workspace Selected</h2>
          <p className="text-sm text-[var(--app-muted)] mb-6">Create or join a workspace before using the common sharing area.</p>
          <ActionButton onClick={() => navigate('/dashboard/workspace-admin')}>Open Workspace Admin</ActionButton>
        </GlassCard>
      </div>
    );
  }

  if (selectedWorkspace.status !== 'active') {
    return (
      <div className="max-w-5xl mx-auto py-12">
        <GlassCard className="p-10 text-center">
          <ShieldAlert className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-[var(--app-text)] mb-2">Workspace Approval Pending</h2>
          <p className="text-sm text-[var(--app-muted)] mb-6">The common share area unlocks after a workspace admin approves your membership.</p>
          <ActionButton onClick={() => navigate('/dashboard/workspace-admin')}>Check Workspace Status</ActionButton>
        </GlassCard>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto py-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col gap-4 mb-8 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-[var(--brand-cyan)] font-bold mb-2">Workspace Common Area</p>
          <h2 className="text-3xl font-bold text-[var(--app-text)] mb-2">{selectedWorkspace.name}</h2>
          <p className="text-sm text-[var(--app-muted)] max-w-2xl">
            Files here are still normal encrypted vault shares. Workspace membership controls who can be discovered, while trusted fingerprints and encrypted grants control access.
          </p>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--app-muted)]" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search workspace files"
              className="app-field w-full rounded-lg py-3 pl-10 pr-4 text-sm sm:w-72"
            />
          </div>
          <button
            onClick={loadWorkspaceShare}
            disabled={loading}
            className="theme-toggle justify-center"
            title="Refresh workspace share"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3 mb-6">
        <GlassCard className="p-5">
          <Users className="w-5 h-5 text-[var(--brand-cyan)] mb-3" />
          <p className="text-2xl font-bold text-[var(--app-text)]">{activeMembers.length}</p>
          <p className="text-xs text-[var(--app-muted)]">Active workspace members</p>
        </GlassCard>
        <GlassCard className="p-5">
          <FileCheck className="w-5 h-5 text-[var(--success-color)] mb-3" />
          <p className="text-2xl font-bold text-[var(--app-text)]">{receivedFiles.length}</p>
          <p className="text-xs text-[var(--app-muted)]">Files shared with you here</p>
        </GlassCard>
        <GlassCard className="p-5">
          <UploadCloud className="w-5 h-5 text-[var(--brand-blue)] mb-3" />
          <p className="text-2xl font-bold text-[var(--app-text)]">{ownedFiles.length}</p>
          <p className="text-xs text-[var(--app-muted)]">Your files shared to members</p>
        </GlassCard>
      </div>

      {loading ? (
        <GlassCard className="p-12 text-center">
          <Activity className="w-10 h-10 text-[var(--brand-cyan)] animate-spin mx-auto mb-4" />
          <p className="text-sm text-[var(--app-muted)]">Opening workspace share...</p>
        </GlassCard>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <GlassCard className="p-5">
            <div className="flex items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">Shared By Workspace Members</h3>
                <p className="text-xs text-[var(--app-muted)]">Download-only files granted to your identity.</p>
              </div>
              <ActionButton variant="secondary" onClick={() => navigate('/dashboard/shared')}>
                Shared <ArrowRight className="w-4 h-4" />
              </ActionButton>
            </div>
            <div className="space-y-3">
              {filteredReceived.length === 0 ? (
                <div className="rounded-lg border border-dashed border-[var(--app-border)] p-8 text-center text-sm text-[var(--app-muted)]">
                  No workspace member has shared a file with you yet.
                </div>
              ) : (
                filteredReceived.map((file) => (
                  <div key={file.id} className="flex items-center justify-between gap-4 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] p-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h4 className="truncate font-semibold text-[var(--app-text)]">{file.metadata?.name || 'Encrypted metadata unavailable'}</h4>
                        {file.signatureValid ? <ShieldCheck className="w-4 h-4 text-[var(--success-color)]" /> : <ShieldAlert className="w-4 h-4 text-red-500" />}
                      </div>
                      <p className="mt-1 text-xs text-[var(--app-muted)]">
                        {file.ownerUsername} · {folderName(file.metadata)} · {formatBytes(file.metadata?.size || file.fileSize)}
                      </p>
                    </div>
                    <button
                      onClick={() => handleDownload(file)}
                      disabled={activeDownloadId !== null || file.signatureValid !== true}
                      className="theme-toggle !p-3"
                      title="Decrypt and download"
                    >
                      {activeDownloadId === file.id ? <Activity className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                    </button>
                  </div>
                ))
              )}
            </div>
          </GlassCard>

          <GlassCard className="p-5">
            <div className="flex items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">Shared By You</h3>
                <p className="text-xs text-[var(--app-muted)]">Your vault files already granted to workspace members.</p>
              </div>
              <ActionButton onClick={() => navigate('/dashboard/files')}>
                <UploadCloud className="w-4 h-4" /> Add
              </ActionButton>
            </div>
            <div className="space-y-3">
              {filteredOwned.length === 0 ? (
                <div className="rounded-lg border border-dashed border-[var(--app-border)] p-8 text-center text-sm text-[var(--app-muted)]">
                  Share a file from Files with a trusted workspace member to make it appear here.
                </div>
              ) : (
                filteredOwned.map((file) => (
                  <div key={file.id} className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] p-4">
                    <h4 className="truncate font-semibold text-[var(--app-text)]">{file.metadata?.name || 'Encrypted metadata unavailable'}</h4>
                    <p className="mt-1 text-xs text-[var(--app-muted)]">
                      {folderName(file.metadata)} · {formatBytes(file.metadata?.size || file.fileSize)}
                    </p>
                    <p className="mt-3 text-[11px] font-semibold uppercase tracking-wider text-[var(--brand-cyan)]">
                      Shared with {file.workspaceRecipients.join(', ')}
                    </p>
                  </div>
                ))
              )}
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
};
