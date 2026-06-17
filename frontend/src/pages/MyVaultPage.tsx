import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Activity, Download, File as FileIcon, Folder, FolderPlus, HardDrive, Lock, RefreshCw, RotateCcw, Save, Search, Share2, Trash2, UploadCloud, UserMinus, ShieldCheck, ShieldQuestion, ShieldAlert, X, Info } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getErrorMessage } from '../utils/errors';
import {
  formatFingerprint,
  forgetTrustedIdentity,
  fingerprintMatches,
  getTrustStatus,
  trustIdentity,
  type TrustStatus
} from '../utils/trust';
import {
  decryptFileChunked,
  decryptFileData,
  encryptFileKeyWithX3DH,
  encryptFileChunk,
  encryptFileChunked,
  encryptFileData,
  estimateChunkedEncryptedSize,
  FILE_CHUNK_SIZE_BYTES,
  generateFileKey,
  signPayload,
  unwrapFileKeyForOwner,
  wrapFileKeyForOwner
} from '../utils/crypto';
import { DEFAULT_UPLOAD_FILE_LIMIT_BYTES, fetchUploadLimits, formatBytes } from '../utils/uploadLimits';
import { useUserPreferences } from '../utils/preferences';
import type { DirectoryUser } from '../types/api';

interface VaultFileRecord {
  id: string;
  fileSize: number;
  encryptedMetadata: string;
  metadataIv: string;
  wrappedFileKey: string;
  wrappedFileKeyIv: string;
  createdAt: number;
  deletedAt?: number | null;
  sharedWithCount?: number;
}

interface VaultMetadata {
  name: string;
  type: string;
  size: number;
  uploadedAt: number;
  folder?: string;
}

interface VaultFileView extends VaultFileRecord {
  metadata: VaultMetadata | null;
  displayName?: string;
  folder?: string;
  trustState?: 'trusted' | 'blocked' | 'unknown';
}

interface VaultGrantRecord {
  id: string;
  vaultFileId: string;
  recipientUsername: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  signature: string;
  createdAt: number;
}

interface GrantPayload {
  recipientUsername: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  signature: string;
}

interface ShareReadiness {
  username: string;
  workspaceApproved: boolean;
  preKeysAvailable: boolean;
  availablePreKeys: number;
  error?: string;
}

interface StorageSummary {
  usedBytes: number;
  quotaBytes: number;
  availableBytes: number;
}

const ALL_FOLDERS = '__all__';
const ROOT_FOLDER = 'Vault';
const CHUNK_UPLOAD_RETRIES = 3;

function normalizeFolderName(value: string) {
  const normalized = value.trim().replace(/\s+/g, ' ');
  return normalized || ROOT_FOLDER;
}

function getFolderName(metadata: VaultMetadata | null) {
  return normalizeFolderName(metadata?.folder || ROOT_FOLDER);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const MyVaultPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const { preferences } = useUserPreferences();
  const [searchParams] = useSearchParams();
  const [files, setFiles] = useState<VaultFileView[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadLimitBytes, setUploadLimitBytes] = useState(DEFAULT_UPLOAD_FILE_LIMIT_BYTES);
  const [uploadLimitNote, setUploadLimitNote] = useState('');
  const [storageSummary, setStorageSummary] = useState<StorageSummary | null>(null);
  const [uploadFolder, setUploadFolder] = useState(ROOT_FOLDER);
  const [activeFolder, setActiveFolder] = useState(ALL_FOLDERS);
  const [showTrash, setShowTrash] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [shareTargets, setShareTargets] = useState<Record<string, string>>({});
  const [grantsByFile, setGrantsByFile] = useState<Record<string, VaultGrantRecord[]>>({});
  const [trustStatuses, setTrustStatuses] = useState<Record<string, TrustStatus>>({});
  const [expectedFingerprints, setExpectedFingerprints] = useState<Record<string, string>>({});
  const [readinessByUser, setReadinessByUser] = useState<Record<string, ShareReadiness>>({});
  const [readinessLoading, setReadinessLoading] = useState<string | null>(null);
  const [activeFileId, setActiveFileId] = useState<string | null>(null);
  const [detailFileId, setDetailFileId] = useState<string | null>(null);
  const [metadataNameDraft, setMetadataNameDraft] = useState('');
  const [metadataFolderDraft, setMetadataFolderDraft] = useState(ROOT_FOLDER);

  useEffect(() => {
    const query = searchParams.get('search') || '';
    setSearchQuery(query);
  }, [searchParams]);

  useEffect(() => {
    fetchUploadLimits()
      .then((limits) => {
        setUploadLimitBytes(limits.uploadFileLimitBytes);
        setUploadLimitNote(limits.note);
      })
      .catch(() => {
        setUploadLimitBytes(DEFAULT_UPLOAD_FILE_LIMIT_BYTES);
      });
  }, []);

  const decryptVaultRecord = useCallback(async (file: VaultFileRecord): Promise<VaultFileView> => {
    if (!user?.kek) return { ...file, metadata: null };

    try {
      const fileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv);
      const metadataText = await decryptFileData(fileKey, file.encryptedMetadata, file.metadataIv);
      const metadata = JSON.parse(metadataText) as VaultMetadata;
      return {
        ...file,
        metadata,
        displayName: metadata.name,
        folder: getFolderName(metadata)
      };
    } catch {
      return { ...file, metadata: null };
    }
  }, [user?.kek]);

  const fetchVaultGrants = useCallback(async (fileId: string): Promise<VaultGrantRecord[]> => {
    if (!user) return [];

    const res = await fetch(apiUrl(`/vault-files/${fileId}/grants`), { headers: authHeaders(user.token) });
    const data = await res.json() as { grants: VaultGrantRecord[]; error?: string };
    if (!res.ok) throw new Error(data.error || 'Unable to load sharing grants.');
    return data.grants;
  }, [user]);

  const loadStorageSummary = useCallback(async () => {
    if (!user) return;

    try {
      const res = await fetch(apiUrl('/storage-summary'), { headers: authHeaders(user.token) });
      const data = await res.json() as StorageSummary & { error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to load storage summary.');
      setStorageSummary({
        usedBytes: Number(data.usedBytes || 0),
        quotaBytes: Number(data.quotaBytes || 0),
        availableBytes: Number(data.availableBytes || 0)
      });
    } catch {
      setStorageSummary(null);
    }
  }, [user]);

  const loadVaultFiles = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const res = await fetch(apiUrl(showTrash ? '/vault-files?trash=true' : '/vault-files'), { headers: authHeaders(user.token) });
      const data = await res.json() as { files: VaultFileRecord[]; error?: string };
      if (!res.ok) throw new Error(data.error || 'Unable to load vault files.');

      const decryptedFiles = await Promise.all(data.files.map(decryptVaultRecord));
      setFiles(decryptedFiles);
      if (showTrash) {
        setGrantsByFile({});
      } else {
        const grantEntries = await Promise.all(data.files.map(async (file) => [file.id, await fetchVaultGrants(file.id)] as const));
        setGrantsByFile(Object.fromEntries(grantEntries));
      }
      await loadStorageSummary();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load vault files.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [decryptVaultRecord, fetchVaultGrants, loadStorageSummary, showToast, showTrash, user]);

  useEffect(() => {
    loadVaultFiles();
  }, [loadVaultFiles]);

  const loadUsers = useCallback(async () => {
    if (!user) return;

    try {
      const res = await fetch(apiUrl('/users'), { headers: authHeaders(user.token) });
      const data = await res.json() as DirectoryUser[];
      if (!res.ok) throw new Error('Unable to load identity directory.');
      const otherUsers = data.filter((entry) => entry.username !== user.username);
      setUsers(otherUsers);
      const statuses = await Promise.all(otherUsers.map(async (identity) => [identity.username, await getTrustStatus(user.username, identity)] as const));
      setTrustStatuses(Object.fromEntries(statuses));
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load identity directory.'), 'error');
    }
  }, [showToast, user]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const folders = useMemo(() => {
    const names = new Set<string>();
    for (const file of files) {
      names.add(getFolderName(file.metadata));
    }
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [files]);

  const filteredFiles = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return files.filter((file) => {
      const folderName = getFolderName(file.metadata);
      if (activeFolder !== ALL_FOLDERS && folderName !== activeFolder) return false;

      const searchText = [
        file.metadata?.name || '',
        file.metadata?.type || '',
        folderName,
        String(file.metadata?.size || file.fileSize)
      ].join(' ').toLowerCase();

      return !query || searchText.includes(query);
    });
  }, [activeFolder, files, searchQuery]);

  const detailFile = files.find((file) => file.id === detailFileId) || null;

  useEffect(() => {
    if (!detailFile) {
      setMetadataNameDraft('');
      setMetadataFolderDraft(ROOT_FOLDER);
      return;
    }

    setMetadataNameDraft(detailFile.metadata?.name || '');
    setMetadataFolderDraft(getFolderName(detailFile.metadata));
  }, [detailFile]);

  useEffect(() => {
    if (activeFolder !== ALL_FOLDERS && !folders.includes(activeFolder)) {
      setActiveFolder(ALL_FOLDERS);
    }
  }, [activeFolder, folders]);

  const handleUpload = async () => {
    if (!user?.kek || !selectedFile) {
      showToast('Select a file first.', 'error');
      return;
    }
    if (selectedFile.size <= 0) {
      showToast('Empty files are not supported yet.', 'error');
      return;
    }

    const estimatedEncryptedSize = estimateChunkedEncryptedSize(selectedFile.size);
    if (estimatedEncryptedSize > uploadLimitBytes) {
      showToast(
        `This file is ${formatBytes(selectedFile.size)} before encryption and about ${formatBytes(estimatedEncryptedSize)} after encryption. Current encrypted upload limit is ${formatBytes(uploadLimitBytes)}.`,
        'error'
      );
      return;
    }
    if (storageSummary?.quotaBytes && estimatedEncryptedSize > storageSummary.availableBytes) {
      showToast(
        `This upload needs about ${formatBytes(estimatedEncryptedSize)}, but your available encrypted storage is ${formatBytes(storageSummary.availableBytes)}.`,
        'error'
      );
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    let uploadSessionId = '';
    try {
      const fileKey = await generateFileKey();
      const metadata: VaultMetadata = {
        name: selectedFile.name,
        type: selectedFile.type || 'application/octet-stream',
        size: selectedFile.size,
        uploadedAt: Date.now(),
        folder: normalizeFolderName(uploadFolder)
      };
      const encryptedMetadata = await encryptFileData(fileKey, JSON.stringify(metadata));
      const wrapped = await wrapFileKeyForOwner(user.kek, fileKey);

      const expectedChunks = Math.ceil(selectedFile.size / FILE_CHUNK_SIZE_BYTES);
      const sessionRes = await fetch(apiUrl('/vault-file-upload-sessions'), {
        method: 'POST',
        headers: {
          ...authHeaders(user.token),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          encryptedMetadata: encryptedMetadata.ciphertext,
          metadataIv: encryptedMetadata.iv,
          wrappedFileKey: wrapped.wrappedFileKey,
          wrappedFileKeyIv: wrapped.wrappedFileKeyIv,
          expectedChunks,
          expectedSize: estimatedEncryptedSize
        })
      });
      const sessionData = await sessionRes.json() as { uploadSessionId?: string; error?: string };
      if (!sessionRes.ok || !sessionData.uploadSessionId) {
        throw new Error(sessionData.error || 'Unable to start encrypted upload session.');
      }
      uploadSessionId = sessionData.uploadSessionId;

      for (let index = 0; index < expectedChunks; index += 1) {
        const offset = index * FILE_CHUNK_SIZE_BYTES;
        const encryptedChunk = await encryptFileChunk(fileKey, selectedFile, offset);
        let uploaded = false;
        let lastError = '';

        for (let attempt = 1; attempt <= CHUNK_UPLOAD_RETRIES; attempt += 1) {
          const formData = new FormData();
          formData.append('chunk', encryptedChunk, `${index}.chunk`);

          try {
            const chunkRes = await fetch(apiUrl(`/vault-file-upload-sessions/${uploadSessionId}/chunks/${index}`), {
              method: 'POST',
              headers: authHeaders(user.token),
              body: formData
            });
            const chunkData = await chunkRes.json() as { error?: string };
            if (!chunkRes.ok) throw new Error(chunkData.error || `Unable to upload encrypted chunk ${index + 1}.`);
            uploaded = true;
            break;
          } catch (err: unknown) {
            lastError = getErrorMessage(err, `Unable to upload encrypted chunk ${index + 1}.`);
            if (attempt < CHUNK_UPLOAD_RETRIES) await sleep(300 * attempt);
          }
        }

        if (!uploaded) throw new Error(lastError || `Unable to upload encrypted chunk ${index + 1}.`);
        setUploadProgress(Math.round(((index + 1) / expectedChunks) * 100));
      }

      const completeRes = await fetch(apiUrl(`/vault-file-upload-sessions/${uploadSessionId}/complete`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const completeData = await completeRes.json() as { error?: string };
      if (!completeRes.ok) throw new Error(completeData.error || 'Unable to finalize encrypted upload.');
      uploadSessionId = '';

      showToast('Encrypted file stored in your vault.', 'success');
      setSelectedFile(null);
      setActiveFolder(metadata.folder || ROOT_FOLDER);
      await loadVaultFiles();
    } catch (err: unknown) {
      if (uploadSessionId) {
        fetch(apiUrl(`/vault-file-upload-sessions/${uploadSessionId}`), {
          method: 'DELETE',
          headers: authHeaders(user.token)
        }).catch(() => undefined);
      }
      showToast(getErrorMessage(err, 'Unable to upload encrypted file.'), 'error');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleDownload = async (file: VaultFileView) => {
    if (!user?.kek) return;

    setActiveFileId(file.id);
    try {
      const fileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv);
      const blobRes = await fetch(apiUrl(`/vault-files/${file.id}/download`), { headers: authHeaders(user.token) });
      if (!blobRes.ok) throw new Error('Encrypted vault blob unavailable.');

      const encryptedBlob = await blobRes.blob();
      const plainBlob = await decryptFileChunked(fileKey, encryptedBlob);
      const url = URL.createObjectURL(plainBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.metadata?.name || 'vault-file';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      showToast('Vault file decrypted.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to decrypt vault file.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const handleDelete = async (file: VaultFileView) => {
    if (!user) return;
    if (preferences.confirmDestructiveActions) {
      const confirmed = window.confirm(`Move "${file.metadata?.name || 'vault file'}" to Trash?`);
      if (!confirmed) return;
    }

    setActiveFileId(file.id);
    try {
      const res = await fetch(apiUrl(`/vault-files/${file.id}`), {
        method: 'DELETE',
        headers: authHeaders(user.token)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to delete vault file.');

      setFiles((current) => current.filter((item) => item.id !== file.id));
      setDetailFileId(null);
      showToast('Vault file moved to Trash.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to delete vault file.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const handleRestore = async (file: VaultFileView) => {
    if (!user) return;

    setActiveFileId(file.id);
    try {
      const res = await fetch(apiUrl(`/vault-files/${file.id}/restore`), {
        method: 'POST',
        headers: authHeaders(user.token)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to restore vault file.');

      setFiles((current) => current.filter((item) => item.id !== file.id));
      setDetailFileId(null);
      showToast('Vault file restored.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to restore vault file.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const handlePermanentDelete = async (file: VaultFileView) => {
    if (!user) return;
    if (preferences.confirmDestructiveActions) {
      const confirmed = window.confirm(`Permanently delete "${file.metadata?.name || 'vault file'}"? This cannot be undone.`);
      if (!confirmed) return;
    }

    setActiveFileId(file.id);
    try {
      const res = await fetch(apiUrl(`/vault-files/${file.id}/permanent`), {
        method: 'DELETE',
        headers: authHeaders(user.token)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to permanently delete vault file.');

      setFiles((current) => current.filter((item) => item.id !== file.id));
      setDetailFileId(null);
      await loadStorageSummary();
      showToast('Vault file permanently deleted.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to permanently delete vault file.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const handleUpdateMetadata = async (file: VaultFileView) => {
    if (!user?.kek || !user.privateKeyECDSA || !file.metadata) {
      showToast('Encrypted metadata is unavailable for this file.', 'error');
      return;
    }

    const nextName = metadataNameDraft.trim();
    if (!nextName) {
      showToast('File name cannot be empty.', 'error');
      return;
    }

    const nextFolder = normalizeFolderName(metadataFolderDraft);
    const nextMetadata: VaultMetadata = {
      ...file.metadata,
      name: nextName,
      folder: nextFolder
    };

    setActiveFileId(file.id);
    try {
      const fileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv, ["encrypt", "decrypt"]);
      const encryptedMetadata = await encryptFileData(fileKey, JSON.stringify(nextMetadata));
      const currentGrants = grantsByFile[file.id] || await fetchVaultGrants(file.id);
      const grantSignatures = await Promise.all(currentGrants.map(async (grant) => ({
        grantId: grant.id,
        signature: await signPayload(user.privateKeyECDSA!, `${file.id}:${grant.wrappedFileKey}:${encryptedMetadata.iv}`)
      })));

      const res = await fetch(apiUrl(`/vault-files/${file.id}/metadata`), {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify({
          encryptedMetadata: encryptedMetadata.ciphertext,
          metadataIv: encryptedMetadata.iv,
          grantSignatures
        })
      });
      const data = await res.json() as { file?: VaultFileRecord; error?: string };
      if (!res.ok || !data.file) throw new Error(data.error || 'Unable to update encrypted metadata.');

      const updatedFile = await decryptVaultRecord(data.file);
      const refreshedGrants = await fetchVaultGrants(file.id);
      setFiles((current) => current.map((entry) => (entry.id === file.id ? updatedFile : entry)));
      setGrantsByFile((current) => ({ ...current, [file.id]: refreshedGrants }));
      setUploadFolder(nextFolder);
      showToast('Encrypted file details updated.', 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to update encrypted metadata.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const createGrantPayload = useCallback(async (
    vaultFileId: string,
    metadataIv: string,
    fileKey: CryptoKey,
    recipientUsername: string
  ): Promise<GrantPayload> => {
    if (!user?.privateKeyECDH || !user.privateKeyECDSA) {
      throw new Error('Identity keys are locked.');
    }

    const targetIdentity = users.find((entry) => entry.username === recipientUsername);
    if (!targetIdentity) throw new Error(`Recipient ${recipientUsername} is unavailable.`);

    const trustStatus = await getTrustStatus(user.username, targetIdentity);
    if (!trustStatus.trusted) {
      throw new Error(trustStatus.changed
        ? `${recipientUsername}'s identity fingerprint changed. Verify it before sharing.`
        : `Trust ${recipientUsername}'s identity fingerprint before sharing.`);
    }

    const preKeyRes = await fetch(apiUrl(`/prekey/${recipientUsername}`), { headers: authHeaders(user.token) });
    const preKeyJson = await preKeyRes.json();
    if (!preKeyRes.ok) throw new Error(preKeyJson.error || 'Recipient has no available pre-keys.');

    const recipientPreKey = preKeyJson.preKey.publicKeyHex;
    const { wrappedFileKey, ephemeralPublicKey } = await encryptFileKeyWithX3DH(
      fileKey,
      recipientPreKey,
      preKeyJson.identityPublicKeyECDH,
      user.privateKeyECDH
    );
    const signaturePayload = `${vaultFileId}:${wrappedFileKey}:${metadataIv}`;
    const signature = await signPayload(user.privateKeyECDSA, signaturePayload);

    return {
      recipientUsername,
      wrappedFileKey,
      ephemeralPublicKey,
      usedPreKey: recipientPreKey,
      signature
    };
  }, [user, users]);

  const handleShare = async (file: VaultFileView) => {
    if (!user?.kek) return;

    const recipientUsername = shareTargets[file.id];
    if (!recipientUsername) {
      showToast('Choose a recipient first.', 'error');
      return;
    }

    setActiveFileId(file.id);
    try {
      const fileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv);
      const grantPayload = await createGrantPayload(file.id, file.metadataIv, fileKey, recipientUsername);

      const res = await fetch(apiUrl(`/vault-files/${file.id}/share`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(user.token)
        },
        body: JSON.stringify(grantPayload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Unable to share vault file.');

      const grants = await fetchVaultGrants(file.id);
      setGrantsByFile((current) => ({ ...current, [file.id]: grants }));
      setShareTargets((current) => ({ ...current, [file.id]: '' }));
      showToast(`Shared with ${recipientUsername}.`, 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to share vault file.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const handleRevokeGrant = async (file: VaultFileView, grant: VaultGrantRecord) => {
    if (!user?.kek) return;

    if (preferences.confirmDestructiveActions) {
      const confirmed = window.confirm(`Revoke ${grant.recipientUsername}'s access and rotate the file key?`);
      if (!confirmed) return;
    }

    setActiveFileId(file.id);
    try {
      const currentGrants = grantsByFile[file.id] || await fetchVaultGrants(file.id);
      const remainingGrants = currentGrants.filter((entry) => entry.id !== grant.id);
      const oldFileKey = await unwrapFileKeyForOwner(user.kek, file.wrappedFileKey, file.wrappedFileKeyIv);

      const blobRes = await fetch(apiUrl(`/vault-files/${file.id}/download`), { headers: authHeaders(user.token) });
      if (!blobRes.ok) throw new Error('Encrypted vault blob unavailable.');

      const encryptedBlob = await blobRes.blob();
      const plainBlob = await decryptFileChunked(oldFileKey, encryptedBlob);
      const newFileKey = await generateFileKey();
      const metadata: VaultMetadata = file.metadata || {
        name: 'vault-file',
        type: 'application/octet-stream',
        size: plainBlob.size,
        uploadedAt: file.createdAt
      };
      const plainFile = new File([plainBlob], metadata.name, {
        type: metadata.type || 'application/octet-stream',
        lastModified: metadata.uploadedAt
      });
      const { encryptedBlob: rotatedBlob } = await encryptFileChunked(newFileKey, plainFile);
      const encryptedMetadata = await encryptFileData(newFileKey, JSON.stringify(metadata));
      const wrapped = await wrapFileKeyForOwner(user.kek, newFileKey);
      const replacementGrantPayloads: GrantPayload[] = [];

      for (const remainingGrant of remainingGrants) {
        replacementGrantPayloads.push(await createGrantPayload(
          file.id,
          encryptedMetadata.iv,
          newFileKey,
          remainingGrant.recipientUsername
        ));
      }

      const formData = new FormData();
      formData.append('encryptedMetadata', encryptedMetadata.ciphertext);
      formData.append('metadataIv', encryptedMetadata.iv);
      formData.append('wrappedFileKey', wrapped.wrappedFileKey);
      formData.append('wrappedFileKeyIv', wrapped.wrappedFileKeyIv);
      formData.append('grants', JSON.stringify(replacementGrantPayloads));
      formData.append('fileBlob', rotatedBlob, `${metadata.name}.rotated.vault`);

      const rotateRes = await fetch(apiUrl(`/vault-files/${file.id}/rotate`), {
        method: 'POST',
        headers: authHeaders(user.token),
        body: formData
      });
      const rotateData = await rotateRes.json();
      if (!rotateRes.ok) throw new Error(rotateData.error || 'Unable to rotate vault file.');

      await loadVaultFiles();
      showToast(`Revoked ${grant.recipientUsername} and rotated the file key.`, 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to revoke access.'), 'error');
    } finally {
      setActiveFileId(null);
    }
  };

  const selectedShareIdentity = (fileId: string) => users.find((entry) => entry.username === shareTargets[fileId]);

  const loadShareReadiness = useCallback(async (username: string) => {
    if (!user || !username) return;

    setReadinessLoading(username);
    try {
      const res = await fetch(apiUrl(`/share-readiness/${username}`), { headers: authHeaders(user.token) });
      const data = await res.json() as ShareReadiness & { error?: string };
      setReadinessByUser((current) => ({
        ...current,
        [username]: res.ok
          ? data
          : {
              username,
              workspaceApproved: false,
              preKeysAvailable: false,
              availablePreKeys: 0,
              error: data.error || 'Recipient is not ready for sharing.'
            }
      }));
    } catch (err: unknown) {
      setReadinessByUser((current) => ({
        ...current,
        [username]: {
          username,
          workspaceApproved: false,
          preKeysAvailable: false,
          availablePreKeys: 0,
          error: getErrorMessage(err, 'Unable to check recipient readiness.')
        }
      }));
    } finally {
      setReadinessLoading(null);
    }
  }, [user]);

  const selectedShareBlockReason = (file: VaultFileView) => {
    const selectedIdentity = selectedShareIdentity(file.id);
    if (!selectedIdentity) return 'Choose an active workspace member.';
    const readiness = readinessByUser[selectedIdentity.username];
    if (readinessLoading === selectedIdentity.username || !readiness) return 'Checking recipient readiness...';
    if (!readiness.workspaceApproved) return readiness.error || 'Recipient is not active in a shared workspace.';
    const status = trustStatuses[selectedIdentity.username];
    if (!status?.trusted) {
      return status?.changed
        ? 'Fingerprint changed. Re-verify this contact before sharing.'
        : 'Fingerprint not trusted. Paste the verified fingerprint before sharing.';
    }
    if (!readiness.preKeysAvailable) return 'Recipient needs to refill one-time pre-keys before new shares can be created.';
    return '';
  };

  const handleTrustIdentity = async (identity: DirectoryUser, status: TrustStatus) => {
    if (!user) return;
    const expectedFingerprint = expectedFingerprints[identity.username] || '';
    if (!fingerprintMatches(status.fingerprint, expectedFingerprint)) {
      showToast('Fingerprint does not match this identity.', 'error');
      return;
    }

    const record = await trustIdentity(user.username, identity);
    setTrustStatuses((current) => ({
      ...current,
      [identity.username]: {
        fingerprint: record.fingerprint,
        trusted: true,
        changed: false,
        record
      }
    }));
    setExpectedFingerprints((current) => ({ ...current, [identity.username]: '' }));
    showToast(`${identity.username} trusted for vault sharing.`, 'success');
  };

  const handleForgetIdentity = (identity: DirectoryUser) => {
    if (!user) return;

    forgetTrustedIdentity(user.username, identity.username);
    setTrustStatuses((current) => ({
      ...current,
      [identity.username]: {
        fingerprint: current[identity.username]?.fingerprint || '',
        trusted: false,
        changed: false
      }
    }));
    showToast(`${identity.username} removed from trusted identities.`, 'success');
  };

  const metadataDirty = !!detailFile?.metadata && (
    metadataNameDraft.trim() !== detailFile.metadata.name ||
    normalizeFolderName(metadataFolderDraft) !== getFolderName(detailFile.metadata)
  );
  const selectedEncryptedSizeEstimate = selectedFile ? estimateChunkedEncryptedSize(selectedFile.size) : 0;
  const selectedFileTooLarge = selectedFile ? selectedEncryptedSizeEstimate > uploadLimitBytes : false;
  const storageQuotaEnabled = !!storageSummary && storageSummary.quotaBytes > 0;
  const storageUsagePercent = storageQuotaEnabled
    ? Math.min(100, Math.round((storageSummary.usedBytes / storageSummary.quotaBytes) * 100))
    : 0;
  const selectedFileExceedsQuota = !!selectedFile && storageQuotaEnabled && selectedEncryptedSizeEstimate > storageSummary.availableBytes;
  const uploadDisabled = !selectedFile || selectedFileTooLarge || selectedFileExceedsQuota || loading;
  const tableHeaderClass = preferences.denseFileTables ? 'px-5 py-3 font-bold' : 'px-5 py-4 font-bold';
  const tableCellClass = preferences.denseFileTables ? 'px-5 py-2.5' : 'px-5 py-4';
  const fileIconClass = preferences.denseFileTables ? 'w-8 h-8' : 'w-9 h-9';

  return (
    <div className="max-w-7xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Files</h2>
          <p className="text-slate-400">Private drive storage with encrypted names, folders, content, and share grants.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search files..."
              className="w-72 bg-slate-900 border border-white/10 rounded-lg py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
          </div>
          <button
            onClick={loadVaultFiles}
            disabled={loading || uploading}
            className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
            title="Refresh vault"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <GlassCard className="p-5 mb-6">
        <div className="flex flex-col md:flex-row md:items-center gap-4">
          <div
            className="relative flex-1 border border-dashed border-white/10 rounded-xl p-6 hover:border-cyan-500/40 transition-colors bg-black/10"
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              setSelectedFile(event.dataTransfer.files?.[0] || null);
            }}
          >
            <input
              type="file"
              className="absolute inset-0 opacity-0 cursor-pointer"
              onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
              disabled={uploading}
            />
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 flex items-center justify-center border border-cyan-500/20">
                <UploadCloud className="w-6 h-6 text-cyan-400" />
              </div>
              <div className="min-w-0">
                <p className="text-white font-medium truncate">{selectedFile ? selectedFile.name : 'Drop a file here or click to choose'}</p>
                <p className={`text-xs mt-1 ${selectedFileTooLarge ? 'text-red-300' : 'text-slate-500'}`}>
                  {selectedFile
                    ? `${formatBytes(selectedFile.size)} selected · encrypted upload about ${formatBytes(selectedEncryptedSizeEstimate)}`
                    : `Content, name, type, and folder are encrypted before upload · limit ${formatBytes(uploadLimitBytes)}`}
                </p>
                {selectedFileTooLarge && (
                  <p className="text-xs text-red-300 mt-1">
                    Current encrypted upload limit is {formatBytes(uploadLimitBytes)}. Larger deployments need object storage and quota policy.
                  </p>
                )}
                {uploading && (
                  <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-cyan-400 transition-all"
                      style={{ width: `${uploadProgress}%` }}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>
          <div className="relative md:w-56">
            <FolderPlus className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              value={uploadFolder}
              onChange={(event) => setUploadFolder(event.target.value)}
              placeholder="Folder"
              disabled={uploading}
              className="w-full bg-black/30 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
            />
          </div>
          <ActionButton onClick={handleUpload} loading={uploading} disabled={uploadDisabled}>
            <Lock className="w-4 h-4" /> {uploading ? `${uploadProgress}%` : 'Upload'}
          </ActionButton>
        </div>
        {preferences.securityHints && uploadLimitNote && (
          <p className="mt-3 text-xs text-slate-500">{uploadLimitNote}</p>
        )}
        {storageSummary && (
          <div className="mt-4 rounded-xl border border-white/10 bg-black/20 p-4">
            <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <HardDrive className="h-4 w-4 text-cyan-400" />
                <span>
                  {formatBytes(storageSummary.usedBytes)} used
                  {storageQuotaEnabled ? ` of ${formatBytes(storageSummary.quotaBytes)}` : ' · quota disabled'}
                </span>
              </div>
              {selectedFileExceedsQuota && (
                <span className="text-xs text-red-300">
                  Selected file exceeds available encrypted storage.
                </span>
              )}
            </div>
            {storageQuotaEnabled && (
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
                <div
                  className={`h-full rounded-full transition-all ${storageUsagePercent > 90 ? 'bg-red-400' : storageUsagePercent > 75 ? 'bg-amber-400' : 'bg-cyan-400'}`}
                  style={{ width: `${storageUsagePercent}%` }}
                />
              </div>
            )}
          </div>
        )}
      </GlassCard>

      <div className="mb-6 flex flex-wrap items-center gap-2">
        <button
          onClick={() => {
            setShowTrash(false);
            setActiveFolder(ALL_FOLDERS);
          }}
          className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs transition-colors ${
            !showTrash && activeFolder === ALL_FOLDERS
              ? 'border-cyan-500/30 bg-cyan-500/15 text-cyan-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:text-white'
          }`}
        >
          <Folder className="w-4 h-4" /> All Files
          <span className="text-[10px] opacity-70">{files.length}</span>
        </button>
        <button
          onClick={() => {
            setShowTrash(true);
            setActiveFolder(ALL_FOLDERS);
          }}
          className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs transition-colors ${
            showTrash
              ? 'border-red-500/30 bg-red-500/15 text-red-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:text-white'
          }`}
        >
          <Trash2 className="w-4 h-4" /> Trash
        </button>
        {folders.map((folderName) => (
          <button
            key={folderName}
            disabled={showTrash}
            onClick={() => {
              setShowTrash(false);
              setActiveFolder(folderName);
              setUploadFolder(folderName);
            }}
            className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs transition-colors ${
              !showTrash && activeFolder === folderName
                ? 'border-cyan-500/30 bg-cyan-500/15 text-cyan-200'
                : 'border-white/10 bg-white/5 text-slate-400 hover:text-white disabled:opacity-40 disabled:hover:text-slate-400'
            }`}
          >
            <Folder className="w-4 h-4" />
            {folderName}
            <span className="text-[10px] opacity-70">{files.filter((file) => getFolderName(file.metadata) === folderName).length}</span>
          </button>
        ))}
      </div>

      <GlassCard className="overflow-hidden">
        {loading ? (
          <GlassCard className="p-12 text-center">
            <Activity className="w-10 h-10 text-cyan-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-400 text-sm">Opening encrypted vault...</p>
          </GlassCard>
        ) : files.length === 0 ? (
          <GlassCard className="p-12 text-center text-slate-500">
            {showTrash ? 'Trash is empty.' : 'Your encrypted vault is empty.'}
          </GlassCard>
        ) : filteredFiles.length === 0 ? (
          <GlassCard className="p-12 text-center text-slate-500">
            No encrypted files match this view.
          </GlassCard>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/5 text-[10px] uppercase tracking-widest text-slate-500">
                  <th className={tableHeaderClass}>Name</th>
                  <th className={tableHeaderClass}>Folder</th>
                  <th className={tableHeaderClass}>Size</th>
                  <th className={tableHeaderClass}>{showTrash ? 'Deleted' : 'Created'}</th>
                  <th className={tableHeaderClass}>Shared</th>
                  <th className={`${tableHeaderClass} text-right`}>Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredFiles.map((file) => {
                  const grants = grantsByFile[file.id] || [];
                  return (
                    <tr key={file.id} className="hover:bg-white/[0.03] transition-colors">
                      <td className={tableCellClass}>
                        <div className="flex items-center gap-3 min-w-0">
                          <div className={`${fileIconClass} rounded-lg bg-white/5 flex items-center justify-center shrink-0`}>
                            <FileIcon className="w-5 h-5 text-slate-400" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm text-white font-medium truncate">{file.metadata?.name || 'Encrypted metadata unavailable'}</p>
                            {preferences.securityHints && <p className="text-[10px] text-slate-500">Encrypted metadata · owner-only key wrap</p>}
                          </div>
                        </div>
                      </td>
                      <td className={`${tableCellClass} text-sm text-slate-300`}>{getFolderName(file.metadata)}</td>
                      <td className={`${tableCellClass} text-sm text-slate-400`}>{formatBytes(file.metadata?.size || file.fileSize)}</td>
                      <td className={`${tableCellClass} text-sm text-slate-400 whitespace-nowrap`}>
                        {new Date((showTrash && file.deletedAt) ? file.deletedAt : file.createdAt).toLocaleDateString()}
                      </td>
                      <td className={tableCellClass}>
                        <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold ${
                          grants.length > 0 ? 'border-cyan-500/20 bg-cyan-500/10 text-cyan-300' : 'border-white/10 bg-white/5 text-slate-500'
                        }`}>
                          {grants.length || file.sharedWithCount || 0} users
                        </span>
                      </td>
                      <td className={tableCellClass}>
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => setDetailFileId(file.id)}
                            className="p-2 bg-white/5 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-400 rounded-lg border border-white/10 hover:border-cyan-500/20 transition-colors"
                            title="Open details"
                          >
                            <Info className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDownload(file)}
                            disabled={activeFileId !== null || showTrash}
                            className="p-2 bg-white/5 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-400 rounded-lg border border-white/10 hover:border-emerald-500/20 transition-colors disabled:opacity-50"
                            title="Decrypt and download"
                          >
                            {activeFileId === file.id ? <Activity className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
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

      {detailFile && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-sm" onClick={() => setDetailFileId(null)}>
          <aside className="h-full w-full max-w-md border-l border-white/10 bg-slate-950 p-6 overflow-y-auto" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-start justify-between gap-4 mb-6">
              <div className="min-w-0">
                <h3 className="text-xl font-bold text-white truncate">{detailFile.metadata?.name || 'Encrypted file'}</h3>
                <p className="text-xs text-slate-500 mt-1">{formatBytes(detailFile.metadata?.size || detailFile.fileSize)} · {getFolderName(detailFile.metadata)}</p>
              </div>
              <button onClick={() => setDetailFileId(null)} className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white hover:bg-white/10">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-5">
              <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Created</p>
                <p className="text-sm text-slate-300 mt-2">{new Date(detailFile.createdAt).toLocaleString()}</p>
              </div>

              {!showTrash && (
                <div className="rounded-xl border border-white/5 bg-black/20 p-4 space-y-3">
                  <h4 className="text-white font-semibold flex items-center gap-2">
                    <FileIcon className="w-4 h-4 text-cyan-400" /> File Details
                  </h4>
                  {preferences.securityHints && (
                    <p className="text-xs text-slate-500">
                      Name and folder are re-encrypted in your browser before they are saved.
                    </p>
                  )}
                  <label className="block">
                    <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Name</span>
                    <input
                      value={metadataNameDraft}
                      onChange={(event) => setMetadataNameDraft(event.target.value)}
                      disabled={activeFileId !== null || !detailFile.metadata}
                      className="mt-2 w-full bg-black/40 border border-white/10 rounded-xl py-3 px-3 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
                    />
                  </label>
                  <label className="block">
                    <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Folder</span>
                    <input
                      value={metadataFolderDraft}
                      onChange={(event) => setMetadataFolderDraft(event.target.value)}
                      disabled={activeFileId !== null || !detailFile.metadata}
                      className="mt-2 w-full bg-black/40 border border-white/10 rounded-xl py-3 px-3 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
                    />
                  </label>
                  <ActionButton
                    variant="secondary"
                    onClick={() => handleUpdateMetadata(detailFile)}
                    loading={activeFileId === detailFile.id}
                    disabled={activeFileId !== null || !metadataDirty}
                    className="w-full"
                  >
                    <Save className="w-4 h-4" /> Save Encrypted Details
                  </ActionButton>
                </div>
              )}

              {showTrash && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-100">
                  This encrypted file is in Trash. Restore it before downloading or sharing, or permanently delete it to remove the stored blob.
                </div>
              )}

              {!showTrash && (
              <div className="rounded-xl border border-white/5 bg-black/20 p-4 space-y-3">
                <h4 className="text-white font-semibold flex items-center gap-2">
                  <Share2 className="w-4 h-4 text-cyan-400" /> Share Access
                </h4>
                {users.length === 0 ? (
                  <p className="text-sm text-slate-500">No approved workspace members are available. Invite and approve members in Workspace Admin first.</p>
                ) : (
                  <>
                    {preferences.securityHints && (
                      <p className="text-xs text-slate-500">
                        Sharing requires all three checks: an approved shared workspace, a trusted fingerprint, and available recipient pre-keys.
                      </p>
                    )}
                    <select
                      value={shareTargets[detailFile.id] || ''}
                      onChange={(event) => {
                        const username = event.target.value;
                        setShareTargets((current) => ({ ...current, [detailFile.id]: username }));
                        if (username) {
                          loadShareReadiness(username);
                        }
                      }}
                      disabled={activeFileId !== null}
                      className="w-full bg-black/40 border border-white/10 rounded-xl py-3 px-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
                    >
                      <option value="">Choose recipient...</option>
                      {users.map((entry) => (
                        <option key={entry.username} value={entry.username}>{entry.username}</option>
                      ))}
                    </select>
                    {selectedShareIdentity(detailFile.id) && (() => {
                      const selectedIdentity = selectedShareIdentity(detailFile.id)!;
                      const selectedTrust = trustStatuses[selectedIdentity.username];
                      const readiness = readinessByUser[selectedIdentity.username];
                      return (
                        <div className="grid grid-cols-3 gap-2">
                          <span className={`rounded-xl border px-3 py-2 text-[10px] font-bold text-center ${
                            readiness?.workspaceApproved
                              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                              : 'border-amber-500/20 bg-amber-500/10 text-amber-300'
                          }`}>
                            Workspace
                          </span>
                          <span className={`rounded-xl border px-3 py-2 text-[10px] font-bold text-center ${
                            selectedTrust?.trusted
                              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                              : 'border-amber-500/20 bg-amber-500/10 text-amber-300'
                          }`}>
                            Fingerprint
                          </span>
                          <span className={`rounded-xl border px-3 py-2 text-[10px] font-bold text-center ${
                            readiness?.preKeysAvailable
                              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                              : 'border-amber-500/20 bg-amber-500/10 text-amber-300'
                          }`}>
                            {readinessLoading === selectedIdentity.username ? 'Checking' : `${readiness?.availablePreKeys ?? 0} Pre-keys`}
                          </span>
                        </div>
                      );
                    })()}
                    {selectedShareIdentity(detailFile.id) && trustStatuses[selectedShareIdentity(detailFile.id)!.username] && (
                      <div className={`rounded-xl border p-4 ${
                        trustStatuses[selectedShareIdentity(detailFile.id)!.username].trusted
                          ? 'border-emerald-500/20 bg-emerald-500/10'
                          : trustStatuses[selectedShareIdentity(detailFile.id)!.username].changed
                            ? 'border-red-500/20 bg-red-500/10'
                            : 'border-amber-500/20 bg-amber-500/10'
                      }`}>
                        {(() => {
                          const selectedIdentity = selectedShareIdentity(detailFile.id)!;
                          const selectedTrust = trustStatuses[selectedIdentity.username];
                          return (
                            <div className="space-y-3">
                              <p className="flex items-center gap-2 text-sm font-medium text-white">
                                {selectedTrust.trusted ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : selectedTrust.changed ? <ShieldAlert className="w-4 h-4 text-red-400" /> : <ShieldQuestion className="w-4 h-4 text-amber-400" />}
                                {selectedTrust.trusted ? 'Fingerprint trusted' : selectedTrust.changed ? 'Fingerprint changed' : 'Fingerprint verification required'}
                              </p>
                              <p className="font-mono text-xs text-slate-300 break-all">{formatFingerprint(selectedTrust.fingerprint)}</p>
                              {!selectedTrust.trusted && (
                                <input
                                  value={expectedFingerprints[selectedIdentity.username] || ''}
                                  onChange={(event) => setExpectedFingerprints((current) => ({
                                    ...current,
                                    [selectedIdentity.username]: event.target.value
                                  }))}
                                  placeholder="Paste verified fingerprint"
                                  className="w-full bg-black/30 border border-white/10 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
                                />
                              )}
                              <div className="flex gap-2">
                                {selectedTrust.trusted ? (
                                  <ActionButton variant="secondary" onClick={() => handleForgetIdentity(selectedIdentity)} className="text-xs flex-1">
                                    Forget Trust
                                  </ActionButton>
                                ) : (
                                  <ActionButton variant="secondary" onClick={() => handleTrustIdentity(selectedIdentity, selectedTrust)} className="text-xs flex-1">
                                    Trust Fingerprint
                                  </ActionButton>
                                )}
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    )}
                    {selectedShareBlockReason(detailFile) && (
                      <p className="text-xs text-amber-300">{selectedShareBlockReason(detailFile)}</p>
                    )}
                    <ActionButton
                      onClick={() => handleShare(detailFile)}
                      loading={activeFileId === detailFile.id}
                      disabled={activeFileId !== null || !!selectedShareBlockReason(detailFile)}
                      className="w-full"
                    >
                      <Share2 className="w-4 h-4" /> Share Encrypted Access
                    </ActionButton>
                  </>
                )}
              </div>
              )}

              {!showTrash && (
              <div className="rounded-xl border border-white/5 bg-black/20 p-4 space-y-3">
                <h4 className="text-white font-semibold">Current Access</h4>
                {(grantsByFile[detailFile.id] || []).length === 0 ? (
                  <p className="text-sm text-slate-500">This file is not shared.</p>
                ) : (
                  (grantsByFile[detailFile.id] || []).map((grant) => (
                    <button
                      key={grant.id}
                      onClick={() => handleRevokeGrant(detailFile, grant)}
                      disabled={activeFileId !== null}
                      className="w-full inline-flex items-center justify-between gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-100 hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-100 transition-colors disabled:opacity-50"
                      title="Revoke and rotate file key"
                    >
                      <span className="inline-flex items-center gap-2"><UserMinus className="w-3.5 h-3.5" /> {grant.recipientUsername}</span>
                      <span>Revoke</span>
                    </button>
                  ))
                )}
              </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                {showTrash ? (
                  <>
                    <ActionButton variant="secondary" onClick={() => handleRestore(detailFile)} disabled={activeFileId !== null}>
                      <RotateCcw className="w-4 h-4" /> Restore
                    </ActionButton>
                    <ActionButton
                      variant="secondary"
                      onClick={() => handlePermanentDelete(detailFile)}
                      disabled={activeFileId !== null}
                      className="text-red-300 border-red-400/20 hover:bg-red-400/10"
                    >
                      <Trash2 className="w-4 h-4" /> Delete Forever
                    </ActionButton>
                  </>
                ) : (
                  <>
                    <ActionButton variant="secondary" onClick={() => handleDownload(detailFile)} disabled={activeFileId !== null}>
                      <Download className="w-4 h-4" /> Download
                    </ActionButton>
                    <ActionButton
                      variant="secondary"
                      onClick={() => handleDelete(detailFile)}
                      disabled={activeFileId !== null}
                      className="text-red-300 border-red-400/20 hover:bg-red-400/10"
                    >
                      <Trash2 className="w-4 h-4" /> Move to Trash
                    </ActionButton>
                  </>
                )}
              </div>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
};
