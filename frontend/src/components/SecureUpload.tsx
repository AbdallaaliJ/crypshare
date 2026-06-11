import React, { useCallback, useState, useEffect } from 'react';
import { UploadCloud, Activity, User, ShieldCheck, ShieldQuestion, ShieldAlert } from 'lucide-react';
import { useToast } from './ui/useToast';
import { useAuth } from '../hooks/useAuth';
import { useLogContext } from '../hooks/useLogContext';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import type { DirectoryUser } from '../types/api';
import { getErrorMessage } from '../utils/errors';
import {
  formatFingerprint,
  forgetTrustedIdentity,
  fingerprintMatches,
  getTrustStatus,
  trustIdentity,
  type TrustStatus
} from '../utils/trust';
import { GlassCard } from './ui/GlassCard';
import { ActionButton } from './ui/ActionButton';
import {
  estimateChunkedEncryptedSize,
  generateFileKey,
  encryptFileChunked,
  encryptFileKeyWithX3DH,
  signPayload
} from '../utils/crypto';
import { DEFAULT_UPLOAD_FILE_LIMIT_BYTES, fetchUploadLimits, formatBytes } from '../utils/uploadLimits';

export const SecureUpload: React.FC = () => {
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [recipient, setRecipient] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadLimitBytes, setUploadLimitBytes] = useState(DEFAULT_UPLOAD_FILE_LIMIT_BYTES);
  const [loading, setLoading] = useState(false);
  const [trustStatuses, setTrustStatuses] = useState<Record<string, TrustStatus>>({});
  const [expectedFingerprints, setExpectedFingerprints] = useState<Record<string, string>>({});
  
  const { showToast } = useToast();
  const { user } = useAuth();
  const { addLog, clearLogs } = useLogContext();

  const loadUsers = useCallback(async () => {
    try {
      const r = await fetch(apiUrl('/users'), { headers: authHeaders(user?.token) });
      const data = await r.json() as DirectoryUser[];
      const otherUsers = data.filter((u) => u.username !== user?.username);
      setUsers(otherUsers);
      setRecipient((current) => current || otherUsers[0]?.username || '');
      if (user) {
        const statuses = await Promise.all(otherUsers.map(async (identity) => [identity.username, await getTrustStatus(user.username, identity)] as const));
        setTrustStatuses(Object.fromEntries(statuses));
      }
    } catch (e) {
      console.error(e);
      showToast('Failed to load directory', 'error');
    }
  }, [showToast, user]);

  useEffect(() => {
    if (user) {
      loadUsers();
    }
  }, [user, loadUsers]);

  useEffect(() => {
    fetchUploadLimits()
      .then((limits) => setUploadLimitBytes(limits.uploadFileLimitBytes))
      .catch(() => setUploadLimitBytes(DEFAULT_UPLOAD_FILE_LIMIT_BYTES));
  }, []);

  const handleSendSecureFile = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!recipient || !selectedFile || !user) {
      showToast('Please fill all required fields.', 'error');
      return;
    }

    const estimatedEncryptedSize = estimateChunkedEncryptedSize(selectedFile.size);
    if (estimatedEncryptedSize > uploadLimitBytes) {
      showToast(
        `This file becomes about ${formatBytes(estimatedEncryptedSize)} after encryption. Current single-upload limit is ${formatBytes(uploadLimitBytes)}.`,
        'error'
      );
      return;
    }

    try {
      setLoading(true);
      clearLogs();
      addLog(`Initializing dispatch protocol for target: ${recipient}...`);

      const targetUser = users.find((u) => u.username === recipient);
      if (!targetUser) return;
      const trustStatus = await getTrustStatus(user.username, targetUser);
      if (!trustStatus.trusted) {
        throw new Error(trustStatus.changed
          ? 'Recipient identity keys changed. Verify the new fingerprint before dispatch.'
          : 'Trust this recipient fingerprint before dispatch.');
      }

      addLog('Generating AES-256-GCM symmetric file key...');
      const fileKey = await generateFileKey();

      addLog(`Encrypting file payload (${selectedFile.size} bytes)...`);
      const { encryptedBlob, fileIv } = await encryptFileChunked(fileKey, selectedFile);
      addLog(`Payload sharded and encrypted successfully.`);

      addLog('Fetching target X3DH material from distributed nodes...');
      const preKeyRes = await fetch(apiUrl(`/prekey/${recipient}`), { headers: authHeaders(user.token) });
      const preKeyJson = await preKeyRes.json();
      if (!preKeyRes.ok) throw new Error(preKeyJson.error);

      const recipientPreKey = preKeyJson.preKey.publicKeyHex;
      const recipientIdentityECDH = preKeyJson.identityPublicKeyECDH; 

      addLog('Executing X3DH key agreement wrapper...');
      const { wrappedFileKey, ephemeralPublicKey } = await encryptFileKeyWithX3DH(
        fileKey,
        recipientPreKey,
        recipientIdentityECDH,
        user.privateKeyECDH!
      );

      addLog('Signing payload manifest with ECDSA private identity key...');
      const signatureData = `${wrappedFileKey}:${fileIv}`;
      const signature = await signPayload(user.privateKeyECDSA!, signatureData);

      addLog('Dispatching encrypted shards to server...');
      const formData = new FormData();
      formData.append('recipientUsername', recipient);
      formData.append('senderUsername', user.username);
      formData.append('signature', signature);
      formData.append('ephemeralPublicKey', ephemeralPublicKey);
      formData.append('usedPreKey', recipientPreKey);
      formData.append('wrappedFileKey', wrappedFileKey);
      formData.append('fileIv', fileIv);
      formData.append('originalFilename', selectedFile.name);
      formData.append('fileBlob', encryptedBlob, selectedFile.name + '.bin');

      const res = await fetch(apiUrl('/upload'), {
        method: 'POST',
        headers: authHeaders(user.token),
        body: formData
      });

      const json = await res.json();
      if (res.ok) {
        addLog('Transmission Confirmed. SECURE DISPATCH COMPLETE.');
        showToast(json.message, 'success');
        setSelectedFile(null);
      } else {
        throw new Error(json.error);
      }
    } catch (err: unknown) {
      const message = getErrorMessage(err, 'Transmission error.');
      addLog(`ERROR: ${message}`);
      showToast(message, 'error');
    } finally {
      setTimeout(() => setLoading(false), 500);
    }
  };

  const selectedRecipient = users.find((entry) => entry.username === recipient);
  const selectedTrust = recipient ? trustStatuses[recipient] : undefined;
  const selectedEncryptedSizeEstimate = selectedFile ? estimateChunkedEncryptedSize(selectedFile.size) : 0;
  const selectedFileTooLarge = selectedFile ? selectedEncryptedSizeEstimate > uploadLimitBytes : false;

  const handleTrustSelected = async () => {
    if (!user || !selectedRecipient || !selectedTrust) return;
    const expectedFingerprint = expectedFingerprints[selectedRecipient.username] || '';
    if (!fingerprintMatches(selectedTrust.fingerprint, expectedFingerprint)) {
      showToast('Fingerprint does not match this identity.', 'error');
      return;
    }

    const record = await trustIdentity(user.username, selectedRecipient);
    setTrustStatuses((current) => ({
      ...current,
      [selectedRecipient.username]: {
        fingerprint: record.fingerprint,
        trusted: true,
        changed: false,
        record
      }
    }));
    setExpectedFingerprints((current) => ({ ...current, [selectedRecipient.username]: '' }));
    showToast(`${selectedRecipient.username} trusted for future dispatches.`, 'success');
  };

  const handleForgetSelected = () => {
    if (!user || !selectedRecipient) return;

    forgetTrustedIdentity(user.username, selectedRecipient.username);
    setTrustStatuses((current) => ({
      ...current,
      [selectedRecipient.username]: {
        fingerprint: current[selectedRecipient.username]?.fingerprint || '',
        trusted: false,
        changed: false
      }
    }));
    showToast(`${selectedRecipient.username} removed from trusted identities.`, 'success');
  };

  return (
    <div className="max-w-2xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Secure Dispatch</h2>
        <p className="text-slate-400">Locally encrypt and shard files for private distribution.</p>
      </div>

      <div className="space-y-6">
        <div 
          className={`relative aspect-video rounded-3xl border-2 border-dashed transition-all duration-500 flex flex-col items-center justify-center p-8
            ${loading ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-white/10 hover:border-cyan-500/40 hover:bg-white/5 group'}`}
        >
          {loading ? (
            <div className="text-center">
              <Activity className="w-12 h-12 text-cyan-400 animate-pulse mx-auto mb-4" />
              <p className="text-cyan-400 font-mono text-sm tracking-widest uppercase">Encryption in Progress</p>
            </div>
          ) : (
            <>
              <div className="w-16 h-16 bg-slate-900 rounded-2xl flex items-center justify-center border border-white/10 mb-6 group-hover:scale-110 transition-transform">
                <UploadCloud className="w-8 h-8 text-cyan-400" />
              </div>
              <input 
                type="file" 
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" 
                onChange={(e) => setSelectedFile(e.target.files ? e.target.files[0] : null)}
              />
              <p className="text-white font-medium text-lg mb-1">
                {selectedFile ? selectedFile.name : 'Click or drag to encrypt'}
              </p>
              <p className={`text-sm ${selectedFileTooLarge ? 'text-red-300' : 'text-slate-500'}`}>
                {selectedFile
                  ? `${formatBytes(selectedFile.size)} selected · encrypted upload about ${formatBytes(selectedEncryptedSizeEstimate)}`
                  : `Single-upload limit ${formatBytes(uploadLimitBytes)}`}
              </p>
            </>
          )}
        </div>

        <GlassCard className="p-6 space-y-4">
          <div>
            <label className="text-[10px] uppercase font-bold text-slate-500 tracking-widest mb-2 block">Target Identity</label>
            <div className="relative flex gap-4">
              <div className="relative flex-1">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <select
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  className="w-full bg-black/40 border border-white/5 rounded-xl py-3 pl-12 pr-4 text-white focus:outline-none focus:border-cyan-500/50 transition-all text-sm appearance-none"
                >
                  <option value="">Select recipient...</option>
                  {users.map((u) => (
                    <option key={u.username} value={u.username}>
                      {u.username}
                    </option>
                  ))}
                </select>
              </div>
              <ActionButton onClick={handleSendSecureFile} loading={loading} disabled={!selectedFile || selectedFileTooLarge || !recipient || selectedTrust?.trusted !== true}>
                Dispatch
              </ActionButton>
            </div>
          </div>
          {selectedRecipient && selectedTrust && (
            <div className={`rounded-xl border p-4 ${
              selectedTrust.trusted
                ? 'border-emerald-500/20 bg-emerald-500/10'
                : selectedTrust.changed
                  ? 'border-red-500/20 bg-red-500/10'
                  : 'border-amber-500/20 bg-amber-500/10'
            }`}>
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="flex items-center gap-2 text-sm font-medium text-white">
                    {selectedTrust.trusted ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : selectedTrust.changed ? <ShieldAlert className="w-4 h-4 text-red-400" /> : <ShieldQuestion className="w-4 h-4 text-amber-400" />}
                    {selectedTrust.trusted ? 'Trusted identity' : selectedTrust.changed ? 'Fingerprint changed' : 'Untrusted identity'}
                  </p>
                  <p className="mt-2 font-mono text-xs text-slate-300 break-all">
                    {formatFingerprint(selectedTrust.fingerprint)}
                  </p>
                  {!selectedTrust.trusted && (
                    <input
                      value={expectedFingerprints[selectedRecipient.username] || ''}
                      onChange={(event) => setExpectedFingerprints((current) => ({
                        ...current,
                        [selectedRecipient.username]: event.target.value
                      }))}
                      placeholder="Paste friend's fingerprint to verify"
                      className="mt-3 w-full bg-black/30 border border-white/10 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
                    />
                  )}
                </div>
                {selectedTrust.trusted ? (
                  <ActionButton variant="secondary" onClick={handleForgetSelected} className="text-xs">
                    Forget
                  </ActionButton>
                ) : (
                  <ActionButton variant="secondary" onClick={handleTrustSelected} className="text-xs">
                    Trust
                  </ActionButton>
                )}
              </div>
            </div>
          )}
        </GlassCard>
      </div>
    </div>
  );
};
