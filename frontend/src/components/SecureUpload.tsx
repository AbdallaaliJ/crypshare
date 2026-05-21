import React, { useState, useEffect } from 'react';
import { UploadCloud, Activity, User } from 'lucide-react';
import { useToast } from './ui/ToastContext';
import { useAuth } from '../contexts/AuthContext';
import { useLogContext } from '../contexts/LogContext';
import { GlassCard } from './ui/GlassCard';
import { ActionButton } from './ui/ActionButton';
import {
  generateFileKey,
  encryptFileChunked,
  encryptFileKeyWithX3DH,
  signPayload
} from '../utils/crypto';

export const SecureUpload: React.FC = () => {
  const [users, setUsers] = useState<{ username: string }[]>([]);
  const [recipient, setRecipient] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  
  const { showToast } = useToast();
  const { user } = useAuth();
  const { addLog, clearLogs } = useLogContext();

  const loadUsers = async () => {
    try {
      const r = await fetch('http://localhost:3001/users');
      const data = await r.json();
      const otherUsers = data.filter((u: any) => u.username !== user?.username);
      setUsers(otherUsers);
      if (otherUsers.length > 0 && !recipient) setRecipient(otherUsers[0].username);
    } catch (e) {
      console.error(e);
      showToast('Failed to load directory', 'error');
    }
  };

  useEffect(() => {
    if (user) {
      loadUsers();
    }
  }, [user]);

  const handleSendSecureFile = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!recipient || !selectedFile || !user) {
      showToast('Please fill all required fields.', 'error');
      return;
    }

    try {
      setLoading(true);
      clearLogs();
      addLog(`Initializing dispatch protocol for target: ${recipient}...`);

      const targetUser = users.find((u) => u.username === recipient);
      if (!targetUser) return;

      addLog('Generating AES-256-GCM symmetric file key...');
      const fileKey = await generateFileKey();

      addLog(`Encrypting file payload (${selectedFile.size} bytes)...`);
      const { encryptedBlob, fileIv } = await encryptFileChunked(fileKey, selectedFile);
      addLog(`Payload sharded and encrypted successfully.`);

      addLog('Fetching target X3DH material from distributed nodes...');
      const preKeyRes = await fetch(`http://localhost:3001/prekey/${recipient}`);
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

      const res = await fetch('http://localhost:3001/upload', {
        method: 'POST',
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
    } catch (err: any) {
      addLog(`ERROR: ${err.message}`);
      showToast(err.message || 'Transmission error.', 'error');
    } finally {
      setTimeout(() => setLoading(false), 500);
    }
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
              <p className="text-slate-500 text-sm">
                {selectedFile ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB` : 'Supports any file up to 2GB'}
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
              <ActionButton onClick={handleSendSecureFile} loading={loading} disabled={!selectedFile || !recipient}>
                Dispatch
              </ActionButton>
            </div>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};
