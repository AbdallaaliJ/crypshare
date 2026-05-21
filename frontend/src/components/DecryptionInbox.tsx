import React, { useState, useEffect } from 'react';
import { FileText, Unlock, Activity } from 'lucide-react';
import { useToast } from './ui/ToastContext';
import { useAuth } from '../contexts/AuthContext';
import { useLogContext } from '../contexts/LogContext';
import {
  decryptFileKeyWithX3DH,
  decryptFileChunked,
  verifySignature,
  importECDSAPublicKey
} from '../utils/crypto';

export const DecryptionInbox: React.FC = () => {
  const [inboxFiles, setInboxFiles] = useState<any[]>([]);
  const [decryptingId, setDecryptingId] = useState<number | null>(null);
  
  const { showToast } = useToast();
  const { user } = useAuth();
  const { addLog, clearLogs } = useLogContext();

  const handleFetchInbox = async () => {
    if (!user) return;
    try {
      const r = await fetch(`http://localhost:3001/inbox/${user.username}`);
      const data = await r.json();
      if (!r.ok) {
        showToast(data.error || 'Failed to fetch inbox', 'error');
        return;
      }
      setInboxFiles(data.inbox.map((file: any) => ({ ...file, salt: data.salt })));
    } catch (err) {
      console.error(err);
      showToast('Error fetching inbox.', 'error');
    }
  };

  useEffect(() => {
    if (user) handleFetchInbox();
  }, [user]);

  const handleDecryptFile = async (idx: number, filePayload: any) => {
    if (!user || !user.kek || !user.privateKeyECDH) {
      showToast('Session keys missing. Log in again.', 'error');
      return;
    }

    setDecryptingId(idx);
    clearLogs();
    addLog(`Initiating decryption protocol for file: ${filePayload.originalFilename}`);

    try {
      addLog('Fetching sender ECDSA public key for signature verification...');
      const usersList = await fetch('http://localhost:3001/users').then(r => r.json());
      const senderInfo = usersList.find((u: any) => u.username === filePayload.senderUsername);
      if (!senderInfo) throw new Error('Sender missing from directory. Spoofing detected.');

      const senderPubECDSA = await importECDSAPublicKey(senderInfo.identityPublicKeyECDSA);
      const signatureData = `${filePayload.wrappedFileKey}:${filePayload.fileIv}`;

      addLog('Verifying cryptographic signature...');
      const sigIsValid = await verifySignature(senderPubECDSA, filePayload.signature, signatureData);
      if (!sigIsValid) throw new Error('SIGNATURE FAILED! IMPERSONATION DETECTED!');
      addLog('Signature valid. Sender identity confirmed.');

      addLog('Unwrapping X3DH keys using session keys...');
      const fileKey = await decryptFileKeyWithX3DH(
        filePayload.wrappedFileKey,
        filePayload.ephemeralPublicKey,
        senderInfo.identityPublicKeyECDH,
        user.privateKeyECDH,
        filePayload.encryptedPrivatePreKey,
        filePayload.preKeyIv,
        user.kek
      );

      addLog('Downloading encrypted shards...');
      const blobRes = await fetch(`http://localhost:3001/download-file/${filePayload.filepath}`);
      if (!blobRes.ok) throw new Error('Encrypted file not found.');

      addLog('Decrypting and assembling fragments (AES-256-GCM)...');
      const encryptedBlob = await blobRes.blob();
      const plainBlob = await decryptFileChunked(fileKey, encryptedBlob);
      const url = URL.createObjectURL(plainBlob);

      addLog('DECRYPTION COMPLETE. Extracting to filesystem...');
      showToast('Decryption successful!', 'success');

      // Auto download
      const a = document.createElement('a');
      a.href = url;
      a.download = filePayload.originalFilename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      
      // Update local state to remove it from the list visually (or mark it)
      // Usually you'd call a backend to mark as read, here we just filter it out.
      setInboxFiles(prev => prev.filter((_, i) => i !== idx));

    } catch (err: any) {
      addLog(`ERROR: ${err.message}`);
      showToast('Failed: ' + err.message, 'error');
    } finally {
      setTimeout(() => setDecryptingId(null), 1000);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Incoming Streams</h2>
          <p className="text-slate-400">Encrypted fragments waiting for your private key.</p>
        </div>
        <button onClick={handleFetchInbox} className="bg-emerald-500/10 text-emerald-500 px-4 py-2 rounded-xl text-xs font-bold border border-emerald-500/20 hover:bg-emerald-500/20 transition-all">
          {inboxFiles.length} Secure Envelopes (Refresh)
        </button>
      </div>

      <div className="grid gap-4">
        {inboxFiles.length === 0 ? (
          <div className="p-8 border border-white/5 bg-slate-900/40 rounded-2xl text-center text-slate-500">
            No incoming streams found.
          </div>
        ) : (
          inboxFiles.map((file, idx) => (
            <div key={idx} className="group flex items-center justify-between p-5 bg-slate-900/40 border border-white/5 rounded-2xl hover:border-white/10 transition-all">
              <div className="flex items-center gap-5">
                <div className="w-12 h-12 bg-white/5 rounded-xl flex items-center justify-center">
                  <FileText className="w-6 h-6 text-slate-400" />
                </div>
                <div>
                  <h4 className="text-white font-medium mb-1">{file.originalFilename}</h4>
                  <p className="text-xs text-slate-500">
                    Sent by <span className="text-slate-300 font-mono">{file.senderUsername}</span> • {(file.fileSize / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              </div>
              
              <div className="flex items-center gap-6">
                <div className="hidden md:block text-right">
                  <p className="text-[10px] uppercase text-slate-600 font-bold tracking-tighter">Date</p>
                  <p className="text-[10px] font-mono text-slate-400">{new Date(file.timestamp).toLocaleDateString()}</p>
                </div>
                <button 
                  onClick={() => handleDecryptFile(idx, file)}
                  disabled={decryptingId !== null}
                  className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-bold transition-all
                    ${decryptingId === idx 
                      ? 'bg-slate-800 text-slate-500' 
                      : 'bg-white/5 hover:bg-emerald-500/20 text-white border border-white/10 hover:border-emerald-400/40'}`}
                >
                  {decryptingId === idx ? <Activity className="w-4 h-4 animate-spin" /> : <Unlock className="w-4 h-4" />}
                  {decryptingId === idx ? 'Unwrapping...' : 'Decrypt & Save'}
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
