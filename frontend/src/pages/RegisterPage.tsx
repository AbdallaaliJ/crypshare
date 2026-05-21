import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, CheckCircle2 } from 'lucide-react';
import { useToast } from '../components/ui/ToastContext';
import { ActionButton } from '../components/ui/ActionButton';
import {
  generateSalt,
  deriveKEK,
  bytesToHex,
  generateIdentityKeyPair,
  generateSigningKeyPair,
  wrapPrivateKey,
  exportPublicKey,
  generatePreKeys
} from '../utils/crypto';

export const RegisterPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { showToast } = useToast();
  const navigate = useNavigate();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || !username) {
      showToast('Please enter a username and password.', 'error');
      return;
    }
    
    setLoading(true);
    try {
      showToast('Generating keys...', 'info');
      const salt = generateSalt();
      const kek = await deriveKEK(password, salt);
      
      const keyPairECDH = await generateIdentityKeyPair();
      const pubKeyHexECDH = await exportPublicKey(keyPairECDH.publicKey);
      const wrappedECDH = await wrapPrivateKey(kek, keyPairECDH.privateKey);

      const keyPairECDSA = await generateSigningKeyPair();
      const pubKeyHexECDSA = await exportPublicKey(keyPairECDSA.publicKey);
      const wrappedECDSA = await wrapPrivateKey(kek, keyPairECDSA.privateKey);

      const payload = {
        username,
        salt: bytesToHex(salt),
        identityPublicKeyECDH: pubKeyHexECDH,
        identityPublicKeyECDSA: pubKeyHexECDSA,
        encryptedPrivateKeyECDH: wrappedECDH.ciphertext,
        ivECDH: wrappedECDH.iv,
        encryptedPrivateKeyECDSA: wrappedECDSA.ciphertext,
        ivECDSA: wrappedECDSA.iv
      };

      const res = await fetch('http://localhost:3001/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      const json = await res.json();
      
      if (res.ok) {
        showToast('Generating pre-keys...', 'info');
        const preKeys = await generatePreKeys(kek, 100);
        await fetch('http://localhost:3001/upload-prekeys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, preKeys })
        });
        
        showToast('Registration complete. Please login.', 'success');
        navigate('/login');
      } else {
        throw new Error(json.error);
      }
    } catch (err: any) {
      console.error(err);
      showToast(err.message || 'Registration failed.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 text-slate-200 selection:bg-cyan-500/30 w-full fixed inset-0 z-50">
      <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_30%_30%,_rgba(34,211,238,0.05),_transparent)] pointer-events-none" />
      
      <div className="w-full max-w-sm animate-in fade-in slide-in-from-bottom-4">
        <div className="text-center mb-10">
          <div className="inline-flex p-4 rounded-3xl bg-cyan-500/10 border border-cyan-500/20 mb-6 animate-pulse">
            <Shield className="w-10 h-10 text-cyan-400" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Create Identity</h1>
          <p className="text-slate-500 mt-2 font-medium">Generate your keys locally.</p>
        </div>

        <form onSubmit={handleRegister} className="space-y-4">
          <div className="space-y-1">
            <input 
              type="text" 
              placeholder="Identity ID (Username)" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-slate-900/50 border border-white/5 rounded-xl px-5 py-3.5 focus:outline-none focus:border-cyan-500/50 transition-all placeholder:text-slate-600" 
              required 
            />
            <input 
              type="password" 
              placeholder="Master Secret" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-900/50 border border-white/5 rounded-xl px-5 py-3.5 focus:outline-none focus:border-cyan-500/50 transition-all placeholder:text-slate-600 font-mono" 
              required 
            />
          </div>
          <ActionButton className="w-full" loading={loading} type="submit">Initialize Node</ActionButton>
        </form>
        
        <div className="mt-8 flex justify-center gap-2 items-center text-[10px] text-slate-500 font-bold uppercase tracking-widest">
          <CheckCircle2 className="w-3 h-3 text-emerald-500" /> Client-Side Crypto
        </div>
        
        <div className="text-center mt-6 text-sm text-slate-500">
          Already have a node? <Link to="/login" className="text-cyan-400 hover:underline">Login</Link>
        </div>
      </div>
    </div>
  );
};
