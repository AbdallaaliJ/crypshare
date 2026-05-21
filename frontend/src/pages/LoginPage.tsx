import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../components/ui/ToastContext';
import { hexToBytes, deriveKEK, unwrapPrivateKey } from '../utils/crypto';
import { ActionButton } from '../components/ui/ActionButton';

export const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      showToast('Please enter both username and password.', 'error');
      return;
    }

    setLoading(true);
    try {
      showToast('Authenticating...', 'info');
      const identRes = await fetch(`http://localhost:3001/identity/${username}`);
      const identData = await identRes.json();
      
      if (!identRes.ok) {
        throw new Error(identData.error || 'User not found');
      }

      const usersRes = await fetch('http://localhost:3001/users');
      const usersList = await usersRes.json();
      const userInfo = usersList.find((u: any) => u.username === username);
      
      if (!userInfo) {
         throw new Error('User public data missing.');
      }

      const saltBytes = hexToBytes(identData.salt);
      const kek = await deriveKEK(password, saltBytes);

      const privateKeyECDH = await unwrapPrivateKey(identData.encryptedPrivateKeyECDH, identData.ivECDH, kek, 'ECDH');
      const privateKeyECDSA = await unwrapPrivateKey(identData.encryptedPrivateKeyECDSA, identData.ivECDSA, kek, 'ECDSA');

      login({
        username,
        kek,
        privateKeyECDH,
        privateKeyECDSA,
        identityPublicKeyECDH: userInfo.identityPublicKeyECDH
      });

      showToast('Vault unlocked. Keys in RAM.', 'success');
      navigate('/dashboard/inbox');

    } catch (err: any) {
      console.error(err);
      showToast(err.message || 'Login failed. Check your password.', 'error');
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
          <h1 className="text-4xl font-bold tracking-tight text-white">CrypShare</h1>
          <p className="text-slate-500 mt-2 font-medium">Zero-Knowledge Secure Cloud</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
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
          <ActionButton className="w-full" loading={loading} type="submit">Unlock Vault</ActionButton>
        </form>
        
        <div className="mt-8 flex justify-center gap-2 items-center text-[10px] text-slate-500 font-bold uppercase tracking-widest">
          <CheckCircle2 className="w-3 h-3 text-emerald-500" /> End-to-End Secure
        </div>
        
        <div className="text-center mt-6 text-sm text-slate-500">
          New to CrypShare? <Link to="/register" className="text-cyan-400 hover:underline">Register</Link>
        </div>
      </div>
    </div>
  );
};
