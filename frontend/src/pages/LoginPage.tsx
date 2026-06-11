import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { CheckCircle2, Fingerprint, LockKeyhole, RadioTower } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { apiUrl } from '../config/api';
import type { DirectoryUser } from '../types/api';
import { getErrorMessage } from '../utils/errors';
import { hexToBytes, deriveKEK, deriveAuthSecret, unwrapPrivateKey } from '../utils/crypto';
import { ActionButton } from '../components/ui/ActionButton';
import { CrypShareLogo } from '../components/brand/CrypShareLogo';

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
      const materialRes = await fetch(apiUrl(`/session-material/${username}`));
      const materialData = await materialRes.json();
      
      if (!materialRes.ok) {
        throw new Error(materialData.error || 'User not found');
      }

      const saltBytes = hexToBytes(materialData.salt);
      const authSaltBytes = hexToBytes(materialData.authSalt);
      const kek = await deriveKEK(password, saltBytes);
      const authSecret = await deriveAuthSecret(password, authSaltBytes);

      const sessionRes = await fetch(apiUrl('/sessions'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, authSecret })
      });
      const sessionData = await sessionRes.json();
      if (!sessionRes.ok) {
        throw new Error(sessionData.error || 'Invalid credentials');
      }

      const authHeader = { Authorization: `Bearer ${sessionData.token}` };
      const identRes = await fetch(apiUrl(`/identity/${username}`), { headers: authHeader });
      const identData = await identRes.json();
      if (!identRes.ok) {
        throw new Error(identData.error || 'Identity payload unavailable.');
      }

      const usersRes = await fetch(apiUrl('/users'), { headers: authHeader });
      const usersList = await usersRes.json() as DirectoryUser[];
      const userInfo = usersList.find((u) => u.username === username);
      
      if (!userInfo) {
         throw new Error('User public data missing.');
      }

      const privateKeyECDH = await unwrapPrivateKey(identData.encryptedPrivateKeyECDH, identData.ivECDH, kek, 'ECDH');
      const privateKeyECDSA = await unwrapPrivateKey(identData.encryptedPrivateKeyECDSA, identData.ivECDSA, kek, 'ECDSA');

      login({
        username,
        kek,
        privateKeyECDH,
        privateKeyECDSA,
        identityPublicKeyECDH: userInfo.identityPublicKeyECDH,
        identityPublicKeyECDSA: userInfo.identityPublicKeyECDSA,
        role: identData.role || 'member',
        token: sessionData.token,
        sessionExpiresAt: sessionData.expiresAt
      });

      showToast('Vault unlocked. Keys in RAM.', 'success');
      navigate('/dashboard/overview');

    } catch (err: unknown) {
      console.error(err);
      showToast(getErrorMessage(err, 'Login failed. Check your password.'), 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto px-4 py-10 md:py-16 animate-in fade-in duration-500">
      <div className="grid lg:grid-cols-[0.92fr_1.08fr] gap-8 items-stretch">
        <section className="brand-showcase-panel rounded-lg p-8 md:p-10 flex flex-col justify-between min-h-[520px]">
          <div>
            <CrypShareLogo markSize={60} wordmarkClassName="text-3xl" />
            <h1 className="mt-10 text-3xl md:text-4xl font-bold tracking-tight leading-tight">
              Unlock your private secure drive.
            </h1>
            <p className="mt-4 text-sm md:text-base text-[var(--app-muted)] leading-relaxed max-w-md">
              Your master secret unwraps identity keys locally. CrypShare keeps collaboration workspace-scoped and fingerprint-gated.
            </p>
          </div>

          <div className="grid sm:grid-cols-3 gap-3 mt-10">
            {[
              { icon: Fingerprint, label: 'Verified identity' },
              { icon: LockKeyhole, label: 'Client-side keys' },
              { icon: RadioTower, label: 'P2P option' }
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
                <Icon className="w-5 h-5 text-[var(--brand-cyan)] mb-3" />
                <p className="text-xs font-semibold text-[var(--app-muted)]">{label}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="app-card rounded-lg p-6 md:p-10 flex flex-col justify-center">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-[var(--brand-cyan)] mb-3">Secure access</p>
              <h2 className="text-3xl font-bold tracking-tight text-[var(--app-text)]">Sign in</h2>
              <p className="text-sm text-[var(--app-muted)] mt-2">Enter your identity username and master secret to unlock your vault session.</p>
            </div>

            <form onSubmit={handleLogin} className="space-y-4">
              <label className="block">
                <span className="text-xs font-bold uppercase tracking-wide text-[var(--app-muted)]">Identity username</span>
                <input
                  type="text"
                  placeholder="aj"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="app-field mt-2 w-full rounded-lg px-4 py-3.5 focus:outline-none focus:border-[var(--brand-cyan)] focus:ring-4 focus:ring-cyan-500/10 transition-all placeholder:text-[var(--app-subtle)]"
                  required
                />
              </label>
              <label className="block">
                <span className="text-xs font-bold uppercase tracking-wide text-[var(--app-muted)]">Master secret</span>
                <input
                  type="password"
                  placeholder="Your local unlock secret"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="app-field mt-2 w-full rounded-lg px-4 py-3.5 focus:outline-none focus:border-[var(--brand-cyan)] focus:ring-4 focus:ring-cyan-500/10 transition-all placeholder:text-[var(--app-subtle)] font-mono"
                  required
                />
              </label>
              <ActionButton className="w-full justify-center" loading={loading} type="submit">
                Unlock Drive
              </ActionButton>
            </form>

            <div className="mt-7 flex items-center justify-center gap-2 text-[11px] text-[var(--app-muted)] font-bold uppercase tracking-widest">
              <CheckCircle2 className="w-3.5 h-3.5 text-[var(--brand-teal)]" /> Keys stay local
            </div>

            <div className="text-center mt-6 text-sm text-[var(--app-muted)]">
              New to CrypShare? <Link to="/register" className="text-[var(--brand-blue)] font-semibold hover:underline">Create an identity</Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
