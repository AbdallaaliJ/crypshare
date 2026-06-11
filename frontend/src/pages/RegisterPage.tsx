import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { CheckCircle2, Fingerprint, KeyRound, ShieldCheck } from 'lucide-react';
import { useToast } from '../components/ui/useToast';
import { ActionButton } from '../components/ui/ActionButton';
import { apiUrl } from '../config/api';
import { getErrorMessage } from '../utils/errors';
import { CrypShareLogo } from '../components/brand/CrypShareLogo';
import {
  generateSalt,
  deriveKEK,
  deriveAuthSecret,
  bytesToHex,
  generateIdentityKeyPair,
  generateSigningKeyPair,
  wrapPrivateKey,
  exportPublicKey,
  generatePreKeys,
  hashSHA256
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
      const authSalt = generateSalt();
      const kek = await deriveKEK(password, salt);
      const authSecret = await deriveAuthSecret(password, authSalt);
      const authVerifierHash = await hashSHA256(authSecret);
      
      const keyPairECDH = await generateIdentityKeyPair();
      const pubKeyHexECDH = await exportPublicKey(keyPairECDH.publicKey);
      const wrappedECDH = await wrapPrivateKey(kek, keyPairECDH.privateKey);

      const keyPairECDSA = await generateSigningKeyPair();
      const pubKeyHexECDSA = await exportPublicKey(keyPairECDSA.publicKey);
      const wrappedECDSA = await wrapPrivateKey(kek, keyPairECDSA.privateKey);

      const payload = {
        username,
        salt: bytesToHex(salt),
        authSalt: bytesToHex(authSalt),
        authVerifierHash,
        identityPublicKeyECDH: pubKeyHexECDH,
        identityPublicKeyECDSA: pubKeyHexECDSA,
        encryptedPrivateKeyECDH: wrappedECDH.ciphertext,
        ivECDH: wrappedECDH.iv,
        encryptedPrivateKeyECDSA: wrappedECDSA.ciphertext,
        ivECDSA: wrappedECDSA.iv
      };

      const res = await fetch(apiUrl('/register'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      const json = await res.json();
      
      if (res.ok) {
        if (!json.approved) {
          showToast('Identity submitted. Wait for an admin to approve it before login.', 'success');
          navigate('/login');
          return;
        }

        const sessionRes = await fetch(apiUrl('/sessions'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, authSecret })
        });
        const sessionJson = await sessionRes.json();
        if (!sessionRes.ok) {
          throw new Error(sessionJson.error || 'Session creation failed.');
        }

        showToast('Generating pre-keys...', 'info');
        const preKeys = await generatePreKeys(kek, 100);
        const preKeyRes = await fetch(apiUrl('/upload-prekeys'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${sessionJson.token}`
          },
          body: JSON.stringify({ username, preKeys })
        });
        const preKeyJson = await preKeyRes.json();
        if (!preKeyRes.ok) {
          throw new Error(preKeyJson.error || 'Pre-key upload failed.');
        }
        
        showToast('Identity registration complete. Please login.', 'success');
        navigate('/login');
      } else {
        throw new Error(json.error);
      }
    } catch (err: unknown) {
      console.error(err);
      showToast(getErrorMessage(err, 'Registration failed.'), 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto px-4 py-10 md:py-16 animate-in fade-in duration-500">
      <div className="grid lg:grid-cols-[1.08fr_0.92fr] gap-8 items-stretch">
        <section className="app-card rounded-lg p-6 md:p-10 flex flex-col justify-center order-2 lg:order-1">
          <div className="max-w-md w-full mx-auto">
            <div className="mb-8">
              <p className="text-[11px] font-bold uppercase tracking-widest text-[var(--brand-cyan)] mb-3">New identity</p>
              <h1 className="text-3xl font-bold tracking-tight text-[var(--app-text)]">Create your CrypShare identity</h1>
              <p className="text-sm text-[var(--app-muted)] mt-2">
                Your signing and encryption keys are generated in this browser and protected by your master secret.
              </p>
            </div>

            <form onSubmit={handleRegister} className="space-y-4">
              <label className="block">
                <span className="text-xs font-bold uppercase tracking-wide text-[var(--app-muted)]">Identity username</span>
                <input
                  type="text"
                  placeholder="choose-a-name"
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
                  placeholder="Protect your local keys"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="app-field mt-2 w-full rounded-lg px-4 py-3.5 focus:outline-none focus:border-[var(--brand-cyan)] focus:ring-4 focus:ring-cyan-500/10 transition-all placeholder:text-[var(--app-subtle)] font-mono"
                  required
                />
              </label>
              <ActionButton className="w-full justify-center" loading={loading} type="submit">
                Generate Identity
              </ActionButton>
            </form>

            <div className="mt-7 flex items-center justify-center gap-2 text-[11px] text-[var(--app-muted)] font-bold uppercase tracking-widest">
              <CheckCircle2 className="w-3.5 h-3.5 text-[var(--brand-teal)]" /> Client-side crypto
            </div>

            <div className="text-center mt-6 text-sm text-[var(--app-muted)]">
              Already have an identity? <Link to="/login" className="text-[var(--brand-blue)] font-semibold hover:underline">Sign in</Link>
            </div>
          </div>
        </section>

        <section className="brand-showcase-panel rounded-lg p-8 md:p-10 flex flex-col justify-between min-h-[520px] order-1 lg:order-2">
          <div>
            <CrypShareLogo markSize={60} wordmarkClassName="text-3xl" />
            <h2 className="mt-10 text-3xl md:text-4xl font-bold tracking-tight leading-tight">
              Start with a private identity, then join trusted workspaces.
            </h2>
            <p className="mt-4 text-sm md:text-base text-[var(--app-muted)] leading-relaxed max-w-md">
              CrypShare separates account identity, workspace approval, and personal fingerprint trust so sharing stays deliberate.
            </p>
          </div>

          <div className="grid sm:grid-cols-3 gap-3 mt-10">
            {[
              { icon: KeyRound, label: 'Local key wrap' },
              { icon: Fingerprint, label: 'Fingerprint trust' },
              { icon: ShieldCheck, label: 'Workspace approval' }
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
                <Icon className="w-5 h-5 text-[var(--brand-teal)] mb-3" />
                <p className="text-xs font-semibold text-[var(--app-muted)]">{label}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
};
