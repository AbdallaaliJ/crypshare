import React from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2, Fingerprint, Lock, RadioTower } from 'lucide-react';
import { CrypShareLogo } from '../components/brand/CrypShareLogo';

export const LandingPage: React.FC = () => {
  return (
    <div className="w-full max-w-6xl mx-auto py-12 px-4 animate-in fade-in duration-700">
      <section className="grid lg:grid-cols-[1.05fr_0.95fr] gap-10 items-center">
        <div>
          <div className="inline-flex items-center gap-2 bg-[color-mix(in_srgb,var(--brand-cyan)_14%,var(--app-surface))] border border-[color-mix(in_srgb,var(--brand-cyan)_42%,var(--app-border))] px-4 py-1.5 rounded-full text-[11px] font-bold text-[var(--app-text)] uppercase tracking-widest mb-8">
            <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success-color)]" />
            Privacy-first secure drive
          </div>

          <h1 className="text-4xl md:text-6xl font-bold tracking-tight text-[var(--app-text)] mb-6 leading-tight max-w-3xl">
            Store, verify, and share with a private identity signature.
          </h1>
          <p className="text-[var(--app-muted)] text-base md:text-lg max-w-2xl mb-10 leading-relaxed">
            CrypShare combines client-side encryption, verified fingerprints, workspace approval, and one-time P2P transfer for trusted teams and privacy-conscious users.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 items-start mb-12">
            <Link 
              to="/register" 
              className="w-full sm:w-auto px-7 py-3 bg-[var(--brand-blue)] text-white hover:bg-blue-700 rounded-lg font-bold transition-colors active:brightness-95 text-center text-sm"
              style={{ textDecoration: 'none' }}
            >
              Create Secure Identity
            </Link>
            <Link
              to="/login"
              className="w-full sm:w-auto px-7 py-3 bg-[var(--app-surface-muted)] hover:bg-[var(--app-surface)] text-[var(--app-text)] border border-[var(--app-border)] rounded-lg font-bold transition-all active:scale-[0.98] text-center text-sm shadow-sm"
              style={{ textDecoration: 'none' }}
            >
              Unlock Drive
            </Link>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {[
              ['You first', 'Identity and control stay with the user.'],
              ['Verified', 'Fingerprint trust before sensitive sharing.'],
              ['Seamless', 'Drive-style workflows with encrypted content.']
            ].map(([title, copy]) => (
              <div key={title} className="app-card rounded-lg p-4">
                <p className="text-sm font-bold text-[var(--app-text)]">{title}</p>
                <p className="mt-1 text-xs text-[var(--app-muted)] leading-relaxed">{copy}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="brand-showcase-panel rounded-lg p-8 md:p-10">
          <div className="flex justify-center mb-8">
            <CrypShareLogo markSize={86} wordmarkClassName="text-4xl" />
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg bg-[var(--app-surface-muted)] border border-[var(--app-border)] p-4">
              <Fingerprint className="w-5 h-5 text-[var(--brand-cyan)] mb-3" />
              <p className="text-xs text-[var(--app-muted)]">Identity fingerprints</p>
            </div>
            <div className="rounded-lg bg-[var(--app-surface-muted)] border border-[var(--app-border)] p-4">
              <Lock className="w-5 h-5 text-[var(--brand-teal)] mb-3" />
              <p className="text-xs text-[var(--app-muted)]">Encrypted files</p>
            </div>
            <div className="rounded-lg bg-[var(--app-surface-muted)] border border-[var(--app-border)] p-4">
              <RadioTower className="w-5 h-5 text-[var(--brand-cyan)] mb-3" />
              <p className="text-xs text-[var(--app-muted)]">P2P transfer</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
