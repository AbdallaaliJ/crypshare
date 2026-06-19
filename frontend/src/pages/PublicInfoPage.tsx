import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { CheckCircle2, Lock, RadioTower, ShieldCheck } from 'lucide-react';

type PublicInfoContent = {
  title: string;
  eyebrow: string;
  intro: string;
  points: string[];
};

const pages: Record<string, PublicInfoContent> = {
  '/features': {
    eyebrow: 'Features',
    title: 'Encrypted collaboration without public file links.',
    intro: 'CrypShare is built around private workspaces, local encryption, verified contacts, and a secure-drive workflow for small trusted groups.',
    points: [
      'Client-side encrypted vault files and metadata.',
      'Workspace-scoped sharing with owner/admin approval.',
      'Fingerprint trust checks before encrypted grants are created.',
      'Online one-time P2P transfer with relay-only WebRTC.'
    ]
  },
  '/security': {
    eyebrow: 'Security',
    title: 'Strong public-beta security with clear boundaries.',
    intro: 'CrypShare keeps plaintext files, folders, file keys, and P2P metadata out of server storage, while acknowledging the metadata a collaboration service must process.',
    points: [
      'Files and sensitive labels are encrypted before upload.',
      'TURN relay can see IP/timing/packet-size metadata, not plaintext file content.',
      'Activity views are scoped to the user and workspace administration permissions.',
      'Public beta is not certified defense or regulated high-security infrastructure.'
    ]
  },
  '/privacy': {
    eyebrow: 'Privacy',
    title: 'Private by design, not anonymous by claim.',
    intro: 'The server needs account, session, workspace, and routing metadata to operate, but it should not receive plaintext file contents or secret keys.',
    points: [
      'No plaintext vault filenames or folder names are stored by the backend.',
      'Identity fingerprints should be verified out-of-band before trust.',
      'Invite codes prove workspace access only, not real-world identity.',
      'Deployment operators remain responsible for logs, backups, TLS, and retention.'
    ]
  },
  '/terms': {
    eyebrow: 'Terms',
    title: 'Public-beta software for trusted groups.',
    intro: 'CrypShare is provided as-is under the project license and should be evaluated carefully before sensitive production use.',
    points: [
      'Do not use for regulated or defense-grade workloads without external review.',
      'Users are responsible for verifying contacts and protecting their devices.',
      'Operators are responsible for abuse handling, backups, monitoring, and incident response.',
      'Public links and anonymous access are intentionally out of scope.'
    ]
  },
  '/contact': {
    eyebrow: 'Contact',
    title: 'Review, deploy, and report carefully.',
    intro: 'For a public deployment, use the release checklist and security policy before inviting users.',
    points: [
      'Run deployment checks with real production values.',
      'Review SECURITY.md before publishing vulnerability details.',
      'Keep production secrets out of Git and frontend code.',
      'Use HTTPS, PostgreSQL, S3-compatible storage, and reachable TURN.'
    ]
  }
};

export const PublicInfoPage: React.FC = () => {
  const location = useLocation();
  const content = pages[location.pathname] || pages['/features'];

  return (
    <div className="w-full max-w-5xl mx-auto py-10 px-4 animate-in fade-in duration-500">
      <div className="max-w-3xl">
        <div className="inline-flex items-center gap-2 bg-[color-mix(in_srgb,var(--brand-cyan)_14%,var(--app-surface))] border border-[color-mix(in_srgb,var(--brand-cyan)_42%,var(--app-border))] px-4 py-1.5 rounded-full text-[11px] font-bold text-[var(--app-text)] uppercase tracking-widest mb-7">
          <ShieldCheck className="w-3.5 h-3.5 text-[var(--brand-cyan)]" />
          {content.eyebrow}
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-[var(--app-text)] mb-5 leading-tight">
          {content.title}
        </h1>
        <p className="text-[var(--app-muted)] text-base md:text-lg max-w-2xl leading-relaxed">
          {content.intro}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 mt-10">
        {content.points.map((point) => (
          <div key={point} className="app-card rounded-lg p-5 flex gap-3">
            <CheckCircle2 className="w-5 h-5 text-[var(--success-color)] shrink-0 mt-0.5" />
            <p className="text-sm text-[var(--app-text)] leading-relaxed">{point}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2 mt-6">
        <div className="app-card rounded-lg p-5">
          <Lock className="w-5 h-5 text-[var(--brand-cyan)] mb-3" />
          <p className="text-sm font-bold text-[var(--app-text)]">Default sharing</p>
          <p className="text-xs text-[var(--app-muted)] leading-relaxed mt-2">
            Encrypted vault sharing is best for async access, revocation, workspace gates, and normal secure-drive workflows.
          </p>
        </div>
        <div className="app-card rounded-lg p-5">
          <RadioTower className="w-5 h-5 text-[var(--brand-teal)] mb-3" />
          <p className="text-sm font-bold text-[var(--app-text)]">One-time transfer</p>
          <p className="text-xs text-[var(--app-muted)] leading-relaxed mt-2">
            P2P transfer is online-only and uses short-lived TURN credentials with app-layer encrypted chunks.
          </p>
        </div>
      </div>

      <div className="mt-10 flex flex-col sm:flex-row gap-3">
        <Link to="/register" className="px-6 py-3 bg-[var(--brand-blue)] text-white rounded-lg text-sm font-bold text-center" style={{ textDecoration: 'none' }}>
          Create Secure Identity
        </Link>
        <Link to="/" className="px-6 py-3 bg-[var(--app-surface-muted)] border border-[var(--app-border)] text-[var(--app-text)] rounded-lg text-sm font-bold text-center" style={{ textDecoration: 'none' }}>
          Back to Home
        </Link>
      </div>
    </div>
  );
};
