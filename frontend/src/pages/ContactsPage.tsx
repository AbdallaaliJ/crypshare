import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Copy, Download, RefreshCw, Search, ShieldAlert, ShieldCheck, ShieldQuestion, Trash2, UserPlus, Users } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { StatusBadge } from '../components/ui/StatusBadge';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import type { DirectoryUser } from '../types/api';
import { getErrorMessage } from '../utils/errors';
import {
  createIdentityInvite,
  fingerprintMatches,
  formatFingerprint,
  forgetTrustedIdentity,
  getTrustedIdentities,
  getTrustStatus,
  identityFingerprint,
  parseIdentityInvite,
  trustIdentity,
  type TrustStatus,
  type TrustedIdentityRecord
} from '../utils/trust';

interface InvitePreview {
  username: string;
  pastedFingerprint: string;
  serverFingerprint: string;
  matches: boolean;
  alreadyTrusted: boolean;
  changed: boolean;
  identity?: DirectoryUser;
  error?: string;
}

export const ContactsPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [directory, setDirectory] = useState<DirectoryUser[]>([]);
  const [trustStatuses, setTrustStatuses] = useState<Record<string, TrustStatus>>({});
  const [trustedContacts, setTrustedContacts] = useState<Record<string, TrustedIdentityRecord>>({});
  const [ownFingerprint, setOwnFingerprint] = useState('');
  const [inviteText, setInviteText] = useState('');
  const [invitePreview, setInvitePreview] = useState<InvitePreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [importing, setImporting] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const importRef = useRef<HTMLTextAreaElement | null>(null);

  const ownInvite = useMemo(() => {
    if (!user || !ownFingerprint) return '';
    return createIdentityInvite(user.username, ownFingerprint);
  }, [ownFingerprint, user]);

  const refreshTrustedContacts = useCallback(() => {
    if (!user) return;
    setTrustedContacts(getTrustedIdentities(user.username));
  }, [user]);

  const loadDirectory = useCallback(async () => {
    if (!user) return;

    setLoading(true);
    try {
      const res = await fetch(apiUrl('/users'), { headers: authHeaders(user.token) });
      const data = await res.json() as DirectoryUser[];
      if (!res.ok) throw new Error('Unable to load identity directory.');

      const contacts = data.filter((entry) => entry.username !== user.username);
      const statuses = await Promise.all(contacts.map(async (identity) => [
        identity.username,
        await getTrustStatus(user.username, identity)
      ] as const));

      setDirectory(contacts);
      setTrustStatuses(Object.fromEntries(statuses));
      refreshTrustedContacts();
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to load contacts.'), 'error');
    } finally {
      setLoading(false);
    }
  }, [refreshTrustedContacts, showToast, user]);

  useEffect(() => {
    if (!user) return;

    identityFingerprint({
      username: user.username,
      identityPublicKeyECDH: user.identityPublicKeyECDH,
      identityPublicKeyECDSA: user.identityPublicKeyECDSA
    }).then(setOwnFingerprint).catch(() => setOwnFingerprint(''));
  }, [user]);

  useEffect(() => {
    loadDirectory();
  }, [loadDirectory]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const parsed = parseIdentityInvite(window.location.href);
    if (parsed.username && parsed.fingerprint) {
      setInviteText(window.location.href);
    }
  }, []);

  const handleCopyInvite = () => {
    if (!ownInvite) return;
    navigator.clipboard.writeText(ownInvite);
    showToast('Private identity invite link copied.', 'success');
  };

  const handlePreviewInvite = async () => {
    if (!user) return;

    const parsed = parseIdentityInvite(inviteText);
    if (!parsed.username || !parsed.fingerprint) {
      showToast('Paste a CrypShare invite link.', 'error');
      return;
    }

    setPreviewing(true);
    try {
      const identity = directory.find((entry) => entry.username === parsed.username);
      if (!identity) {
        setInvitePreview({
          username: parsed.username,
          pastedFingerprint: parsed.fingerprint,
          serverFingerprint: '',
          matches: false,
          alreadyTrusted: false,
          changed: false,
          error: `Identity ${parsed.username} is not discoverable. Both users must share an active workspace before trust can be verified.`
        });
        return;
      }

      const status = trustStatuses[identity.username] || await getTrustStatus(user.username, identity);
      const matches = fingerprintMatches(status.fingerprint, parsed.fingerprint);
      setInvitePreview({
        username: identity.username,
        pastedFingerprint: parsed.fingerprint,
        serverFingerprint: status.fingerprint,
        matches,
        alreadyTrusted: status.trusted,
        changed: status.changed,
        identity,
        error: matches ? undefined : 'Invite fingerprint does not match the server-published identity keys.'
      });
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to preview invite.'), 'error');
    } finally {
      setPreviewing(false);
    }
  };

  const handleTrustPreview = async () => {
    if (!user || !invitePreview?.identity || !invitePreview.matches) return;

    const identity = invitePreview.identity;
    setImporting(true);
    try {
      await trustIdentity(user.username, identity);
      setTrustStatuses((current) => ({
        ...current,
        [identity.username]: {
          fingerprint: invitePreview.serverFingerprint,
          trusted: true,
          changed: false
        }
      }));
      refreshTrustedContacts();
      setInviteText('');
      setInvitePreview(null);
      showToast(`${identity.username} added as a trusted contact.`, 'success');
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to trust contact.'), 'error');
    } finally {
      setImporting(false);
    }
  };

  const handleForgetContact = (username: string) => {
    if (!user) return;

    forgetTrustedIdentity(user.username, username);
    setTrustStatuses((current) => ({
      ...current,
      [username]: {
        fingerprint: current[username]?.fingerprint || trustedContacts[username]?.fingerprint || '',
        trusted: false,
        changed: false
      }
    }));
    refreshTrustedContacts();
    showToast(`${username} removed from trusted contacts.`, 'success');
  };

  const contactRows = useMemo(() => {
    const trustedRows = Object.values(trustedContacts).map((contact) => {
      const status = trustStatuses[contact.username];
      return {
        username: contact.username,
        fingerprint: status?.fingerprint || contact.fingerprint,
        trustedAt: contact.trustedAt,
        status,
        trusted: true,
        changed: !!status?.changed
      };
    });

    const trustedNames = new Set(trustedRows.map((contact) => contact.username));
    const directoryRows = directory
      .filter((identity) => !trustedNames.has(identity.username))
      .map((identity) => ({
        username: identity.username,
        fingerprint: trustStatuses[identity.username]?.fingerprint || '',
        trustedAt: 0,
        status: trustStatuses[identity.username],
        trusted: false,
        changed: !!trustStatuses[identity.username]?.changed
      }));

    const normalized = searchQuery.trim().toLowerCase();
    return [...trustedRows, ...directoryRows].filter((row) => {
      if (!normalized) return true;
      return `${row.username} ${row.fingerprint}`.toLowerCase().includes(normalized);
    });
  }, [directory, searchQuery, trustStatuses, trustedContacts]);

  return (
    <div className="mx-auto max-w-7xl animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="mb-2 text-3xl font-bold text-[var(--app-text)]">Contacts</h2>
          <p className="text-sm text-[var(--app-muted)]">Manage trusted identities and fingerprint verification.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ActionButton onClick={handleCopyInvite} disabled={!ownInvite}>
            <UserPlus className="h-4 w-4" /> Add Contact
          </ActionButton>
          <ActionButton
            variant="secondary"
            onClick={() => importRef.current?.focus()}
          >
            <Download className="h-4 w-4" /> Import
          </ActionButton>
          <button
            onClick={loadDirectory}
            disabled={loading}
            className="theme-toggle !p-2"
            title="Refresh contacts"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
        <GlassCard className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="font-semibold text-[var(--app-text)]">Private Identity Invite</h3>
              <p className="mt-1 text-xs text-[var(--app-muted)]">Send this through a trusted channel so a friend can verify your fingerprint.</p>
            </div>
            <ActionButton variant="secondary" onClick={handleCopyInvite} disabled={!ownInvite} className="text-xs">
              <Copy className="h-4 w-4" /> Copy
            </ActionButton>
          </div>
          <div className="mt-4 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-[var(--success-color)]" />
              <p className="text-sm font-medium text-[var(--app-text)]">{ownInvite ? 'Invite link is ready' : 'Generating invite link...'}</p>
            </div>
            <p className="mt-2 text-xs text-[var(--app-muted)]">
              New links use a private URL fragment. The server does not receive the invite payload in normal HTTP requests.
            </p>
            {ownInvite && (
              <details className="mt-3 text-xs text-[var(--app-muted)]">
                <summary className="cursor-pointer font-semibold text-[var(--brand-blue)]">Show private link</summary>
                <p className="mt-2 break-all font-mono">{ownInvite}</p>
              </details>
            )}
          </div>
        </GlassCard>

        <GlassCard className="p-5">
          <div>
            <h3 className="font-semibold text-[var(--app-text)]">Import And Verify</h3>
            <p className="mt-1 text-xs text-[var(--app-muted)]">Paste a CrypShare invite link, preview the fingerprint, then verify out-of-band before trusting.</p>
          </div>
          <textarea
            ref={importRef}
            value={inviteText}
            onChange={(event) => {
              setInviteText(event.target.value);
              setInvitePreview(null);
            }}
            placeholder="Paste CrypShare invite URL..."
            className="mt-4 min-h-24 w-full resize-none rounded-lg border border-[var(--app-border)] bg-[var(--app-field)] p-4 text-xs text-[var(--app-text)] placeholder:text-[var(--app-subtle)] focus:outline-none focus:border-[var(--brand-blue)]"
          />
          <div className="mt-3 flex justify-end">
            <ActionButton onClick={handlePreviewInvite} loading={previewing} disabled={!inviteText.trim()}>
              <ShieldQuestion className="h-4 w-4" /> Preview Verification
            </ActionButton>
          </div>
          {invitePreview && (
            <div className={`mt-4 rounded-lg border p-4 text-sm ${
              invitePreview.error
                ? 'border-[color-mix(in_srgb,var(--danger-color)_35%,var(--app-border))] bg-[color-mix(in_srgb,var(--danger-color)_10%,var(--app-surface))]'
                : 'border-[color-mix(in_srgb,var(--success-color)_35%,var(--app-border))] bg-[color-mix(in_srgb,var(--success-color)_10%,var(--app-surface))]'
            }`}>
              <div className="flex items-center gap-2 font-semibold text-[var(--app-text)]">
                {invitePreview.error ? <ShieldAlert className="h-4 w-4 text-[var(--danger-color)]" /> : <ShieldCheck className="h-4 w-4 text-[var(--success-color)]" />}
                {invitePreview.matches ? 'Fingerprint match' : 'Verification blocked'}
              </div>
              <div className="mt-3 space-y-2 text-xs">
                <p className="text-[var(--app-muted)]">Identity: <span className="font-mono text-[var(--app-text)]">{invitePreview.username}</span></p>
                <p className="break-all text-[var(--app-muted)]">Invite fingerprint: <span className="font-mono">{formatFingerprint(invitePreview.pastedFingerprint)}</span></p>
                {invitePreview.serverFingerprint && (
                  <p className="break-all text-[var(--app-muted)]">Published fingerprint: <span className="font-mono">{formatFingerprint(invitePreview.serverFingerprint)}</span></p>
                )}
                {invitePreview.error ? (
                  <p className="text-[var(--danger-color)]">{invitePreview.error}</p>
                ) : (
                  <p className="text-[var(--success-color)]">Confirm this fingerprint with your friend outside CrypShare before trusting.</p>
                )}
                {invitePreview.alreadyTrusted && (
                  <p className="text-[var(--brand-blue)]">This contact is already trusted on this browser.</p>
                )}
                {invitePreview.changed && (
                  <p className="text-[var(--danger-color)]">A previous trusted key changed. Re-verify carefully before trusting again.</p>
                )}
              </div>
              <ActionButton
                onClick={handleTrustPreview}
                loading={importing}
                disabled={!invitePreview.matches || !invitePreview.identity}
                className="mt-4 w-full"
              >
                <UserPlus className="h-4 w-4" /> Mark as Trusted
              </ActionButton>
            </div>
          )}
        </GlassCard>
      </div>

      <GlassCard className="overflow-hidden">
        <div className="flex flex-col gap-4 border-b border-[var(--app-border)] p-5 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-[var(--brand-blue)]" />
            <div>
              <h3 className="font-semibold text-[var(--app-text)]">Contacts</h3>
              <p className="text-xs text-[var(--app-muted)]">Trust status is local to this browser.</p>
            </div>
          </div>
          <div className="relative w-full md:w-80">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--app-muted)]" />
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search contacts..."
              className="w-full rounded-lg border border-[var(--app-border)] bg-[var(--app-field)] py-2 pl-10 pr-3 text-sm text-[var(--app-text)] placeholder:text-[var(--app-subtle)] focus:outline-none focus:border-[var(--brand-blue)]"
            />
          </div>
        </div>
        {contactRows.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldQuestion className="mx-auto mb-3 h-10 w-10 text-[var(--app-muted)]" />
            <p className="font-semibold text-[var(--app-text)]">No contacts found</p>
            <p className="mt-1 text-sm text-[var(--app-muted)]">Import a private invite link to trust your first contact.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-[var(--app-border)] bg-[var(--app-surface-muted)]">
                <tr>
                  <th className="px-5 py-3">Name</th>
                  <th className="px-5 py-3">Trust Status</th>
                  <th className="px-5 py-3">Fingerprint</th>
                  <th className="px-5 py-3">Added</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {contactRows.map((contact) => {
                  const changed = contact.changed;
                  const tone = changed ? 'danger' : contact.trusted ? 'success' : 'warning';
                  const statusLabel = changed ? 'Changed key' : contact.trusted ? 'Trusted' : 'Needs invite';
                  const initials = contact.username.slice(0, 2).toUpperCase();
              return (
                    <tr key={contact.username} className="border-b border-[var(--app-border)] last:border-0">
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--brand-blue)_16%,var(--app-surface))] text-xs font-bold text-[var(--brand-blue)]">
                            {initials}
                          </div>
                          <div>
                            <p className="font-medium text-[var(--app-text)]">{contact.username}</p>
                            <p className="text-xs text-[var(--app-muted)]">Workspace identity</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <StatusBadge tone={tone}>{statusLabel}</StatusBadge>
                      </td>
                      <td className="px-5 py-4">
                        <p className="max-w-[320px] truncate font-mono text-xs text-[var(--app-muted)]">
                          {contact.fingerprint ? formatFingerprint(contact.fingerprint) : 'Awaiting invite verification'}
                        </p>
                      </td>
                      <td className="px-5 py-4 text-[var(--app-muted)]">
                        {contact.trustedAt ? new Date(contact.trustedAt).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-5 py-4 text-right">
                        {contact.trusted ? (
                          <button
                            onClick={() => handleForgetContact(contact.username)}
                            className="inline-flex items-center justify-center gap-2 rounded-lg border border-[color-mix(in_srgb,var(--danger-color)_30%,var(--app-border))] px-3 py-2 text-xs font-medium text-[var(--danger-color)] hover:bg-[color-mix(in_srgb,var(--danger-color)_10%,var(--app-surface))] transition-colors"
                            title="Forget trusted contact"
                          >
                            <Trash2 className="h-4 w-4" /> Forget
                          </button>
                        ) : (
                          <StatusBadge tone={changed ? 'danger' : 'warning'}>{changed ? 'Re-verify' : 'Import invite'}</StatusBadge>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
};
