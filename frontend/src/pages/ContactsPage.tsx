import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Copy, RefreshCw, ShieldAlert, ShieldCheck, ShieldQuestion, Trash2, UserPlus, Users } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
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

  const handleCopyInvite = () => {
    if (!ownInvite) return;
    navigator.clipboard.writeText(ownInvite);
    showToast('Identity invite copied.', 'success');
  };

  const handlePreviewInvite = async () => {
    if (!user) return;

    const parsed = parseIdentityInvite(inviteText);
    if (!parsed.username || !parsed.fingerprint) {
      showToast('Paste an invite with username and fingerprint.', 'error');
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

  return (
    <div className="max-w-5xl mx-auto py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Contacts</h2>
          <p className="text-slate-400">Verify identity fingerprints before sharing encrypted files.</p>
        </div>
        <button
          onClick={loadDirectory}
          disabled={loading}
          className="p-3 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10 transition-colors disabled:opacity-50"
          title="Refresh contacts"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 mb-6">
        <GlassCard className="p-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-white font-semibold">Your Identity Invite</h3>
              <p className="text-xs text-slate-500 mt-1">Send this through a trusted channel so a friend can verify you.</p>
            </div>
            <ActionButton variant="secondary" onClick={handleCopyInvite} disabled={!ownInvite} className="text-xs">
              <Copy className="w-4 h-4" /> Copy
            </ActionButton>
          </div>
          <pre className="min-h-32 whitespace-pre-wrap break-all rounded-xl border border-white/5 bg-black/30 p-4 text-xs text-slate-300">
            {ownInvite || 'Generating invite...'}
          </pre>
        </GlassCard>

        <GlassCard className="p-6 space-y-4">
          <div>
            <h3 className="text-white font-semibold">Verify Friend Invite</h3>
            <p className="text-xs text-slate-500 mt-1">Paste an identity invite or secure workspace invite package.</p>
          </div>
          <textarea
            value={inviteText}
            onChange={(event) => {
              setInviteText(event.target.value);
              setInvitePreview(null);
            }}
            placeholder="Paste CrypShare invite..."
            className="min-h-32 w-full resize-none rounded-xl border border-white/5 bg-black/30 p-4 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
          />
          <ActionButton onClick={handlePreviewInvite} loading={previewing} disabled={!inviteText.trim()} className="w-full">
            <ShieldQuestion className="w-4 h-4" /> Preview Verification
          </ActionButton>
          {invitePreview && (
            <div className={`rounded-xl border p-4 text-sm ${
              invitePreview.error
                ? 'border-red-500/20 bg-red-500/10'
                : 'border-emerald-500/20 bg-emerald-500/10'
            }`}>
              <div className="flex items-center gap-2 text-white font-semibold">
                {invitePreview.error ? <ShieldAlert className="w-4 h-4 text-red-300" /> : <ShieldCheck className="w-4 h-4 text-emerald-300" />}
                {invitePreview.matches ? 'Fingerprint match' : 'Verification blocked'}
              </div>
              <div className="mt-3 space-y-2 text-xs">
                <p className="text-slate-300">Invite username: <span className="font-mono text-white">{invitePreview.username}</span></p>
                <p className="text-slate-400 break-all">Invite fingerprint: <span className="font-mono">{formatFingerprint(invitePreview.pastedFingerprint)}</span></p>
                {invitePreview.serverFingerprint && (
                  <p className="text-slate-400 break-all">Server fingerprint: <span className="font-mono">{formatFingerprint(invitePreview.serverFingerprint)}</span></p>
                )}
                {invitePreview.error ? (
                  <p className="text-red-200">{invitePreview.error}</p>
                ) : (
                  <p className="text-emerald-100">Confirm this fingerprint with your friend outside CrypShare before trusting.</p>
                )}
                {invitePreview.alreadyTrusted && (
                  <p className="text-cyan-200">This contact is already trusted on this browser.</p>
                )}
                {invitePreview.changed && (
                  <p className="text-red-200">A previous trusted key changed. Re-verify carefully before trusting again.</p>
                )}
              </div>
              <ActionButton
                onClick={handleTrustPreview}
                loading={importing}
                disabled={!invitePreview.matches || !invitePreview.identity}
                className="w-full mt-4"
              >
                <UserPlus className="w-4 h-4" /> Trust Contact
              </ActionButton>
            </div>
          )}
        </GlassCard>
      </div>

      <GlassCard className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Users className="w-5 h-5 text-cyan-400" />
          <h3 className="text-white font-semibold">Trusted Contacts</h3>
        </div>
        {Object.values(trustedContacts).length === 0 ? (
          <p className="text-sm text-slate-500">No trusted contacts yet.</p>
        ) : (
          <div className="grid gap-3">
            {Object.values(trustedContacts).map((contact) => {
              const status = trustStatuses[contact.username];
              const changed = status?.changed;
              return (
                <div key={contact.username} className="flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/20 p-4">
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium text-white">
                      {changed ? <ShieldAlert className="w-4 h-4 text-red-400" /> : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
                      {contact.username}
                    </p>
                    <p className="mt-1 font-mono text-xs text-slate-500 break-all">
                      {formatFingerprint(status?.fingerprint || contact.fingerprint)}
                    </p>
                    {changed && (
                      <p className="mt-2 text-xs text-red-300">Published keys changed. Re-verify with a new invite before sharing.</p>
                    )}
                  </div>
                  <button
                    onClick={() => handleForgetContact(contact.username)}
                    className="inline-flex items-center justify-center gap-2 rounded-xl border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-200 hover:bg-red-500/20 transition-colors"
                    title="Forget trusted contact"
                  >
                    <Trash2 className="w-4 h-4" /> Forget
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </GlassCard>

      <div className="mt-6 grid gap-3">
        {directory.map((identity) => {
          const status = trustStatuses[identity.username];
          if (status?.trusted) return null;
          return (
            <div key={identity.username} className="flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-xl border border-white/5 bg-slate-900/40 p-4">
              <div className="min-w-0">
                <p className="flex items-center gap-2 text-sm font-medium text-white">
                  {status?.changed ? <ShieldAlert className="w-4 h-4 text-red-400" /> : <ShieldQuestion className="w-4 h-4 text-amber-400" />}
                  {identity.username}
                </p>
                <p className="mt-1 font-mono text-xs text-slate-500 break-all">
                  {status ? formatFingerprint(status.fingerprint) : 'Calculating fingerprint...'}
                </p>
              </div>
              <span className={`shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold ${
                status?.changed
                  ? 'border-red-500/20 bg-red-500/10 text-red-300'
                  : 'border-amber-500/20 bg-amber-500/10 text-amber-300'
              }`}>
                {status?.changed ? 'Changed' : 'Needs Invite'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
