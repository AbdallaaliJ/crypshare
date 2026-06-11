import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, Download, RadioTower, Send, ShieldAlert, ShieldCheck, Wifi, WifiOff } from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { apiUrl, wsUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import type { DirectoryUser } from '../types/api';
import { bytesToHex, deriveP2PTransferKey, encryptFileData, hexToBytes, importECDSAPublicKey, signPayload, verifySignature } from '../utils/crypto';
import { getErrorMessage } from '../utils/errors';
import { formatBytes } from '../utils/uploadLimits';
import {
  fingerprintMatches,
  formatFingerprint,
  getTrustStatus,
  identityFingerprint,
  parseIdentityInvite,
  trustIdentity,
  type TrustStatus
} from '../utils/trust';

interface IceConfigResponse {
  iceServers: RTCIceServer[];
  directOnlyIceServers: RTCIceServer[];
  turnConfigured: boolean;
  sessionTtlMs: number;
  privacyNote: string;
}

interface IncomingInvite {
  sessionId: string;
  senderUsername: string;
  relayAllowed: boolean;
  expiresAt: number;
}

interface OutgoingSession {
  sessionId: string;
  recipientUsername: string;
  relayAllowed: boolean;
  file: File;
}

interface P2PMessage {
  type: string;
  sessionId?: string;
  senderUsername?: string;
  recipientUsername?: string;
  relayAllowed?: boolean;
  delivered?: boolean;
  expiresAt?: number;
  fromUsername?: string;
  signalType?: string;
  payload?: RTCSessionDescriptionInit | RTCIceCandidateInit | null;
  error?: string;
}

interface P2PHeader {
  name: string;
  type: string;
  size: number;
  chunkSize: number;
  chunkCount: number;
  createdAt: number;
}

const P2P_CHUNK_SIZE_BYTES = 64 * 1024;

function encryptedPacketSize(fileSize: number) {
  if (fileSize <= 0) return 0;
  return fileSize + Math.ceil(fileSize / P2P_CHUNK_SIZE_BYTES) * 28;
}

async function encryptBytes(key: CryptoKey, bytes: Uint8Array) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes as BufferSource);
  return {
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(ciphertext))
  };
}

async function decryptBytes(key: CryptoKey, ivHex: string, ciphertextHex: string) {
  const plaintext = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: hexToBytes(ivHex) as BufferSource },
    key,
    hexToBytes(ciphertextHex) as BufferSource
  );
  return new Uint8Array(plaintext);
}

export const P2PTransferPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [p2pIdentities, setP2PIdentities] = useState<Record<string, DirectoryUser>>({});
  const [trustStatuses, setTrustStatuses] = useState<Record<string, TrustStatus>>({});
  const [iceConfig, setIceConfig] = useState<IceConfigResponse | null>(null);
  const [socketReady, setSocketReady] = useState(false);
  const [recipientUsername, setRecipientUsername] = useState('');
  const [recipientMode, setRecipientMode] = useState<'known' | 'identity'>('known');
  const [identityInviteText, setIdentityInviteText] = useState('');
  const [identityInviteError, setIdentityInviteError] = useState('');
  const [identityInvitePreview, setIdentityInvitePreview] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [allowRelay, setAllowRelay] = useState(false);
  const [incomingInvite, setIncomingInvite] = useState<IncomingInvite | null>(null);
  const [outgoingSession, setOutgoingSession] = useState<OutgoingSession | null>(null);
  const [status, setStatus] = useState('Waiting for a P2P transfer.');
  const [progress, setProgress] = useState(0);
  const [connectionMode, setConnectionMode] = useState<'Direct' | 'Relay fallback allowed' | 'Relay in use' | 'Failed'>('Direct');
  const [activePeer, setActivePeer] = useState('');
  const socketRef = useRef<WebSocket | null>(null);
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const channelRef = useRef<RTCDataChannel | null>(null);
  const outgoingRef = useRef<OutgoingSession | null>(null);
  const incomingRef = useRef<IncomingInvite | null>(null);
  const receivedChunksRef = useRef<Blob[]>([]);
  const receivedHeaderRef = useRef<P2PHeader | null>(null);
  const receivedCountRef = useRef(0);
  const transferKeyRef = useRef<CryptoKey | null>(null);

  const findIdentity = useCallback((username: string) => users.find((entry) => entry.username === username) || p2pIdentities[username], [p2pIdentities, users]);
  const selectedRecipient = recipientMode === 'known'
    ? users.find((entry) => entry.username === recipientUsername)
    : findIdentity(recipientUsername);
  const activeTrust = activePeer ? trustStatuses[activePeer] : undefined;

  const sendSignaling = useCallback((message: Record<string, unknown>) => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error('P2P signaling is not connected.');
    }
    socket.send(JSON.stringify(message));
  }, []);

  const loadUsers = useCallback(async () => {
    if (!user) return;
    const res = await fetch(apiUrl('/users'), { headers: authHeaders(user.token) });
    const data = await res.json() as DirectoryUser[];
    if (!res.ok) throw new Error('Unable to load known users.');
    const others = data.filter((entry) => entry.username !== user.username);
    setUsers(others);
    setRecipientUsername((current) => current || others[0]?.username || '');
    const statuses = await Promise.all(others.map(async (identity) => [identity.username, await getTrustStatus(user.username, identity)] as const));
    setTrustStatuses(Object.fromEntries(statuses));
  }, [user]);

  const fetchP2PIdentity = useCallback(async (username: string) => {
    if (!user) throw new Error('Authentication required.');
    const res = await fetch(apiUrl(`/p2p/identity/${encodeURIComponent(username)}`), {
      headers: authHeaders(user.token)
    });
    const data = await res.json() as DirectoryUser & { error?: string };
    if (!res.ok) throw new Error(data.error || 'Unable to load P2P identity.');
    setP2PIdentities((current) => ({ ...current, [data.username]: data }));
    const status = await getTrustStatus(user.username, data);
    setTrustStatuses((current) => ({ ...current, [data.username]: status }));
    return { identity: data, status };
  }, [user]);

  const handleParseIdentityInvite = async () => {
    if (!user) return;
    setIdentityInviteError('');
    setIdentityInvitePreview('');
    try {
      const parsed = parseIdentityInvite(identityInviteText);
      if (!parsed.username || !parsed.fingerprint) {
        throw new Error('Paste a CrypShare identity invite with username and fingerprint.');
      }

      const { identity, status } = await fetchP2PIdentity(parsed.username);
      const actualFingerprint = await identityFingerprint(identity);
      if (!fingerprintMatches(actualFingerprint, parsed.fingerprint)) {
        throw new Error('Identity code fingerprint does not match the server-published keys.');
      }

      setRecipientMode('identity');
      setRecipientUsername(identity.username);
      setIdentityInvitePreview(`${identity.username} verified · ${formatFingerprint(status.fingerprint)}`);
      showToast(`${identity.username} identity code verified for P2P.`, 'success');
    } catch (err: unknown) {
      const message = getErrorMessage(err, 'Unable to verify identity code.');
      setIdentityInviteError(message);
      showToast(message, 'error');
    }
  };

  const handleTrustActivePeer = async () => {
    if (!user || !activePeer) return;
    const identity = findIdentity(activePeer);
    if (!identity) return;
    const record = await trustIdentity(user.username, identity);
    setTrustStatuses((current) => ({
      ...current,
      [identity.username]: {
        fingerprint: record.fingerprint,
        trusted: true,
        changed: false,
        record
      }
    }));
    showToast(`${identity.username} trusted for future P2P transfers.`, 'success');
  };

  useEffect(() => {
    if (!user) return;
    queueMicrotask(() => {
      loadUsers().catch((err) => showToast(getErrorMessage(err, 'Unable to load known users.'), 'error'));
    });
    fetch(apiUrl('/p2p/ice-config'), { headers: authHeaders(user.token) })
      .then(async (res) => {
        const data = await res.json() as IceConfigResponse & { error?: string };
        if (!res.ok) throw new Error(data.error || 'Unable to load P2P network configuration.');
        setIceConfig(data);
      })
      .catch((err) => showToast(getErrorMessage(err, 'Unable to load P2P network configuration.'), 'error'));
  }, [loadUsers, showToast, user]);

  const cleanupPeer = useCallback(() => {
    channelRef.current?.close();
    peerRef.current?.close();
    channelRef.current = null;
    peerRef.current = null;
    transferKeyRef.current = null;
  }, []);

  const updateConnectionMode = useCallback(async () => {
    const peer = peerRef.current;
    if (!peer) return;
    try {
      const stats = await peer.getStats();
      let selectedPair: RTCStats | null = null;
      stats.forEach((report) => {
        if (report.type === 'transport' && report.selectedCandidatePairId) {
          selectedPair = stats.get(report.selectedCandidatePairId) || null;
        }
      });
      if (!selectedPair) return;
      const localCandidateId = (selectedPair as RTCIceCandidatePairStats).localCandidateId;
      const localCandidate = localCandidateId ? stats.get(localCandidateId) as RTCStats | undefined : undefined;
      if ((localCandidate as RTCStats & { candidateType?: string } | undefined)?.candidateType === 'relay') {
        setConnectionMode('Relay in use');
      }
    } catch {
      // Candidate-pair stats vary by browser; the transfer still works without this label.
    }
  }, []);

  const createPeer = useCallback((sessionId: string, relayAllowed: boolean) => {
    if (!iceConfig) throw new Error('P2P network configuration is not ready.');
    cleanupPeer();
    setConnectionMode(relayAllowed ? 'Relay fallback allowed' : 'Direct');
    const peer = new RTCPeerConnection({
      iceServers: relayAllowed ? iceConfig.iceServers : iceConfig.directOnlyIceServers
    });
    peerRef.current = peer;
    peer.onicecandidate = (event) => {
      if (event.candidate) {
        sendSignaling({
          type: 'p2p-signal',
          sessionId,
          signalType: 'ice',
          payload: event.candidate.toJSON()
        });
      }
    };
    peer.oniceconnectionstatechange = () => {
      if (peer.iceConnectionState === 'connected' || peer.iceConnectionState === 'completed') {
        updateConnectionMode();
      }
      if (peer.iceConnectionState === 'failed') {
        setConnectionMode('Failed');
        sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'failed', payload: null });
      }
    };
    return peer;
  }, [cleanupPeer, iceConfig, sendSignaling, updateConnectionMode]);

  const sendEncryptedFile = useCallback(async (session: OutgoingSession, channel: RTCDataChannel) => {
    if (!user?.privateKeyECDH || !user.privateKeyECDSA) throw new Error('Identity keys are locked.');
    const recipient = findIdentity(session.recipientUsername);
    if (!recipient) throw new Error('Recipient identity is unavailable.');

    const transferKey = await deriveP2PTransferKey(user.privateKeyECDH, recipient.identityPublicKeyECDH, session.sessionId);
    const header: P2PHeader = {
      name: session.file.name,
      type: session.file.type || 'application/octet-stream',
      size: session.file.size,
      chunkSize: P2P_CHUNK_SIZE_BYTES,
      chunkCount: Math.ceil(session.file.size / P2P_CHUNK_SIZE_BYTES),
      createdAt: Date.now()
    };
    const encryptedHeader = await encryptFileData(transferKey, JSON.stringify(header));
    const signaturePayload = `${session.sessionId}:${session.recipientUsername}:${encryptedHeader.iv}:${encryptedHeader.ciphertext}`;
    const signature = await signPayload(user.privateKeyECDSA, signaturePayload);

    channel.send(JSON.stringify({
      kind: 'header',
      iv: encryptedHeader.iv,
      ciphertext: encryptedHeader.ciphertext,
      signature,
      senderUsername: user.username
    }));

    let offset = 0;
    let index = 0;
    setStatus('Sending encrypted chunks directly to peer...');
    while (offset < session.file.size) {
      while (channel.bufferedAmount > 4 * 1024 * 1024) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const plain = new Uint8Array(await session.file.slice(offset, offset + P2P_CHUNK_SIZE_BYTES).arrayBuffer());
      const encrypted = await encryptBytes(transferKey, plain);
      channel.send(JSON.stringify({
        kind: 'chunk',
        index,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext
      }));
      offset += P2P_CHUNK_SIZE_BYTES;
      index += 1;
      setProgress(Math.round((offset / session.file.size) * 100));
    }

    channel.send(JSON.stringify({ kind: 'done' }));
    setStatus('Encrypted P2P file transfer completed.');
  }, [findIdentity, user]);

  const startSenderPeer = useCallback(async (session: OutgoingSession) => {
    const peer = createPeer(session.sessionId, session.relayAllowed);
    const channel = peer.createDataChannel('crypshare-p2p-file', { ordered: true });
    channelRef.current = channel;
    channel.onopen = () => {
      sendEncryptedFile(session, channel).catch((err) => {
        setStatus(getErrorMessage(err, 'P2P send failed.'));
        sendSignaling({ type: 'p2p-signal', sessionId: session.sessionId, signalType: 'failed', payload: null });
      });
    };
    channel.onclose = () => setStatus('P2P data channel closed.');

    const offer = await peer.createOffer();
    await peer.setLocalDescription(offer);
    sendSignaling({
      type: 'p2p-signal',
      sessionId: session.sessionId,
      signalType: 'offer',
      payload: offer
    });
    setStatus('P2P invite accepted. Negotiating direct connection...');
  }, [createPeer, sendEncryptedFile, sendSignaling]);

  const handleIncomingData = useCallback(async (sessionId: string, senderUsername: string, event: MessageEvent<string>) => {
    if (!user?.privateKeyECDH) return;
    const sender = findIdentity(senderUsername);
    if (!sender) {
      setStatus('Sender identity is unavailable. Transfer blocked.');
      return;
    }

    const packet = JSON.parse(event.data) as {
      kind: string;
      iv?: string;
      ciphertext?: string;
      signature?: string;
      index?: number;
    };

    if (packet.kind === 'header' && packet.iv && packet.ciphertext && packet.signature) {
      const signingKey = await importECDSAPublicKey(sender.identityPublicKeyECDSA);
      const valid = await verifySignature(signingKey, packet.signature, `${sessionId}:${user.username}:${packet.iv}:${packet.ciphertext}`);
      if (!valid) {
        setStatus('P2P sender signature verification failed.');
        sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'failed', payload: null });
        return;
      }
      const transferKey = await deriveP2PTransferKey(user.privateKeyECDH, sender.identityPublicKeyECDH, sessionId);
      transferKeyRef.current = transferKey;
      const headerBytes = await decryptBytes(transferKey, packet.iv, packet.ciphertext);
      const header = JSON.parse(new TextDecoder().decode(headerBytes)) as P2PHeader;
      receivedHeaderRef.current = header;
      receivedChunksRef.current = new Array(header.chunkCount);
      receivedCountRef.current = 0;
      setProgress(0);
      setStatus(`Receiving encrypted file directly. ${formatBytes(header.size)} expected.`);
      return;
    }

    if (packet.kind === 'chunk' && packet.iv && packet.ciphertext && typeof packet.index === 'number') {
      const transferKey = transferKeyRef.current;
      const header = receivedHeaderRef.current;
      if (!transferKey || !header) return;
      const plainBytes = await decryptBytes(transferKey, packet.iv, packet.ciphertext);
      if (!receivedChunksRef.current[packet.index]) {
        receivedChunksRef.current[packet.index] = new Blob([plainBytes], { type: header.type });
        receivedCountRef.current += 1;
      }
      setProgress(Math.round((receivedCountRef.current / header.chunkCount) * 100));
      return;
    }

    if (packet.kind === 'done') {
      const header = receivedHeaderRef.current;
      if (!header) return;
      const blob = new Blob(receivedChunksRef.current, { type: header.type });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = header.name || 'crypshare-p2p-file';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus('P2P file received and downloaded. Nothing was stored in CrypShare.');
      sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'completed', payload: null });
      cleanupPeer();
    }
  }, [cleanupPeer, findIdentity, sendSignaling, user]);

  const startReceiverPeer = useCallback(async (invite: IncomingInvite, offer: RTCSessionDescriptionInit) => {
    const peer = createPeer(invite.sessionId, invite.relayAllowed);
    peer.ondatachannel = (event) => {
      const channel = event.channel;
      channelRef.current = channel;
      channel.onmessage = (messageEvent) => {
        handleIncomingData(invite.sessionId, invite.senderUsername, messageEvent as MessageEvent<string>).catch((err) => {
          setStatus(getErrorMessage(err, 'Unable to receive P2P file.'));
          sendSignaling({ type: 'p2p-signal', sessionId: invite.sessionId, signalType: 'failed', payload: null });
        });
      };
    };
    await peer.setRemoteDescription(offer);
    const answer = await peer.createAnswer();
    await peer.setLocalDescription(answer);
    sendSignaling({
      type: 'p2p-signal',
      sessionId: invite.sessionId,
      signalType: 'answer',
      payload: answer
    });
    setStatus('Accepted P2P invite. Waiting for encrypted file stream...');
  }, [createPeer, handleIncomingData, sendSignaling]);

  const handleSignal = useCallback(async (message: P2PMessage) => {
    if (!message.sessionId || !message.signalType) return;
    if (message.signalType === 'offer') {
      const invite = incomingRef.current;
      if (!invite || invite.sessionId !== message.sessionId || !message.payload) return;
      await startReceiverPeer(invite, message.payload as RTCSessionDescriptionInit);
      return;
    }
    if (message.signalType === 'answer' && peerRef.current && message.payload) {
      await peerRef.current.setRemoteDescription(message.payload as RTCSessionDescriptionInit);
      setStatus('P2P connection established. Sending encrypted data...');
      return;
    }
    if (message.signalType === 'ice' && peerRef.current && message.payload) {
      await peerRef.current.addIceCandidate(message.payload as RTCIceCandidateInit);
      return;
    }
    if (message.signalType === 'completed') {
      setStatus('Peer confirmed P2P transfer completed.');
      cleanupPeer();
      return;
    }
    if (message.signalType === 'failed') {
      setConnectionMode('Failed');
      setStatus('Peer reported that P2P transfer failed.');
      cleanupPeer();
    }
  }, [cleanupPeer, startReceiverPeer]);

  useEffect(() => {
    if (!user?.token) return;
    const socket = new WebSocket(wsUrl(`/p2p/signaling?token=${encodeURIComponent(user.token)}`));
    socketRef.current = socket;
    socket.onopen = () => setSocketReady(true);
    socket.onclose = () => {
      setSocketReady(false);
      setStatus('P2P signaling disconnected.');
    };
    socket.onerror = () => setStatus('P2P signaling error.');
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data) as P2PMessage;
      if (message.type === 'p2p-invite' && message.sessionId && message.senderUsername && message.expiresAt) {
        const invite = {
          sessionId: message.sessionId,
          senderUsername: message.senderUsername,
          relayAllowed: message.relayAllowed === true,
          expiresAt: message.expiresAt
        };
        incomingRef.current = invite;
        setIncomingInvite(invite);
        setActivePeer(invite.senderUsername);
        setStatus(`Incoming P2P request from ${invite.senderUsername}.`);
        fetchP2PIdentity(invite.senderUsername).catch((err) => {
          setStatus(getErrorMessage(err, 'Unable to verify incoming P2P sender identity.'));
        });
      }
      if (message.type === 'p2p-invite-created' && message.sessionId && selectedFile) {
        const session = {
          sessionId: message.sessionId,
          recipientUsername,
          relayAllowed: allowRelay,
          file: selectedFile
        };
        outgoingRef.current = session;
        setOutgoingSession(session);
        setActivePeer(recipientUsername);
        setStatus(message.delivered ? 'P2P invite delivered. Waiting for recipient.' : 'P2P invite created, but recipient is not online.');
      }
      if (message.type === 'p2p-accepted' && message.sessionId) {
        const session = outgoingRef.current;
        if (session?.sessionId === message.sessionId) {
          startSenderPeer(session).catch((err) => setStatus(getErrorMessage(err, 'Unable to start P2P sender.')));
        }
      }
      if (message.type === 'p2p-declined') {
        setStatus('Recipient declined the P2P transfer.');
        cleanupPeer();
      }
      if (message.type === 'p2p-expired') {
        setStatus('P2P session expired.');
        cleanupPeer();
      }
      if (message.type === 'p2p-signal') {
        handleSignal(message).catch((err) => setStatus(getErrorMessage(err, 'P2P signaling failed.')));
      }
      if (message.type === 'p2p-error') {
        setStatus(message.error || 'P2P signaling error.');
      }
    };
    return () => {
      socket.close();
      cleanupPeer();
    };
  }, [allowRelay, cleanupPeer, fetchP2PIdentity, handleSignal, recipientUsername, selectedFile, startSenderPeer, user?.token]);

  const handleSendInvite = () => {
    if (!selectedRecipient || !selectedFile) {
      showToast('Choose a recipient and file first.', 'error');
      return;
    }
    setProgress(0);
    setActivePeer(selectedRecipient.username);
    sendSignaling({
      type: 'p2p-invite',
      recipientUsername: selectedRecipient.username,
      relayAllowed: allowRelay
    });
  };

  const handleAcceptInvite = () => {
    if (!incomingInvite) return;
    sendSignaling({ type: 'p2p-accept', sessionId: incomingInvite.sessionId });
    setStatus('P2P invite accepted. Waiting for sender connection offer...');
    setIncomingInvite(null);
  };

  const handleDeclineInvite = () => {
    if (!incomingInvite) return;
    sendSignaling({ type: 'p2p-decline', sessionId: incomingInvite.sessionId });
    setIncomingInvite(null);
    setStatus('P2P invite declined.');
  };

  const relayCopy = allowRelay
    ? 'Relay fallback is allowed. TURN can observe IP/timing/packet sizes, but file metadata and chunks are encrypted before transfer.'
    : 'Direct-only mode. CrypShare will not relay file bytes, but strict networks may fail to connect.';

  const transferEstimate = useMemo(() => selectedFile ? encryptedPacketSize(selectedFile.size) : 0, [selectedFile]);

  return (
    <div className="max-w-6xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">P2P Transfer</h2>
          <p className="text-slate-400">One-time browser-to-browser transfer. CrypShare signals the connection, not the file.</p>
        </div>
        <div className={`inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-xs font-bold ${
          socketReady ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300' : 'border-red-500/20 bg-red-500/10 text-red-300'
        }`}>
          {socketReady ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
          {socketReady ? 'Signaling online' : 'Signaling offline'}
        </div>
      </div>

      <div className="grid lg:grid-cols-[1.2fr_0.8fr] gap-6">
        <GlassCard className="p-6 space-y-5">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <RadioTower className="w-5 h-5 text-cyan-300" />
            </div>
            <div>
              <h3 className="text-white font-bold">Send Directly</h3>
              <p className="text-xs text-slate-500">Recipient must be online and must accept before bytes move.</p>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div className="block">
              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Recipient</span>
              <div className="mt-2 grid grid-cols-2 rounded-xl border border-white/10 bg-black/20 p-1">
                <button
                  type="button"
                  onClick={() => setRecipientMode('known')}
                  className={`rounded-lg px-3 py-2 text-xs font-bold transition-colors ${recipientMode === 'known' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
                >
                  Known User
                </button>
                <button
                  type="button"
                  onClick={() => setRecipientMode('identity')}
                  className={`rounded-lg px-3 py-2 text-xs font-bold transition-colors ${recipientMode === 'identity' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
                >
                  Identity Code
                </button>
              </div>

              {recipientMode === 'known' ? (
                <select
                  value={recipientUsername}
                  onChange={(event) => setRecipientUsername(event.target.value)}
                  className="mt-3 w-full bg-black/30 border border-white/10 rounded-xl px-3 py-3 text-sm text-white focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="">Choose known user...</option>
                  {users.map((entry) => (
                    <option key={entry.username} value={entry.username}>{entry.username}</option>
                  ))}
                </select>
              ) : (
                <div className="mt-3 space-y-3">
                  <textarea
                    value={identityInviteText}
                    onChange={(event) => setIdentityInviteText(event.target.value)}
                    placeholder="Paste CrypShare identity invite..."
                    rows={5}
                    className="w-full bg-black/30 border border-white/10 rounded-xl px-3 py-3 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
                  />
                  <ActionButton
                    variant="secondary"
                    onClick={handleParseIdentityInvite}
                    disabled={!identityInviteText.trim()}
                    className="w-full text-xs"
                  >
                    Verify Identity Code
                  </ActionButton>
                  {identityInvitePreview && <p className="text-xs text-emerald-300">{identityInvitePreview}</p>}
                  {identityInviteError && <p className="text-xs text-red-300">{identityInviteError}</p>}
                </div>
              )}
            </div>

            <label className="block">
              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">File</span>
              <div className="mt-2 relative rounded-xl border border-dashed border-white/10 bg-black/20 px-3 py-3 min-h-[48px]">
                <input
                  type="file"
                  className="absolute inset-0 opacity-0 cursor-pointer"
                  onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
                />
                <p className="text-sm text-white truncate">{selectedFile?.name || 'Choose one file...'}</p>
              </div>
            </label>
          </div>

          <div className="rounded-xl border border-white/5 bg-black/20 p-4 space-y-3">
            <label className="flex items-start gap-3">
              <input
                type="checkbox"
                checked={allowRelay}
                onChange={(event) => setAllowRelay(event.target.checked)}
                disabled={!iceConfig?.turnConfigured}
                className="mt-1"
              />
              <span>
                <span className="block text-sm text-white font-medium">Allow TURN relay fallback</span>
                <span className="block text-xs text-slate-500">{iceConfig?.turnConfigured ? relayCopy : 'TURN is not configured. Direct STUN-assisted P2P only.'}</span>
              </span>
            </label>
            {selectedFile && (
              <p className="text-xs text-slate-500">
                {formatBytes(selectedFile.size)} selected. App-layer encrypted P2P payload is about {formatBytes(transferEstimate)}.
              </p>
            )}
          </div>

          {selectedRecipient && trustStatuses[selectedRecipient.username] && !trustStatuses[selectedRecipient.username].trusted && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-100">
              <p className="font-semibold flex items-center gap-2"><ShieldAlert className="w-4 h-4" /> Recipient fingerprint is not locally trusted.</p>
              <p className="mt-2 font-mono text-xs break-all">{formatFingerprint(trustStatuses[selectedRecipient.username].fingerprint)}</p>
            </div>
          )}

          <ActionButton onClick={handleSendInvite} disabled={!socketReady || !selectedFile || !selectedRecipient} className="w-full">
            <Send className="w-4 h-4" /> Send P2P Invite
          </ActionButton>
        </GlassCard>

        <div className="space-y-6">
          <GlassCard className="p-6 space-y-4">
            <h3 className="text-white font-bold flex items-center gap-2">
              <Download className="w-4 h-4 text-cyan-300" /> Incoming Request
            </h3>
            {incomingInvite ? (
              <div className="space-y-4">
                <div className={`rounded-xl border p-4 ${
                  activeTrust?.trusted ? 'border-emerald-500/20 bg-emerald-500/10' : 'border-amber-500/20 bg-amber-500/10'
                }`}>
                  <p className="text-sm text-white font-medium flex items-center gap-2">
                    {activeTrust?.trusted ? <ShieldCheck className="w-4 h-4 text-emerald-300" /> : <AlertTriangle className="w-4 h-4 text-amber-300" />}
                    {incomingInvite.senderUsername}
                  </p>
                  <p className="text-xs text-slate-400 mt-2">
                    {activeTrust?.trusted ? 'Verified trusted sender.' : 'Untrusted identity. You may accept once or trust this sender for future transfers.'}
                  </p>
                  {activeTrust && <p className="font-mono text-[11px] text-slate-300 break-all mt-2">{formatFingerprint(activeTrust.fingerprint)}</p>}
                  {activePeer && activeTrust && !activeTrust.trusted && (
                    <ActionButton variant="secondary" onClick={handleTrustActivePeer} className="mt-3 text-xs">
                      Trust Sender
                    </ActionButton>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <ActionButton variant="secondary" onClick={handleDeclineInvite}>Decline</ActionButton>
                  <ActionButton onClick={handleAcceptInvite}>Accept</ActionButton>
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-500">No incoming P2P request.</p>
            )}
          </GlassCard>

          <GlassCard className="p-6 space-y-4">
            <h3 className="text-white font-bold flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-300" /> Transfer Status
            </h3>
            <div className="rounded-xl border border-white/5 bg-black/20 p-4">
              <p className="text-sm text-slate-300">{status}</p>
              <p className="text-xs text-slate-500 mt-2">Connection mode: {connectionMode}</p>
              {outgoingSession && <p className="text-xs text-slate-500 mt-1">Session: {outgoingSession.sessionId}</p>}
            </div>
            <div className="h-2 rounded-full bg-white/5 overflow-hidden">
              <div className="h-full bg-cyan-400 transition-all" style={{ width: `${progress}%` }} />
            </div>
            <p className="text-xs text-slate-500">
              P2P download-only mode does not add received files to CrypShare Vault.
            </p>
          </GlassCard>
        </div>
      </div>
    </div>
  );
};
