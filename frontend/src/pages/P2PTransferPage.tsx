import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckCircle2,
  Circle,
  Download,
  FileUp,
  KeyRound,
  LockKeyhole,
  RadioTower,
  Send,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Wifi,
  WifiOff,
  XCircle
} from 'lucide-react';
import { ActionButton } from '../components/ui/ActionButton';
import { GlassCard } from '../components/ui/GlassCard';
import { StatusBadge } from '../components/ui/StatusBadge';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { useP2P } from '../hooks/useP2P';
import type { P2PMessage, PendingP2PInvite } from '../contexts/P2PContextBase';
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
  turnConfigured: boolean;
  relayOnly?: boolean;
  sessionTtlMs: number;
  privacyNote: string;
}

interface IncomingInvite {
  sessionId: string;
  senderUsername: string;
  senderFingerprint?: string;
  relayAllowed: boolean;
  expiresAt: number;
}

interface OutgoingSession {
  sessionId: string;
  recipientUsername: string;
  relayAllowed: boolean;
  file: File;
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
const P2P_FRAME_KIND_CHUNK = 1;

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

function createChunkFrame(index: number, ivHex: string, ciphertextHex: string) {
  const iv = hexToBytes(ivHex);
  const ciphertext = hexToBytes(ciphertextHex);
  const frame = new Uint8Array(1 + 4 + iv.length + ciphertext.length);
  const view = new DataView(frame.buffer);
  view.setUint8(0, P2P_FRAME_KIND_CHUNK);
  view.setUint32(1, index);
  frame.set(iv, 5);
  frame.set(ciphertext, 17);
  return frame.buffer;
}

function parseChunkFrame(frame: ArrayBuffer) {
  const bytes = new Uint8Array(frame);
  const view = new DataView(frame);
  if (bytes.byteLength < 18 || view.getUint8(0) !== P2P_FRAME_KIND_CHUNK) return null;
  return {
    index: view.getUint32(1),
    iv: bytesToHex(bytes.slice(5, 17)),
    ciphertext: bytesToHex(bytes.slice(17))
  };
}

function countSdpCandidates(description: RTCSessionDescription | null) {
  return description?.sdp?.split('\n').filter((line) => line.trim().startsWith('a=candidate:')).length || 0;
}

function noIceCandidateMessage(relayAllowed: boolean, turnConfigured: boolean) {
  if (relayAllowed && turnConfigured) {
    return 'No TURN relay candidates were gathered. The local TURN service is not reachable, credentials are wrong, or the browser/network is blocking TURN/WebRTC.';
  }
  if (turnConfigured) {
    return 'No TURN relay candidates were gathered. Check the TURN server, credentials, and firewall rules.';
  }
  return 'TURN relay is not configured. P2P is relay-only for privacy, so configure TURN before starting a transfer.';
}

export const P2PTransferPage: React.FC = () => {
  const { user } = useAuth();
  const { showToast } = useToast();
  const { socketReady, pendingInvites, sendSignaling, subscribeMessages, markInviteRead, removeInvite } = useP2P();
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [p2pIdentities, setP2PIdentities] = useState<Record<string, DirectoryUser>>({});
  const [trustStatuses, setTrustStatuses] = useState<Record<string, TrustStatus>>({});
  const [iceConfig, setIceConfig] = useState<IceConfigResponse | null>(null);
  const [recipientUsername, setRecipientUsername] = useState('');
  const [recipientMode, setRecipientMode] = useState<'known' | 'identity'>('known');
  const [identityInviteText, setIdentityInviteText] = useState('');
  const [identityInviteError, setIdentityInviteError] = useState('');
  const [identityInvitePreview, setIdentityInvitePreview] = useState('');
  const [recipientInviteFingerprint, setRecipientInviteFingerprint] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [incomingInvite, setIncomingInvite] = useState<IncomingInvite | null>(null);
  const [outgoingSession, setOutgoingSession] = useState<OutgoingSession | null>(null);
  const [status, setStatus] = useState('Waiting for a P2P transfer.');
  const [diagnostics, setDiagnostics] = useState<string[]>([]);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [progress, setProgress] = useState(0);
  const [connectionMode, setConnectionMode] = useState<'TURN relay only' | 'Relay in use' | 'Failed'>('TURN relay only');
  const [activePeer, setActivePeer] = useState('');
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const channelRef = useRef<RTCDataChannel | null>(null);
  const pendingIceRef = useRef<RTCIceCandidateInit[]>([]);
  const outgoingRef = useRef<OutgoingSession | null>(null);
  const pendingAcceptedSessionIdRef = useRef('');
  const incomingRef = useRef<IncomingInvite | null>(null);
  const selectedFileRef = useRef<File | null>(null);
  const recipientUsernameRef = useRef('');
  const fetchP2PIdentityRef = useRef<(username: string, fingerprint?: string) => Promise<{ identity: DirectoryUser; status: TrustStatus }>>(
    async () => {
      throw new Error('P2P identity loader is not ready.');
    }
  );
  const startSenderPeerRef = useRef<((session: OutgoingSession) => Promise<void>) | null>(null);
  const handleSignalRef = useRef<((message: P2PMessage) => Promise<void>) | null>(null);
  const receivedChunksRef = useRef<Blob[]>([]);
  const receivedHeaderRef = useRef<P2PHeader | null>(null);
  const receivedCountRef = useRef(0);
  const transferKeyRef = useRef<CryptoKey | null>(null);
  const streamTimeoutRef = useRef<number | null>(null);

  const findIdentity = useCallback((username: string) => users.find((entry) => entry.username === username) || p2pIdentities[username], [p2pIdentities, users]);
  const selectedRecipient = recipientMode === 'known'
    ? users.find((entry) => entry.username === recipientUsername)
    : findIdentity(recipientUsername);
  const activeTrust = activePeer ? trustStatuses[activePeer] : undefined;

  const addDiagnostic = useCallback((message: string) => {
    const stamp = new Date().toLocaleTimeString();
    setDiagnostics((current) => [`${stamp} ${message}`, ...current].slice(0, 10));
  }, []);

  const clearStreamTimeout = useCallback(() => {
    if (streamTimeoutRef.current) {
      window.clearTimeout(streamTimeoutRef.current);
      streamTimeoutRef.current = null;
    }
  }, []);

  const startStreamTimeout = useCallback((sessionId: string, label: string) => {
    clearStreamTimeout();
    streamTimeoutRef.current = window.setTimeout(() => {
      setConnectionMode('Failed');
      setStatus(`${label} timed out before encrypted data arrived. TURN relay connectivity may be blocked or misconfigured.`);
      addDiagnostic('Timed out before encrypted data arrived.');
      try {
        sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'failed', payload: null });
      } catch {
        // The socket may already be closed after a network failure.
      }
    }, 30_000);
  }, [addDiagnostic, clearStreamTimeout, sendSignaling]);

  const loadUsers = useCallback(async () => {
    if (!user) return;
    const res = await fetch(apiUrl('/users'), { headers: authHeaders(user.token), cache: 'no-store' });
    const data = await res.json() as DirectoryUser[];
    if (!res.ok) throw new Error('Unable to load known users.');
    const others = data.filter((entry) => entry.username !== user.username);
    setUsers(others);
    setRecipientUsername((current) => current || others[0]?.username || '');
    const statuses = await Promise.all(others.map(async (identity) => [identity.username, await getTrustStatus(user.username, identity)] as const));
    setTrustStatuses(Object.fromEntries(statuses));
  }, [user]);

  const fetchP2PIdentity = useCallback(async (username: string, fingerprint?: string) => {
    if (!user) throw new Error('Authentication required.');
    const query = fingerprint ? `?fingerprint=${encodeURIComponent(fingerprint)}` : '';
    const res = await fetch(apiUrl(`/p2p/identity/${encodeURIComponent(username)}${query}`), {
      headers: authHeaders(user.token),
      cache: 'no-store'
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
        throw new Error('Paste a CrypShare identity invite URL with username and fingerprint.');
      }

      const { identity, status } = await fetchP2PIdentity(parsed.username, parsed.fingerprint);
      const actualFingerprint = await identityFingerprint(identity);
      if (!fingerprintMatches(actualFingerprint, parsed.fingerprint)) {
        throw new Error('Identity invite fingerprint does not match the server-published keys.');
      }

      setRecipientMode('identity');
      setRecipientUsername(identity.username);
      setRecipientInviteFingerprint(parsed.fingerprint);
      setIdentityInvitePreview(`${identity.username} verified · ${formatFingerprint(status.fingerprint)}`);
      showToast(`${identity.username} identity invite verified for P2P.`, 'success');
    } catch (err: unknown) {
      const message = getErrorMessage(err, 'Unable to verify identity invite.');
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
    selectedFileRef.current = selectedFile;
  }, [selectedFile]);

  useEffect(() => {
    recipientUsernameRef.current = recipientUsername;
  }, [recipientUsername]);

  useEffect(() => {
    fetchP2PIdentityRef.current = fetchP2PIdentity;
  }, [fetchP2PIdentity]);

  useEffect(() => {
    if (!user) return;
    queueMicrotask(() => {
      loadUsers().catch((err) => showToast(getErrorMessage(err, 'Unable to load known users.'), 'error'));
    });
    fetch(apiUrl('/p2p/ice-config'), { headers: authHeaders(user.token), cache: 'no-store' })
      .then(async (res) => {
        const data = await res.json() as IceConfigResponse & { error?: string };
        if (!res.ok) throw new Error(data.error || 'Unable to load P2P network configuration.');
        setIceConfig(data);
      })
      .catch((err) => showToast(getErrorMessage(err, 'Unable to load P2P network configuration.'), 'error'));
  }, [loadUsers, showToast, user]);

  const cleanupPeer = useCallback(() => {
    clearStreamTimeout();
    channelRef.current?.close();
    peerRef.current?.close();
    channelRef.current = null;
    peerRef.current = null;
    pendingIceRef.current = [];
    transferKeyRef.current = null;
  }, [clearStreamTimeout]);

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

  const createPeer = useCallback((sessionId: string) => {
    if (!iceConfig) throw new Error('P2P network configuration is not ready.');
    const queuedRemoteIce = pendingIceRef.current;
    cleanupPeer();
    pendingIceRef.current = queuedRemoteIce;
    if (!iceConfig.turnConfigured || iceConfig.iceServers.length === 0) {
      throw new Error('TURN relay is not configured. P2P is relay-only for privacy.');
    }
    setConnectionMode('TURN relay only');
    addDiagnostic('Creating WebRTC peer (TURN relay only).');
    const iceServers = iceConfig.iceServers;
    addDiagnostic(`ICE servers loaded: ${iceServers.length}.`);
    const peer = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: 'relay',
      iceCandidatePoolSize: 4
    });
    peerRef.current = peer;
    peer.onicecandidate = (event) => {
      if (event.candidate) {
        addDiagnostic(`Local ICE candidate gathered: ${event.candidate.type || 'candidate'}.`);
        sendSignaling({
          type: 'p2p-signal',
          sessionId,
          signalType: 'ice',
          payload: event.candidate.toJSON()
        });
      } else {
        addDiagnostic('ICE gathering completed.');
      }
    };
    peer.oniceconnectionstatechange = () => {
      addDiagnostic(`ICE state: ${peer.iceConnectionState}.`);
      if (peer.iceConnectionState === 'connected' || peer.iceConnectionState === 'completed') {
        setStatus((current) => current.includes('Receiving encrypted file') || current.includes('Sending encrypted chunks') ? current : 'P2P network path connected. Waiting for data channel...');
        updateConnectionMode();
      }
      if (peer.iceConnectionState === 'failed') {
        setConnectionMode('Failed');
        try {
          sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'failed', payload: null });
        } catch {
          // Socket may already be closed during cleanup.
        }
      }
    };
    peer.onconnectionstatechange = () => {
      addDiagnostic(`Peer state: ${peer.connectionState}.`);
      if (peer.connectionState === 'failed') {
        setConnectionMode('Failed');
      }
    };
    peer.onicegatheringstatechange = () => {
      addDiagnostic(`ICE gathering state: ${peer.iceGatheringState}.`);
    };
    peer.onsignalingstatechange = () => {
      addDiagnostic(`Signaling state: ${peer.signalingState}.`);
    };
    return peer;
  }, [addDiagnostic, cleanupPeer, iceConfig, sendSignaling, updateConnectionMode]);

  const waitForIceGathering = useCallback(async (peer: RTCPeerConnection, label: string) => {
    if (peer.iceGatheringState === 'complete') {
      const candidateCount = countSdpCandidates(peer.localDescription);
      addDiagnostic(`${label} ICE already complete with ${candidateCount} SDP candidate(s).`);
      return candidateCount;
    }

    addDiagnostic(`${label} waiting for ICE candidates.`);
    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        peer.removeEventListener('icegatheringstatechange', handleStateChange);
        resolve();
      };
      const handleStateChange = () => {
        if (peer.iceGatheringState === 'complete') {
          finish();
        }
      };
      const timeout = window.setTimeout(finish, 5000);
      peer.addEventListener('icegatheringstatechange', handleStateChange);
    });
    const candidateCount = countSdpCandidates(peer.localDescription);
    addDiagnostic(`${label} SDP has ${candidateCount} ICE candidate(s).`);
    return candidateCount;
  }, [addDiagnostic]);

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

    addDiagnostic('Sending encrypted metadata header.');
    channel.send(JSON.stringify({
      kind: 'header',
      iv: encryptedHeader.iv,
      ciphertext: encryptedHeader.ciphertext,
      signature,
      senderUsername: user.username
    }));

    let offset = 0;
    let index = 0;
    setStatus('Sending encrypted chunks through the TURN relay...');
    while (offset < session.file.size) {
      while (channel.bufferedAmount > 4 * 1024 * 1024) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const plain = new Uint8Array(await session.file.slice(offset, offset + P2P_CHUNK_SIZE_BYTES).arrayBuffer());
      const encrypted = await encryptBytes(transferKey, plain);
      channel.send(createChunkFrame(index, encrypted.iv, encrypted.ciphertext));
      offset += P2P_CHUNK_SIZE_BYTES;
      index += 1;
      setProgress(Math.round((offset / session.file.size) * 100));
    }

    channel.send(JSON.stringify({ kind: 'done' }));
    setProgress(100);
    setStatus('Encrypted P2P file transfer completed.');
    addDiagnostic('Encrypted transfer completed.');
    clearStreamTimeout();
  }, [addDiagnostic, clearStreamTimeout, findIdentity, user]);

  const startSenderPeer = useCallback(async (session: OutgoingSession) => {
    const peer = createPeer(session.sessionId);
    const channel = peer.createDataChannel('crypshare-p2p-file', { ordered: true });
    channel.binaryType = 'arraybuffer';
    channelRef.current = channel;
    channel.onopen = () => {
      setStatus('P2P data channel opened. Sending encrypted header...');
      addDiagnostic('Sender data channel opened.');
      clearStreamTimeout();
      sendEncryptedFile(session, channel).catch((err) => {
        setStatus(getErrorMessage(err, 'P2P send failed.'));
        addDiagnostic('Sender failed while sending encrypted file.');
        sendSignaling({ type: 'p2p-signal', sessionId: session.sessionId, signalType: 'failed', payload: null });
      });
    };
    channel.onerror = () => {
      addDiagnostic('Sender data channel error.');
      setStatus('P2P data channel error before transfer completed.');
    };
    channel.onclose = () => {
      addDiagnostic('Sender data channel closed.');
      setStatus('P2P data channel closed.');
    };

    addDiagnostic('Creating and sending WebRTC offer.');
    const offer = await peer.createOffer();
    await peer.setLocalDescription(offer);
    const candidateCount = await waitForIceGathering(peer, 'Sender');
    if (candidateCount === 0) {
      const message = noIceCandidateMessage(session.relayAllowed, iceConfig?.turnConfigured === true);
      setConnectionMode('Failed');
      setStatus(message);
      addDiagnostic('Transfer stopped because sender gathered 0 ICE candidates.');
      sendSignaling({ type: 'p2p-signal', sessionId: session.sessionId, signalType: 'failed', payload: { reason: 'no-ice-candidates' } });
      return;
    }
    sendSignaling({
      type: 'p2p-signal',
      sessionId: session.sessionId,
      signalType: 'offer',
      payload: peer.localDescription
    });
    startStreamTimeout(session.sessionId, 'P2P sender');
    setStatus('P2P invite accepted. Negotiating encrypted TURN relay path...');
  }, [addDiagnostic, clearStreamTimeout, createPeer, iceConfig?.turnConfigured, sendEncryptedFile, sendSignaling, startStreamTimeout, waitForIceGathering]);

  useEffect(() => {
    startSenderPeerRef.current = startSenderPeer;
  }, [startSenderPeer]);

  const flushPendingIce = useCallback(async () => {
    const peer = peerRef.current;
    if (!peer?.remoteDescription) return;
    const pending = pendingIceRef.current.splice(0);
    if (pending.length > 0) {
      addDiagnostic(`Applying ${pending.length} queued remote ICE candidate${pending.length === 1 ? '' : 's'}.`);
    }
    for (const candidate of pending) {
      await peer.addIceCandidate(candidate);
    }
  }, [addDiagnostic]);

  const handleIncomingData = useCallback(async (sessionId: string, senderUsername: string, event: MessageEvent<string | ArrayBuffer | Blob>) => {
    if (!user?.privateKeyECDH) return;
    const sender = findIdentity(senderUsername);
    if (!sender) {
      setStatus('Sender identity is unavailable. Transfer blocked.');
      return;
    }

    if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
      const frame = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
      const packet = parseChunkFrame(frame);
      if (!packet) {
        throw new Error('Received malformed encrypted P2P chunk.');
      }

      const transferKey = transferKeyRef.current;
      const header = receivedHeaderRef.current;
      if (!transferKey || !header) {
        throw new Error('Received file chunk before verified header.');
      }
      if (packet.index < 0 || packet.index >= header.chunkCount) {
        throw new Error('Received encrypted chunk outside expected range.');
      }

      const plainBytes = await decryptBytes(transferKey, packet.iv, packet.ciphertext);
      if (!receivedChunksRef.current[packet.index]) {
        receivedChunksRef.current[packet.index] = new Blob([plainBytes], { type: header.type });
        receivedCountRef.current += 1;
        if (receivedCountRef.current === 1) {
          addDiagnostic('First encrypted file chunk received.');
        }
      }
      setProgress(Math.round((receivedCountRef.current / Math.max(header.chunkCount, 1)) * 100));
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
      clearStreamTimeout();
      addDiagnostic('Verified sender signature and decrypted metadata header.');
      setStatus(`Receiving encrypted file through the TURN relay. ${formatBytes(header.size)} expected.`);
      return;
    }

    if (packet.kind === 'done') {
      const header = receivedHeaderRef.current;
      if (!header) return;
      if (receivedCountRef.current !== header.chunkCount) {
        throw new Error('P2P transfer ended before all encrypted chunks arrived.');
      }
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
      addDiagnostic('Received all encrypted chunks and downloaded file.');
      sendSignaling({ type: 'p2p-signal', sessionId, signalType: 'completed', payload: null });
      cleanupPeer();
    }
  }, [addDiagnostic, clearStreamTimeout, cleanupPeer, findIdentity, sendSignaling, user]);

  const startReceiverPeer = useCallback(async (invite: IncomingInvite, offer: RTCSessionDescriptionInit) => {
    const peer = createPeer(invite.sessionId);
    peer.ondatachannel = (event) => {
      addDiagnostic('Receiver data channel arrived.');
      const channel = event.channel;
      channel.binaryType = 'arraybuffer';
      channelRef.current = channel;
      channel.onopen = () => {
        addDiagnostic('Receiver data channel opened.');
        setStatus('P2P data channel opened. Waiting for encrypted header...');
      };
      channel.onerror = () => {
        addDiagnostic('Receiver data channel error.');
        setStatus('P2P data channel error before file arrived.');
      };
      channel.onclose = () => {
        addDiagnostic('Receiver data channel closed.');
        setStatus((current) => current.includes('downloaded') ? current : 'P2P data channel closed before transfer completed.');
      };
      channel.onmessage = (messageEvent) => {
        handleIncomingData(invite.sessionId, invite.senderUsername, messageEvent as MessageEvent<string>).catch((err) => {
          setStatus(getErrorMessage(err, 'Unable to receive P2P file.'));
          addDiagnostic('Receiver failed while processing encrypted data.');
          sendSignaling({ type: 'p2p-signal', sessionId: invite.sessionId, signalType: 'failed', payload: null });
        });
      };
    };
    addDiagnostic('Receiver applying WebRTC offer.');
    await peer.setRemoteDescription(offer);
    await flushPendingIce();
    const answer = await peer.createAnswer();
    await peer.setLocalDescription(answer);
    const candidateCount = await waitForIceGathering(peer, 'Receiver');
    if (candidateCount === 0) {
      const message = noIceCandidateMessage(invite.relayAllowed, iceConfig?.turnConfigured === true);
      setConnectionMode('Failed');
      setStatus(message);
      addDiagnostic('Transfer stopped because receiver gathered 0 ICE candidates.');
      sendSignaling({ type: 'p2p-signal', sessionId: invite.sessionId, signalType: 'failed', payload: { reason: 'no-ice-candidates' } });
      return;
    }
    sendSignaling({
      type: 'p2p-signal',
      sessionId: invite.sessionId,
      signalType: 'answer',
      payload: peer.localDescription
    });
    addDiagnostic('Receiver sent WebRTC answer.');
    startStreamTimeout(invite.sessionId, 'P2P receiver');
    setStatus('Accepted P2P invite. Waiting for encrypted file stream...');
  }, [addDiagnostic, createPeer, flushPendingIce, handleIncomingData, iceConfig?.turnConfigured, sendSignaling, startStreamTimeout, waitForIceGathering]);

  const handleSignal = useCallback(async (message: P2PMessage) => {
    if (!message.sessionId || !message.signalType) return;
    if (message.signalType === 'offer') {
      addDiagnostic('WebRTC offer received.');
      const invite = incomingRef.current;
      if (!invite || invite.sessionId !== message.sessionId || !message.payload) return;
      await startReceiverPeer(invite, message.payload as RTCSessionDescriptionInit);
      return;
    }
    if (message.signalType === 'answer' && peerRef.current && message.payload) {
      addDiagnostic('WebRTC answer received.');
      await peerRef.current.setRemoteDescription(message.payload as RTCSessionDescriptionInit);
      await flushPendingIce();
      setStatus('P2P connection established. Sending encrypted data...');
      return;
    }
    if (message.signalType === 'ice' && message.payload) {
      const candidate = message.payload as RTCIceCandidateInit;
      if (peerRef.current?.remoteDescription) {
        addDiagnostic('Remote ICE candidate applied.');
        await peerRef.current.addIceCandidate(candidate);
      } else {
        pendingIceRef.current.push(candidate);
        addDiagnostic('Remote ICE candidate queued.');
      }
      return;
    }
    if (message.signalType === 'completed') {
      setStatus('Peer confirmed P2P transfer completed.');
      addDiagnostic('Peer confirmed transfer completion.');
      cleanupPeer();
      return;
    }
    if (message.signalType === 'failed') {
      const failedPayload = message.payload as { reason?: string } | null | undefined;
      setConnectionMode('Failed');
      if (failedPayload?.reason === 'no-ice-candidates') {
        setStatus('Peer gathered 0 TURN relay candidates. P2P cannot start until the TURN service is reachable and credentials are valid.');
        addDiagnostic('Peer reported 0 TURN relay candidates.');
      } else {
        setStatus('Peer reported that P2P transfer failed.');
        addDiagnostic('Peer reported transfer failure.');
      }
      cleanupPeer();
    }
  }, [addDiagnostic, cleanupPeer, flushPendingIce, startReceiverPeer]);

  useEffect(() => {
    handleSignalRef.current = handleSignal;
  }, [handleSignal]);

  const applyIncomingInvite = useCallback((invite: IncomingInvite | PendingP2PInvite) => {
    addDiagnostic(`P2P invite received from ${invite.senderUsername}.`);
    const normalizedInvite = {
      sessionId: invite.sessionId,
      senderUsername: invite.senderUsername,
      senderFingerprint: invite.senderFingerprint,
      relayAllowed: invite.relayAllowed === true,
      expiresAt: invite.expiresAt
    };
    incomingRef.current = normalizedInvite;
    setIncomingInvite(normalizedInvite);
    setActivePeer(normalizedInvite.senderUsername);
    setStatus(`Incoming P2P request from ${normalizedInvite.senderUsername}.`);
    markInviteRead(normalizedInvite.sessionId);
    fetchP2PIdentityRef.current(normalizedInvite.senderUsername, normalizedInvite.senderFingerprint).catch((err) => {
      setStatus(getErrorMessage(err, 'Unable to verify incoming P2P sender identity.'));
    });
  }, [addDiagnostic, markInviteRead]);

  const handleSocketMessage = useCallback((message: P2PMessage) => {
    if (message.type === 'p2p-ready') {
      addDiagnostic('P2P signaling connected.');
    }
    if (message.type === 'p2p-invite' && message.sessionId && message.senderUsername && message.expiresAt) {
      applyIncomingInvite({
        sessionId: message.sessionId,
        senderUsername: message.senderUsername,
        senderFingerprint: message.senderFingerprint,
        relayAllowed: message.relayAllowed === true,
        expiresAt: message.expiresAt
      });
    }
    if (message.type === 'p2p-invite-created' && message.sessionId && selectedFileRef.current) {
      addDiagnostic('P2P invite session created.');
      const session = {
        sessionId: message.sessionId,
        recipientUsername: recipientUsernameRef.current,
        relayAllowed: true,
        file: selectedFileRef.current
      };
      outgoingRef.current = session;
      setOutgoingSession(session);
      setActivePeer(recipientUsernameRef.current);
      setStatus('P2P invite created. Delivering request to recipient...');
      if (pendingAcceptedSessionIdRef.current === message.sessionId) {
        pendingAcceptedSessionIdRef.current = '';
        startSenderPeerRef.current?.(session).catch((err) => setStatus(getErrorMessage(err, 'Unable to start P2P sender.')));
      }
    }
    if (message.type === 'p2p-invite-delivery' && message.sessionId) {
      addDiagnostic(message.delivered ? 'Invite delivered to recipient socket.' : 'Invite could not be delivered; recipient offline.');
      setStatus(message.delivered ? 'P2P invite delivered. Waiting for recipient.' : 'P2P invite created, but recipient is not online.');
    }
    if (message.type === 'p2p-accepted' && message.sessionId) {
      addDiagnostic('Recipient accepted P2P invite.');
      const session = outgoingRef.current;
      if (session?.sessionId === message.sessionId) {
        startSenderPeerRef.current?.(session).catch((err) => setStatus(getErrorMessage(err, 'Unable to start P2P sender.')));
      } else {
        pendingAcceptedSessionIdRef.current = message.sessionId;
        setStatus('Recipient accepted. Preparing sender session...');
      }
    }
    if (message.type === 'p2p-declined') {
      addDiagnostic('Recipient declined P2P invite.');
      setStatus('Recipient declined the P2P transfer.');
      cleanupPeer();
    }
    if (message.type === 'p2p-expired') {
      addDiagnostic('P2P session expired.');
      setStatus('P2P session expired.');
      cleanupPeer();
    }
    if (message.type === 'p2p-signal') {
      handleSignalRef.current?.(message).catch((err) => setStatus(getErrorMessage(err, 'P2P signaling failed.')));
    }
    if (message.type === 'p2p-error') {
      addDiagnostic(`Signaling error: ${message.error || 'unknown error'}.`);
      setStatus(message.error || 'P2P signaling error.');
    }
  }, [addDiagnostic, applyIncomingInvite, cleanupPeer]);

  useEffect(() => subscribeMessages(handleSocketMessage), [handleSocketMessage, subscribeMessages]);

  useEffect(() => {
    if (incomingInvite || pendingInvites.length === 0) return;
    applyIncomingInvite(pendingInvites[0]);
  }, [applyIncomingInvite, incomingInvite, pendingInvites]);

  useEffect(() => cleanupPeer, [cleanupPeer]);

  const handleSendInvite = () => {
    if (!selectedRecipient || !selectedFile) {
      showToast('Choose a recipient and file first.', 'error');
      return;
    }
    if (!iceConfig?.turnConfigured || iceConfig.iceServers.length === 0) {
      showToast('TURN relay is not configured. P2P is relay-only for privacy.', 'error');
      setConnectionMode('Failed');
      setStatus('TURN relay is not configured. Start the local TURN service or configure a public TURN server before sending P2P files.');
      return;
    }
    setProgress(0);
    setDiagnostics([]);
    setActivePeer(selectedRecipient.username);
    addDiagnostic(`Sending P2P invite to ${selectedRecipient.username}.`);
    sendSignaling({
      type: 'p2p-invite',
      recipientUsername: selectedRecipient.username,
      recipientFingerprint: recipientMode === 'identity' ? recipientInviteFingerprint : undefined,
      relayAllowed: true
    });
  };

  const handleAcceptInvite = () => {
    if (!incomingInvite) return;
    addDiagnostic(`Accepting P2P invite from ${incomingInvite.senderUsername}.`);
    sendSignaling({ type: 'p2p-accept', sessionId: incomingInvite.sessionId });
    setStatus('P2P invite accepted. Waiting for sender connection offer...');
    removeInvite(incomingInvite.sessionId);
    setIncomingInvite(null);
  };

  const handleDeclineInvite = () => {
    if (!incomingInvite) return;
    sendSignaling({ type: 'p2p-decline', sessionId: incomingInvite.sessionId });
    removeInvite(incomingInvite.sessionId);
    setIncomingInvite(null);
    setStatus('P2P invite declined.');
  };

  const handleTurnSelfTest = async () => {
    if (!iceConfig?.turnConfigured || iceConfig.iceServers.length === 0) {
      setConnectionMode('Failed');
      setStatus('TURN relay is not configured. Start coturn or configure a public TURN server before testing P2P.');
      addDiagnostic('TURN self-test skipped: no TURN config.');
      return;
    }

    setProgress(0);
    setDiagnostics([]);
    setConnectionMode('TURN relay only');
    setStatus('Testing TURN relay candidate gathering in this browser...');
    addDiagnostic(`TURN self-test started with ${iceConfig.iceServers.length} ICE server config(s).`);

    const peer = new RTCPeerConnection({
      iceServers: iceConfig.iceServers,
      iceTransportPolicy: 'relay',
      iceCandidatePoolSize: 4
    });

    try {
      peer.createDataChannel('crypshare-turn-self-test');
      peer.onicecandidate = (event) => {
        if (event.candidate) {
          addDiagnostic(`Self-test candidate: ${event.candidate.type || 'candidate'} ${event.candidate.protocol || ''}`.trim());
        }
      };
      peer.onicegatheringstatechange = () => {
        addDiagnostic(`Self-test ICE gathering state: ${peer.iceGatheringState}.`);
      };

      const offer = await peer.createOffer();
      await peer.setLocalDescription(offer);
      const candidateCount = await waitForIceGathering(peer, 'Self-test');
      if (candidateCount > 0) {
        setStatus(`TURN relay self-test passed. Browser gathered ${candidateCount} relay candidate${candidateCount === 1 ? '' : 's'}.`);
        setConnectionMode('TURN relay only');
      } else {
        setStatus('TURN relay self-test failed: browser gathered 0 relay candidates. Check TURN URL, credentials, Docker port mapping, or browser WebRTC blocking.');
        setConnectionMode('Failed');
      }
    } catch (err: unknown) {
      setConnectionMode('Failed');
      setStatus(getErrorMessage(err, 'TURN relay self-test failed.'));
      addDiagnostic('TURN self-test threw an error.');
    } finally {
      peer.close();
    }
  };

  const relayCopy = 'TURN relay-only mode is enforced for P2P privacy. TURN can observe IP/timing/packet sizes, but file metadata and chunks are encrypted before transfer.';

  const transferEstimate = useMemo(() => selectedFile ? encryptedPacketSize(selectedFile.size) : 0, [selectedFile]);
  const selectedTrust = selectedRecipient ? trustStatuses[selectedRecipient.username] : undefined;
  const relayReady = iceConfig?.turnConfigured === true && iceConfig.iceServers.length > 0;
  const activeStep = progress >= 100 ? 4 : selectedFile && selectedRecipient ? 3 : selectedRecipient ? 2 : 1;
  const steps = [
    { id: 1, label: 'Select Recipient' },
    { id: 2, label: 'Add File' },
    { id: 3, label: 'Review & Send' },
    { id: 4, label: 'Complete' }
  ];
  const transferBlockedReason = !socketReady
    ? 'Signaling is offline.'
    : !relayReady
      ? 'TURN relay is unavailable.'
      : !selectedRecipient
        ? 'Select a recipient.'
        : !selectedFile
          ? 'Choose a file.'
          : '';

  return (
    <div className="mx-auto max-w-7xl animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--app-border)] bg-[var(--brand-blue)] text-white">
              <RadioTower className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-2xl font-semibold text-[var(--app-text)]">P2P Secure Transfer</h2>
              <p className="text-sm text-[var(--app-muted)]">One-time encrypted browser transfer for online recipients.</p>
            </div>
          </div>
          <p className="max-w-3xl text-sm leading-6 text-[var(--app-muted)]">
            CrypShare handles signaling and TURN relay setup only. The file manifest and chunks are encrypted in the browser before anything leaves your device.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge tone={socketReady ? 'success' : 'danger'} className="gap-1.5">
            {socketReady ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
            {socketReady ? 'Signaling online' : 'Signaling offline'}
          </StatusBadge>
          <StatusBadge tone={relayReady ? 'success' : 'warning'} className="gap-1.5">
            <RadioTower className="h-3.5 w-3.5" />
            {relayReady ? 'TURN relay ready' : 'TURN unavailable'}
          </StatusBadge>
        </div>
      </div>

      <GlassCard className="mb-6 p-4">
        <div className="grid gap-3 md:grid-cols-4">
          {steps.map((step) => {
            const complete = activeStep > step.id;
            const active = activeStep === step.id;
            return (
              <div
                key={step.id}
                className={`flex items-center gap-3 rounded-lg border px-3 py-3 ${
                  active
                    ? 'border-[color-mix(in_srgb,var(--brand-blue)_55%,var(--app-border))] bg-[color-mix(in_srgb,var(--brand-blue)_12%,var(--app-surface))]'
                    : complete
                      ? 'border-[color-mix(in_srgb,var(--success-color)_35%,var(--app-border))] bg-[color-mix(in_srgb,var(--success-color)_8%,var(--app-surface))]'
                      : 'border-[var(--app-border)] bg-[var(--app-surface-muted)]'
                }`}
              >
                <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${
                  active
                    ? 'bg-[var(--brand-blue)] text-white'
                    : complete
                      ? 'bg-[var(--success-color)] text-white'
                      : 'bg-[var(--app-surface)] text-[var(--app-muted)]'
                }`}>
                  {complete ? <CheckCircle2 className="h-4 w-4" /> : step.id}
                </span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-[var(--app-text)]">{step.label}</p>
                  <p className="text-xs text-[var(--app-muted)]">{complete ? 'Ready' : active ? 'Current step' : 'Waiting'}</p>
                </div>
              </div>
            );
          })}
        </div>
      </GlassCard>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(380px,0.95fr)]">
        <div className="space-y-6">
          <GlassCard className="p-6">
            <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">Recipient</h3>
                <p className="text-sm text-[var(--app-muted)]">Send to a known contact or verify an identity invite URL first.</p>
              </div>
              {selectedRecipient && (
                <StatusBadge tone={selectedTrust?.trusted ? 'success' : 'warning'} className="gap-1.5">
                  {selectedTrust?.trusted ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
                  {selectedTrust?.trusted ? 'Trusted' : 'Verify fingerprint'}
                </StatusBadge>
              )}
            </div>

            <div className="grid grid-cols-2 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-1">
              <button
                type="button"
                onClick={() => {
                  setRecipientMode('known');
                  setRecipientInviteFingerprint('');
                }}
                className={`rounded-md px-3 py-2 text-sm font-semibold transition-colors ${
                  recipientMode === 'known' ? 'bg-[var(--brand-blue)] text-white' : 'text-[var(--app-muted)] hover:text-[var(--app-text)]'
                }`}
              >
                Known user
              </button>
              <button
                type="button"
                onClick={() => setRecipientMode('identity')}
                className={`rounded-md px-3 py-2 text-sm font-semibold transition-colors ${
                  recipientMode === 'identity' ? 'bg-[var(--brand-blue)] text-white' : 'text-[var(--app-muted)] hover:text-[var(--app-text)]'
                }`}
              >
                Identity URL
              </button>
            </div>

            <div className="mt-5">
              {recipientMode === 'known' ? (
                <div>
                  <label className="text-xs font-semibold uppercase tracking-[0.16em] text-[var(--app-muted)]">Workspace or trusted contact</label>
                  <select
                    value={recipientUsername}
                    onChange={(event) => setRecipientUsername(event.target.value)}
                    className="mt-2 w-full rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] px-3 py-3 text-sm text-[var(--app-text)] outline-none transition focus:border-[var(--brand-blue)]"
                  >
                    <option value="">Choose known user...</option>
                    {users.map((entry) => (
                      <option key={entry.username} value={entry.username}>{entry.username}</option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="space-y-3">
                  <label className="text-xs font-semibold uppercase tracking-[0.16em] text-[var(--app-muted)]">Private invite URL</label>
                  <textarea
                    value={identityInviteText}
                    onChange={(event) => {
                      setIdentityInviteText(event.target.value);
                      setIdentityInviteError('');
                      setIdentityInvitePreview('');
                      setRecipientInviteFingerprint('');
                    }}
                    placeholder="Paste a CrypShare identity invite URL. The sensitive payload should stay in the URL fragment, not server logs."
                    rows={5}
                    className="w-full resize-none rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] px-3 py-3 text-sm text-[var(--app-text)] outline-none transition placeholder:text-[var(--app-muted)] focus:border-[var(--brand-blue)]"
                  />
                  <ActionButton
                    variant="secondary"
                    onClick={handleParseIdentityInvite}
                    disabled={!identityInviteText.trim()}
                    className="w-full justify-center text-sm"
                  >
                    <UserCheck className="h-4 w-4" /> Verify Identity URL
                  </ActionButton>
                  {identityInvitePreview && (
                    <div className="rounded-lg border border-[color-mix(in_srgb,var(--success-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--success-color)_10%,var(--app-surface))] p-3 text-sm text-[var(--success-color)]">
                      {identityInvitePreview}
                    </div>
                  )}
                  {identityInviteError && (
                    <div className="rounded-lg border border-[color-mix(in_srgb,var(--danger-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--danger-color)_10%,var(--app-surface))] p-3 text-sm text-[var(--danger-color)]">
                      {identityInviteError}
                    </div>
                  )}
                </div>
              )}
            </div>

            {selectedRecipient && (
              <div className="mt-5 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-[var(--app-text)]">{selectedRecipient.username}</p>
                    <p className="mt-1 text-xs text-[var(--app-muted)]">
                      {recipientMode === 'identity' ? 'Verified from invite URL' : 'Selected from discoverable contacts'}
                    </p>
                  </div>
                  <StatusBadge tone={selectedTrust?.trusted ? 'success' : 'warning'}>
                    {selectedTrust?.trusted ? 'Trusted' : 'Untrusted'}
                  </StatusBadge>
                </div>
              </div>
            )}
          </GlassCard>

          <GlassCard className="p-6">
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">File</h3>
                <p className="text-sm text-[var(--app-muted)]">One file per P2P session. Nothing is added to Vault on receive.</p>
              </div>
              <StatusBadge tone={selectedFile ? 'success' : 'neutral'}>
                {selectedFile ? 'Ready' : 'Waiting'}
              </StatusBadge>
            </div>

            <label className="block">
              <div className="relative flex min-h-[148px] cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-[var(--app-border-strong)] bg-[var(--app-surface-muted)] p-6 text-center transition hover:border-[var(--brand-blue)]">
                <input
                  type="file"
                  className="absolute inset-0 cursor-pointer opacity-0"
                  onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
                />
                <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--brand-blue)_14%,var(--app-surface))] text-[var(--brand-blue)]">
                  <FileUp className="h-6 w-6" />
                </div>
                <p className="max-w-full truncate text-sm font-semibold text-[var(--app-text)]">
                  {selectedFile?.name || 'Choose encrypted transfer file'}
                </p>
                <p className="mt-1 text-xs text-[var(--app-muted)]">Local file is encrypted chunk-by-chunk before transfer.</p>
              </div>
            </label>

            {selectedFile && (
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                  <p className="text-xs text-[var(--app-muted)]">Original size</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--app-text)]">{formatBytes(selectedFile.size)}</p>
                </div>
                <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                  <p className="text-xs text-[var(--app-muted)]">Encrypted payload</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--app-text)]">About {formatBytes(transferEstimate)}</p>
                </div>
              </div>
            )}
          </GlassCard>

          <div className="grid gap-6 lg:grid-cols-2">
            <GlassCard className="p-6">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] text-[var(--brand-teal)]">
                  <KeyRound className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-[var(--app-text)]">Trust fingerprint</h3>
                  <p className="text-xs text-[var(--app-muted)]">Trust is local and must be verified outside CrypShare.</p>
                </div>
              </div>

              {selectedRecipient && selectedTrust ? (
                <div className={`rounded-lg border p-4 ${
                  selectedTrust.trusted
                    ? 'border-[color-mix(in_srgb,var(--success-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--success-color)_8%,var(--app-surface))]'
                    : 'border-[color-mix(in_srgb,var(--warning-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--warning-color)_10%,var(--app-surface))]'
                }`}>
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-[var(--app-text)]">{selectedTrust.trusted ? 'Verified trusted recipient' : 'Not trusted yet'}</p>
                    <StatusBadge tone={selectedTrust.trusted ? 'success' : 'warning'}>
                      {selectedTrust.changed ? 'Changed' : selectedTrust.trusted ? 'Trusted' : 'Check'}
                    </StatusBadge>
                  </div>
                  <p className="break-all font-mono text-xs leading-6 text-[var(--app-muted)]">{formatFingerprint(selectedTrust.fingerprint)}</p>
                  {!selectedTrust.trusted && (
                    <p className="mt-3 text-xs leading-5 text-[var(--app-muted)]">
                      Confirm this fingerprint with the recipient through another channel before treating future transfers as trusted.
                    </p>
                  )}
                </div>
              ) : (
                <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
                  <p className="text-sm text-[var(--app-muted)]">Select or verify a recipient to inspect their identity fingerprint.</p>
                </div>
              )}
            </GlassCard>

            <GlassCard className="p-6">
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] text-[var(--brand-blue)]">
                  <LockKeyhole className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-[var(--app-text)]">Relay status</h3>
                  <p className="text-xs text-[var(--app-muted)]">Direct WebRTC candidates are disabled for this privacy mode.</p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                  <span className="text-sm text-[var(--app-text)]">TURN relay</span>
                  <StatusBadge tone={relayReady ? 'success' : 'warning'}>{relayReady ? 'Available' : 'Unavailable'}</StatusBadge>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                  <span className="text-sm text-[var(--app-text)]">Direct peer route</span>
                  <StatusBadge tone="neutral">Disabled</StatusBadge>
                </div>
                <p className="text-xs leading-5 text-[var(--app-muted)]">{relayReady ? relayCopy : 'Start the local TURN service or configure a public TURN server before sending P2P files.'}</p>
                <ActionButton
                  variant="secondary"
                  onClick={handleTurnSelfTest}
                  disabled={!relayReady}
                  className="w-full justify-center text-sm"
                >
                  Test TURN Relay
                </ActionButton>
              </div>
            </GlassCard>
          </div>

          <GlassCard className="p-5">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <h3 className="text-base font-semibold text-[var(--app-text)]">Review & Send</h3>
                <p className="text-sm text-[var(--app-muted)]">
                  {transferBlockedReason || 'Ready to create an online transfer request.'}
                </p>
              </div>
              <ActionButton onClick={handleSendInvite} disabled={!socketReady || !selectedFile || !selectedRecipient || !relayReady} className="justify-center md:min-w-48">
                <Send className="h-4 w-4" /> Send P2P Invite
              </ActionButton>
            </div>
          </GlassCard>
        </div>

        <div className="space-y-6">
          <GlassCard className="p-6">
            <div className="mb-5 flex items-center justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">Incoming request</h3>
                <p className="text-sm text-[var(--app-muted)]">Accept only after checking the sender identity state.</p>
              </div>
              <Download className="h-5 w-5 text-[var(--brand-blue)]" />
            </div>

            {incomingInvite ? (
              <div className="space-y-4">
                <div className={`rounded-lg border p-4 ${
                  activeTrust?.trusted
                    ? 'border-[color-mix(in_srgb,var(--success-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--success-color)_8%,var(--app-surface))]'
                    : 'border-[color-mix(in_srgb,var(--warning-color)_30%,var(--app-border))] bg-[color-mix(in_srgb,var(--warning-color)_10%,var(--app-surface))]'
                }`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-[var(--app-text)]">{incomingInvite.senderUsername}</p>
                      <p className="mt-1 text-xs text-[var(--app-muted)]">
                        {activeTrust?.trusted ? 'Verified trusted sender.' : 'Untrusted identity. Accept once or trust after out-of-band verification.'}
                      </p>
                    </div>
                    <StatusBadge tone={activeTrust?.trusted ? 'success' : 'warning'}>
                      {activeTrust?.trusted ? 'Trusted' : 'Untrusted'}
                    </StatusBadge>
                  </div>
                  {activeTrust && <p className="mt-4 break-all font-mono text-xs leading-6 text-[var(--app-muted)]">{formatFingerprint(activeTrust.fingerprint)}</p>}
                  {activePeer && activeTrust && !activeTrust.trusted && (
                    <ActionButton variant="secondary" onClick={handleTrustActivePeer} className="mt-4 justify-center text-sm">
                      <ShieldCheck className="h-4 w-4" /> Trust Sender
                    </ActionButton>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <ActionButton variant="secondary" onClick={handleDeclineInvite} className="justify-center">
                    <XCircle className="h-4 w-4" /> Decline
                  </ActionButton>
                  <ActionButton onClick={handleAcceptInvite} className="justify-center">
                    <CheckCircle2 className="h-4 w-4" /> Accept
                  </ActionButton>
                </div>
              </div>
            ) : (
              <div className="flex min-h-[160px] flex-col items-center justify-center rounded-lg border border-dashed border-[var(--app-border)] bg-[var(--app-surface-muted)] p-6 text-center">
                <Circle className="mb-3 h-8 w-8 text-[var(--app-muted)]" />
                <p className="text-sm font-semibold text-[var(--app-text)]">No pending transfer</p>
                <p className="mt-1 text-xs text-[var(--app-muted)]">Keep this page open to receive online P2P requests.</p>
              </div>
            )}
          </GlassCard>

          <GlassCard className="p-6">
            <div className="mb-5 flex items-center justify-between gap-3">
              <div>
                <h3 className="text-lg font-semibold text-[var(--app-text)]">Transfer activity</h3>
                <p className="text-sm text-[var(--app-muted)]">Live connection and encrypted stream status.</p>
              </div>
              <StatusBadge tone={connectionMode === 'Failed' ? 'danger' : connectionMode === 'Relay in use' ? 'success' : 'primary'}>
                {connectionMode}
              </StatusBadge>
            </div>

            <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
              <p className="text-sm leading-6 text-[var(--app-text)]">{status}</p>
              <div className="mt-4">
                <div className="mb-2 flex items-center justify-between text-xs text-[var(--app-muted)]">
                  <span>Progress</span>
                  <span>{progress}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-[var(--app-surface)]">
                  <div
                    className={`h-full rounded-full transition-all ${connectionMode === 'Failed' ? 'bg-[var(--danger-color)]' : 'bg-[var(--brand-blue)]'}`}
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                <p className="text-xs text-[var(--app-muted)]">Received files</p>
                <p className="mt-1 text-sm font-semibold text-[var(--app-text)]">Download only</p>
              </div>
              <div className="rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-3">
                <p className="text-xs text-[var(--app-muted)]">Vault storage</p>
                <p className="mt-1 text-sm font-semibold text-[var(--app-text)]">Not automatic</p>
              </div>
            </div>

            {diagnostics.length > 0 && (
              <div className="mt-4 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface-muted)] p-4">
                <button
                  type="button"
                  onClick={() => setShowDiagnostics((current) => !current)}
                  className="flex w-full items-center justify-between gap-3 text-left text-xs font-semibold uppercase tracking-[0.16em] text-[var(--app-muted)]"
                >
                  Connection trace
                  <span className="normal-case tracking-normal text-[var(--brand-blue)]">{showDiagnostics ? 'Hide' : 'Show'}</span>
                </button>
                {showDiagnostics && (
                  <div className="mt-4 space-y-2">
                    {outgoingSession && <p className="break-all font-mono text-xs text-[var(--app-muted)]">Session: {outgoingSession.sessionId}</p>}
                    {diagnostics.map((entry, index) => (
                      <p key={`${entry}-${index}`} className="break-words font-mono text-xs text-[var(--app-muted)]">{entry}</p>
                    ))}
                  </div>
                )}
              </div>
            )}
          </GlassCard>
        </div>
      </div>
    </div>
  );
};
