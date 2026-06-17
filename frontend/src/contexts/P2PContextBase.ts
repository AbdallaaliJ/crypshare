import { createContext } from 'react';

export interface P2PMessage {
  type: string;
  sessionId?: string;
  senderUsername?: string;
  recipientUsername?: string;
  relayAllowed?: boolean;
  delivered?: boolean;
  expiresAt?: number;
  createdAt?: number;
  fromUsername?: string;
  senderFingerprint?: string;
  signalType?: string;
  payload?: RTCSessionDescriptionInit | RTCIceCandidateInit | { reason?: string } | null;
  error?: string;
}

export interface PendingP2PInvite {
  sessionId: string;
  senderUsername: string;
  senderFingerprint?: string;
  relayAllowed: boolean;
  expiresAt: number;
  createdAt?: number;
  unread: boolean;
}

export type P2PMessageHandler = (message: P2PMessage) => void | Promise<void>;

export interface P2PContextValue {
  socketReady: boolean;
  pendingInvites: PendingP2PInvite[];
  unreadCount: number;
  sendSignaling: (message: Record<string, unknown>) => void;
  subscribeMessages: (handler: P2PMessageHandler) => () => void;
  markInviteRead: (sessionId: string) => void;
  removeInvite: (sessionId: string) => void;
  declineInvite: (sessionId: string) => void;
}

export const P2PContext = createContext<P2PContextValue | undefined>(undefined);
