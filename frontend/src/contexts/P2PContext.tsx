import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { apiUrl, wsUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/useToast';
import { getErrorMessage } from '../utils/errors';
import { P2PContext, type P2PContextValue, type P2PMessage, type P2PMessageHandler, type PendingP2PInvite } from './P2PContextBase';

export function P2PProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [socketReady, setSocketReady] = useState(false);
  const [pendingInvites, setPendingInvites] = useState<PendingP2PInvite[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef(new Set<P2PMessageHandler>());
  const reconnectTimerRef = useRef<number | null>(null);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const dispatchMessage = useCallback((message: P2PMessage) => {
    if (message.type === 'p2p-invite' && message.sessionId && message.senderUsername && message.expiresAt) {
      setPendingInvites((current) => {
        if (current.some((invite) => invite.sessionId === message.sessionId)) return current;
        return [
          {
            sessionId: message.sessionId!,
            senderUsername: message.senderUsername!,
            senderFingerprint: message.senderFingerprint,
            relayAllowed: message.relayAllowed === true,
            expiresAt: message.expiresAt!,
            createdAt: message.createdAt,
            unread: true
          },
          ...current
        ];
      });
      showToast(`Incoming P2P transfer from ${message.senderUsername}.`, 'info');
    }

    if (message.type === 'p2p-expired' || message.type === 'p2p-declined') {
      if (message.sessionId) {
        setPendingInvites((current) => current.filter((invite) => invite.sessionId !== message.sessionId));
      }
    }

    handlersRef.current.forEach((handler) => {
      Promise.resolve(handler(message)).catch((err) => {
        console.error('P2P message handler failed.', err);
      });
    });
  }, [showToast]);

  useEffect(() => {
    if (!user) {
      socketRef.current?.close();
      socketRef.current = null;
      setSocketReady(false);
      setPendingInvites([]);
      clearReconnectTimer();
      return;
    }

    let cancelled = false;

    const connect = async () => {
      clearReconnectTimer();
      try {
        const res = await fetch(apiUrl('/p2p/signaling-ticket'), {
          method: 'POST',
          headers: authHeaders(user.token)
        });
        const data = await res.json() as { ticket?: string; error?: string };
        if (!res.ok || !data.ticket) throw new Error(data.error || 'Unable to create P2P signaling ticket.');
        if (cancelled) return;

        const socket = new WebSocket(wsUrl(`/p2p/signaling?ticket=${encodeURIComponent(data.ticket)}`));
        socketRef.current = socket;
        socket.onopen = () => setSocketReady(true);
        socket.onclose = () => {
          if (socketRef.current === socket) {
            socketRef.current = null;
          }
          setSocketReady(false);
          if (!cancelled) {
            reconnectTimerRef.current = window.setTimeout(connect, 3000);
          }
        };
        socket.onerror = () => {
          setSocketReady(false);
        };
        socket.onmessage = (event) => {
          try {
            dispatchMessage(JSON.parse(event.data) as P2PMessage);
          } catch {
            console.error('Invalid P2P signaling payload.');
          }
        };
      } catch (err: unknown) {
        setSocketReady(false);
        if (!cancelled) {
          console.error(getErrorMessage(err, 'Unable to connect P2P signaling.'));
          reconnectTimerRef.current = window.setTimeout(connect, 5000);
        }
      }
    };

    connect();

    return () => {
      cancelled = true;
      clearReconnectTimer();
      socketRef.current?.close();
      socketRef.current = null;
      setSocketReady(false);
    };
  }, [clearReconnectTimer, dispatchMessage, user]);

  const sendSignaling = useCallback((message: Record<string, unknown>) => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error('P2P signaling is not connected.');
    }
    socket.send(JSON.stringify(message));
  }, []);

  const subscribeMessages = useCallback((handler: P2PMessageHandler) => {
    handlersRef.current.add(handler);
    return () => {
      handlersRef.current.delete(handler);
    };
  }, []);

  const markInviteRead = useCallback((sessionId: string) => {
    setPendingInvites((current) => current.map((invite) => (
      invite.sessionId === sessionId ? { ...invite, unread: false } : invite
    )));
  }, []);

  const removeInvite = useCallback((sessionId: string) => {
    setPendingInvites((current) => current.filter((invite) => invite.sessionId !== sessionId));
  }, []);

  const declineInvite = useCallback((sessionId: string) => {
    try {
      sendSignaling({ type: 'p2p-decline', sessionId });
      removeInvite(sessionId);
    } catch (err: unknown) {
      showToast(getErrorMessage(err, 'Unable to decline P2P invite.'), 'error');
    }
  }, [removeInvite, sendSignaling, showToast]);

  const unreadCount = pendingInvites.filter((invite) => invite.unread).length;

  const value = useMemo<P2PContextValue>(() => ({
    socketReady,
    pendingInvites,
    unreadCount,
    sendSignaling,
    subscribeMessages,
    markInviteRead,
    removeInvite,
    declineInvite
  }), [declineInvite, markInviteRead, pendingInvites, removeInvite, sendSignaling, socketReady, subscribeMessages, unreadCount]);

  return <P2PContext.Provider value={value}>{children}</P2PContext.Provider>;
}
