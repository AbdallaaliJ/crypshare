import { useContext } from 'react';
import { P2PContext } from '../contexts/P2PContextBase';

export function useP2P() {
  const context = useContext(P2PContext);
  if (!context) {
    throw new Error('useP2P must be used within P2PProvider');
  }
  return context;
}
