import { createContext } from 'react';

export interface AuthState {
  username: string;
  kek: CryptoKey | null;
  privateKeyECDH: CryptoKey | null;
  privateKeyECDSA: CryptoKey | null;
  identityPublicKeyECDH: string;
  identityPublicKeyECDSA: string;
  role: string;
  token: string;
  csrfToken?: string;
  sessionExpiresAt: number;
}

export interface AuthContextProps {
  user: AuthState | null;
  login: (userData: AuthState) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

export const AuthContext = createContext<AuthContextProps | undefined>(undefined);
