import React, { createContext, useContext, useState, type ReactNode } from 'react';

interface AuthState {
  username: string;
  kek: CryptoKey | null;
  privateKeyECDH: CryptoKey | null;
  privateKeyECDSA: CryptoKey | null;
  identityPublicKeyECDH: string;
}

interface AuthContextProps {
  user: AuthState | null;
  login: (userData: AuthState) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextProps | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthState | null>(null);

  const login = (userData: AuthState) => {
    setUser(userData);
  };

  const logout = () => {
    setUser(null);
    // Real app might also clear localStorage if anything was persisted
  };

  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
