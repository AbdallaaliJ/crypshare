import React, { useState, type ReactNode } from 'react';
import { AuthContext, type AuthState } from './AuthContextBase';

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
