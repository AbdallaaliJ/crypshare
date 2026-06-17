import React, { useState, type ReactNode } from 'react';
import { AuthContext, type AuthState } from './AuthContextBase';
import { clearCsrfToken } from '../config/auth';

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthState | null>(null);

  const login = (userData: AuthState) => {
    setUser(userData);
  };

  const logout = () => {
    setUser(null);
    clearCsrfToken();
  };

  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
};
