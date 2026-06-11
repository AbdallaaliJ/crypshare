import React from 'react';
import { Outlet, Link } from 'react-router-dom';
import { CrypShareLogo } from '../components/brand/CrypShareLogo';
import { ThemeToggle } from '../components/theme/ThemeToggle';

export const PublicLayout: React.FC = () => {
  return (
    <div className="app-shell min-h-screen flex flex-col relative overflow-hidden">
      <div className="app-main absolute inset-0 pointer-events-none" />

      <nav className="app-header flex flex-row justify-between items-center gap-3 py-4 px-4 md:px-12 border-b backdrop-blur-md sticky top-0 z-50">
        <Link to="/" className="flex items-center gap-3 group" style={{ textDecoration: 'none' }}>
          <CrypShareLogo markSize={38} wordmarkClassName="text-xl" />
        </Link>
        
        <div className="flex flex-row gap-2 sm:gap-3 items-center">
          <ThemeToggle compact />
          <Link 
            to="/login" 
            className="px-4 sm:px-5 py-2.5 bg-[var(--app-surface)] hover:bg-[var(--app-surface-muted)] text-[var(--app-text)] border border-[var(--app-border)] rounded-lg text-xs font-bold uppercase tracking-wider transition-all text-center"
            style={{ textDecoration: 'none' }}
          >
            Login
          </Link>
          <Link 
            to="/register" 
            className="px-4 sm:px-5 py-2.5 bg-[var(--brand-navy)] hover:bg-[var(--brand-navy-2)] text-white rounded-lg text-xs font-bold uppercase tracking-wider transition-all text-center shadow-sm"
            style={{ textDecoration: 'none' }}
          >
            <span className="sm:hidden">Create</span>
            <span className="hidden sm:inline">Create Account</span>
          </Link>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 flex items-center justify-center p-6 relative z-10">
        <Outlet />
      </main>
    </div>
  );
};
