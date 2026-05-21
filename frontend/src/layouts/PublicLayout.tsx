import React from 'react';
import { Outlet, Link } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';

export const PublicLayout: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_-20%,_rgba(34,211,238,0.06),_transparent)] pointer-events-none" />

      {/* Navbar */}
      <nav className="flex flex-row justify-between items-center py-5 px-6 md:px-12 border-b border-white/5 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
        <Link to="/" className="flex items-center gap-3 group" style={{ textDecoration: 'none' }}>
          <div className="p-2 bg-cyan-500/10 rounded-xl border border-cyan-500/20 group-hover:scale-105 transition-transform">
            <ShieldCheck size={24} className="text-cyan-400" />
          </div>
          <div>
            <h1 className="margin-0 text-lg font-bold tracking-tight text-white">CrypShare</h1>
          </div>
        </Link>
        
        <div className="flex flex-row gap-3">
          <Link 
            to="/login" 
            className="px-5 py-2.5 bg-white/5 hover:bg-white/10 text-white border border-white/10 rounded-xl text-xs font-bold uppercase tracking-wider transition-all text-center"
            style={{ textDecoration: 'none' }}
          >
            Login
          </Link>
          <Link 
            to="/register" 
            className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-xl text-xs font-bold uppercase tracking-wider transition-all text-center shadow-[0_0_15px_rgba(34,211,238,0.1)]"
            style={{ textDecoration: 'none' }}
          >
            Create Account
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
