import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Shield, Plus, Inbox, History, Settings, LogOut, User, Terminal, ChevronRight, X } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLogContext } from '../contexts/LogContext';
import { IconButton } from '../components/ui/IconButton';

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { logs } = useLogContext();
  const [showConsole, setShowConsole] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex selection:bg-cyan-500/30">
      {/* --- SIDEBAR NAVIGATION --- */}
      <aside className="w-64 border-r border-white/5 bg-slate-900/20 backdrop-blur-xl flex flex-col fixed inset-y-0 left-0 z-40">
        <div className="p-8 flex items-center gap-3">
          <Shield className="w-7 h-7 text-cyan-400" />
          <span className="font-bold text-lg text-white">CrypShare</span>
        </div>

        <nav className="flex-1 px-4 space-y-2">
          <NavLink to="/dashboard/send" style={{ textDecoration: 'none' }}>
            {({ isActive }) => <IconButton icon={Plus} label="Dispatch" active={isActive} />}
          </NavLink>
          <NavLink to="/dashboard/inbox" style={{ textDecoration: 'none' }}>
            {({ isActive }) => <IconButton icon={Inbox} label="Inbox" active={isActive} />}
          </NavLink>
          <NavLink to="/dashboard/vault" style={{ textDecoration: 'none' }}>
            {({ isActive }) => <IconButton icon={History} label="Audit Vault" active={isActive} />}
          </NavLink>
          <NavLink to="/dashboard/settings" style={{ textDecoration: 'none' }}>
            {({ isActive }) => <IconButton icon={Settings} label="Identity" active={isActive} />}
          </NavLink>
        </nav>

        <div className="p-6 border-t border-white/5 space-y-4">
          <div className="flex items-center gap-3 bg-white/5 p-3 rounded-xl border border-white/5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
              <User className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-bold text-white truncate">{user?.username || "anonymous"}</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-tighter">Identity Verified</p>
            </div>
          </div>
          <button onClick={handleLogout} className="w-full flex items-center justify-center gap-2 py-3 text-xs font-bold text-slate-500 hover:text-red-400 transition-colors uppercase tracking-widest">
            <LogOut className="w-4 h-4" /> Lock Vault
          </button>
        </div>
      </aside>

      {/* --- MAIN CONTENT AREA --- */}
      <main className="flex-1 ml-64 p-10 pb-32">
        <Outlet />
      </main>

      {/* --- CRYPTO CONSOLE (Togglable Drawer) --- */}
      <div className={`fixed bottom-0 right-0 left-64 transition-all duration-300 z-50 ${showConsole ? 'h-64' : 'h-10'}`}>
        <div 
          onClick={() => setShowConsole(!showConsole)}
          className="bg-slate-900 border-t border-white/10 h-10 flex items-center justify-between px-6 cursor-pointer hover:bg-slate-800 transition-colors"
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-3 h-3 text-cyan-400" />
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Cryptographic Console</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-[9px] font-mono text-slate-500">ENGINE_STABLE</span>
            {showConsole ? <X className="w-3 h-3 ml-2" /> : <ChevronRight className="w-3 h-3 ml-2 -rotate-90" />}
          </div>
        </div>
        
        {showConsole && (
          <div className="h-full bg-black/90 p-6 font-mono text-xs text-emerald-400/80 overflow-y-auto">
            {logs.map((log, i) => (
              <div key={i} className="mb-1 leading-relaxed">
                <span className="opacity-40 text-[10px] mr-3">{new Date().toLocaleTimeString()}</span>
                {log}
              </div>
            ))}
            <div className="animate-pulse">_</div>
          </div>
        )}
      </div>
    </div>
  );
};
