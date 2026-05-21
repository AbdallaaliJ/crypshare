import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface IconButtonProps {
  icon: LucideIcon;
  label: string;
  active?: boolean;
  onClick?: () => void;
  className?: string;
}

export const IconButton: React.FC<IconButtonProps> = ({ icon: Icon, label, active, onClick, className = "" }) => (
  <button 
    onClick={onClick}
    className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group
      ${active 
        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_15px_rgba(34,211,238,0.1)]' 
        : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'} ${className}`}
  >
    <Icon className={`w-5 h-5 ${active ? 'text-cyan-400' : 'group-hover:text-cyan-400 transition-colors'}`} />
    <span className="text-sm font-medium tracking-tight">{label}</span>
  </button>
);
