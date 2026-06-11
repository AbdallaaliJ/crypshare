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
    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group border
      ${active 
        ? 'bg-[color-mix(in_srgb,var(--brand-cyan)_14%,var(--app-surface))] text-[var(--app-text)] border-[color-mix(in_srgb,var(--brand-cyan)_42%,var(--app-border))] shadow-sm' 
        : 'text-[var(--app-muted)] hover:text-[var(--app-text)] hover:bg-[var(--app-surface)] border-transparent'} ${className}`}
  >
    <Icon className={`w-4 h-4 ${active ? 'text-[var(--brand-cyan)]' : 'group-hover:text-[var(--brand-cyan)] transition-colors'}`} />
    <span className="text-sm font-semibold tracking-tight">{label}</span>
  </button>
);
