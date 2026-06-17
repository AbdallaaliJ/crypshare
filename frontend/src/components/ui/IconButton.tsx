import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface IconButtonProps {
  icon: LucideIcon;
  label: string;
  active?: boolean;
  className?: string;
}

export const IconButton: React.FC<IconButtonProps> = ({ icon: Icon, label, active, className = "" }) => (
  <span
    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors duration-150 group border
      ${active 
        ? 'bg-[var(--brand-blue)] text-white border-[var(--brand-blue)] shadow-sm'
        : 'text-[var(--app-muted)] hover:text-[var(--app-text)] hover:bg-[var(--app-surface-muted)] border-transparent'} ${className}`}
  >
    <Icon className={`w-4 h-4 ${active ? 'text-white' : 'group-hover:text-[var(--brand-blue)] transition-colors'}`} />
    <span className="text-sm font-medium tracking-normal">{label}</span>
  </span>
);
