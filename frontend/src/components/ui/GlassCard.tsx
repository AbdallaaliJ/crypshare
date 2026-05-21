import React from 'react';

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
}

export const GlassCard: React.FC<GlassCardProps> = ({ children, className = "" }) => (
  <div className={`bg-slate-900/20 backdrop-blur-md border border-white/5 rounded-2xl ${className}`}>
    {children}
  </div>
);
