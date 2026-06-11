import React from 'react';

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
}

export const GlassCard: React.FC<GlassCardProps> = ({ children, className = "" }) => (
  <div className={`app-card rounded-lg backdrop-blur-md ${className}`}>
    {children}
  </div>
);
