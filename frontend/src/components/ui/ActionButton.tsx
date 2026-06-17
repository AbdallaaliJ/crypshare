import React from 'react';

interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  loading?: boolean;
  variant?: 'primary' | 'secondary';
  className?: string;
}

export const ActionButton: React.FC<ActionButtonProps> = ({ children, onClick, loading, variant = "primary", className = "", ...props }) => {
  const styles = {
    primary: "bg-[var(--brand-blue)] text-white hover:bg-blue-700 focus-visible:ring-[var(--brand-cyan)] active:brightness-95",
    secondary: "bg-[var(--app-surface)] hover:bg-[var(--app-surface-muted)] text-[var(--app-text)] border border-[var(--app-border)] hover:border-[var(--app-border-strong)] focus-visible:ring-[var(--app-border)] active:brightness-95",
  };
  return (
    <button 
      onClick={onClick}
      disabled={loading || props.disabled}
      className={`px-5 py-2.5 rounded-lg font-semibold text-sm tracking-normal transition-colors duration-150 ease-out flex items-center justify-center gap-2 disabled:opacity-50 disabled:pointer-events-none focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--app-bg)] cursor-pointer ${styles[variant]} ${className}`}
      {...props}
    >
      {loading && <div className="w-4 h-4 border-2 border-current/20 border-t-current rounded-full animate-spin" />}
      {children}
    </button>
  );
};
