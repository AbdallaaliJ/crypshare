import React from 'react';

interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  loading?: boolean;
  variant?: 'primary' | 'secondary';
  className?: string;
}

export const ActionButton: React.FC<ActionButtonProps> = ({ children, onClick, loading, variant = "primary", className = "", ...props }) => {
  const styles = {
    primary: "bg-[var(--brand-navy)] hover:bg-[var(--brand-navy-2)] text-white shadow-sm",
    secondary: "bg-[var(--app-surface)] hover:bg-[var(--app-surface-muted)] text-[var(--app-text)] border border-[var(--app-border)]",
  };
  return (
    <button 
      onClick={onClick}
      disabled={loading || props.disabled}
      className={`px-5 py-2.5 rounded-lg font-bold transition-all active:scale-[0.98] flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed ${styles[variant]} ${className}`}
      {...props}
    >
      {loading && <div className="w-4 h-4 border-2 border-current/20 border-t-current rounded-full animate-spin" />}
      {children}
    </button>
  );
};
