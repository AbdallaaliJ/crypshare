import React from 'react';

interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  loading?: boolean;
  variant?: 'primary' | 'secondary';
  className?: string;
}

export const ActionButton: React.FC<ActionButtonProps> = ({ children, onClick, loading, variant = "primary", className = "", ...props }) => {
  const styles = {
    primary: "bg-cyan-500 hover:bg-cyan-400 text-slate-950",
    secondary: "bg-white/5 hover:bg-white/10 text-white border border-white/10",
  };
  return (
    <button 
      onClick={onClick}
      disabled={loading || props.disabled}
      className={`px-6 py-3 rounded-xl font-bold transition-all active:scale-95 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed ${styles[variant]} ${className}`}
      {...props}
    >
      {loading && <div className="w-4 h-4 border-2 border-current/20 border-t-current rounded-full animate-spin" />}
      {children}
    </button>
  );
};
