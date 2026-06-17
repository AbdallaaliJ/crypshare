import React from 'react';

type StatusTone = 'success' | 'warning' | 'danger' | 'primary' | 'accent' | 'neutral';

const toneClasses: Record<StatusTone, string> = {
  success: 'bg-[color-mix(in_srgb,var(--success-color)_12%,var(--app-surface))] text-[var(--success-color)] border-[color-mix(in_srgb,var(--success-color)_28%,var(--app-border))]',
  warning: 'bg-[color-mix(in_srgb,var(--warning-color)_14%,var(--app-surface))] text-[var(--warning-color)] border-[color-mix(in_srgb,var(--warning-color)_30%,var(--app-border))]',
  danger: 'bg-[color-mix(in_srgb,var(--danger-color)_12%,var(--app-surface))] text-[var(--danger-color)] border-[color-mix(in_srgb,var(--danger-color)_28%,var(--app-border))]',
  primary: 'bg-[color-mix(in_srgb,var(--brand-blue)_12%,var(--app-surface))] text-[var(--brand-blue)] border-[color-mix(in_srgb,var(--brand-blue)_28%,var(--app-border))]',
  accent: 'bg-[color-mix(in_srgb,var(--brand-teal)_14%,var(--app-surface))] text-[var(--brand-teal)] border-[color-mix(in_srgb,var(--brand-teal)_30%,var(--app-border))]',
  neutral: 'bg-[var(--app-surface-muted)] text-[var(--app-muted)] border-[var(--app-border)]'
};

export function StatusBadge({
  children,
  tone = 'neutral',
  className = ''
}: {
  children: React.ReactNode;
  tone?: StatusTone;
  className?: string;
}) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${toneClasses[tone]} ${className}`}>
      {children}
    </span>
  );
}
