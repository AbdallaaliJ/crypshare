import React from 'react';
import { Monitor, ShieldCheck, SlidersHorizontal, Table2, Trash2 } from 'lucide-react';
import { GlassCard } from '../components/ui/GlassCard';
import { useTheme } from '../hooks/useTheme';
import { useUserPreferences, type UserPreferences } from '../utils/preferences';

function ToggleRow({
  icon: Icon,
  title,
  description,
  checked,
  onChange
}: {
  icon: React.ElementType;
  title: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-[var(--app-border)] bg-[var(--app-surface)] p-4">
      <div className="flex min-w-0 items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--app-surface-muted)] text-[var(--brand-blue)]">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-[var(--app-text)]">{title}</p>
          <p className="mt-1 text-xs leading-5 text-[var(--app-muted)]">{description}</p>
        </div>
      </div>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={`relative h-7 w-12 shrink-0 rounded-full border transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-blue)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--app-bg)] ${
          checked
            ? 'border-[var(--brand-blue)] bg-[var(--brand-blue)]'
            : 'border-[var(--app-border-strong)] bg-[var(--app-surface-muted)]'
        }`}
        aria-pressed={checked}
        aria-label={title}
      >
        <span
          className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${checked ? 'translate-x-5' : 'translate-x-1'}`}
        />
      </button>
    </div>
  );
}

export const SettingsPage: React.FC = () => {
  const { theme, setTheme } = useTheme();
  const { preferences, setPreferences } = useUserPreferences();

  const updatePreference = (key: keyof UserPreferences, value: boolean) => {
    setPreferences((current) => ({ ...current, [key]: value }));
  };

  return (
    <div className="mx-auto max-w-6xl animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <h2 className="mb-2 text-3xl font-bold text-[var(--app-text)]">Settings</h2>
          <p className="text-[var(--app-muted)]">Manage local appearance and file-workflow behavior.</p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[0.8fr_1.2fr]">
        <GlassCard className="p-6">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--brand-blue)_12%,var(--app-surface))] text-[var(--brand-blue)]">
              <Monitor className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-[var(--app-text)]">Appearance</h3>
              <p className="text-xs text-[var(--app-muted)]">Choose the interface mode.</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {(['light', 'dark'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setTheme(mode)}
                className={`rounded-lg border px-4 py-3 text-sm font-semibold capitalize transition-colors ${
                  theme === mode
                    ? 'border-[var(--brand-blue)] bg-[color-mix(in_srgb,var(--brand-blue)_12%,var(--app-surface))] text-[var(--brand-blue)]'
                    : 'border-[var(--app-border)] bg-[var(--app-surface)] text-[var(--app-muted)] hover:text-[var(--app-text)]'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
          <p className="mt-4 text-xs leading-5 text-[var(--app-muted)]">
            Theme choice is stored locally in this browser.
          </p>
        </GlassCard>

        <GlassCard className="p-6">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--brand-teal)_14%,var(--app-surface))] text-[var(--brand-teal)]">
              <SlidersHorizontal className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-[var(--app-text)]">Preferences</h3>
              <p className="text-xs text-[var(--app-muted)]">Local controls that affect visible file workflows.</p>
            </div>
          </div>

          <div className="grid gap-3">
            <ToggleRow
              icon={Trash2}
              title="Confirm destructive file actions"
              description="Ask before moving files to Trash, permanently deleting, or revoking a grant."
              checked={preferences.confirmDestructiveActions}
              onChange={(checked) => updatePreference('confirmDestructiveActions', checked)}
            />
            <ToggleRow
              icon={Table2}
              title="Dense file tables"
              description="Use tighter file rows in Files when you prefer scanning more items at once."
              checked={preferences.denseFileTables}
              onChange={(checked) => updatePreference('denseFileTables', checked)}
            />
            <ToggleRow
              icon={ShieldCheck}
              title="Security guidance"
              description="Show short explanations for encrypted upload, trust, and sharing gates."
              checked={preferences.securityHints}
              onChange={(checked) => updatePreference('securityHints', checked)}
            />
          </div>
        </GlassCard>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        {[
          { icon: ShieldCheck, title: 'Security Center', body: 'Identity, pre-keys, sessions, and checkpoints live in Security.' },
          { icon: SlidersHorizontal, title: 'Local Only', body: 'These preferences stay in browser storage and are not sent as account settings.' }
        ].map((item) => {
          const Icon = item.icon;
          return (
            <GlassCard key={item.title} className="p-5">
              <Icon className="mb-3 h-5 w-5 text-[var(--brand-blue)]" />
              <p className="font-semibold text-[var(--app-text)]">{item.title}</p>
              <p className="mt-2 text-sm text-[var(--app-muted)]">{item.body}</p>
            </GlassCard>
          );
        })}
      </div>
    </div>
  );
};
