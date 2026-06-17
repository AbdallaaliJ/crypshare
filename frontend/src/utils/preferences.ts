import { useEffect, useState } from 'react';

export type UserPreferences = {
  confirmDestructiveActions: boolean;
  denseFileTables: boolean;
  securityHints: boolean;
};

const STORAGE_KEY = 'crypshare.preferences';
const PREFERENCES_CHANGED_EVENT = 'crypshare.preferences-changed';

export const defaultUserPreferences: UserPreferences = {
  confirmDestructiveActions: true,
  denseFileTables: false,
  securityHints: true
};

export function loadUserPreferences(): UserPreferences {
  if (typeof window === 'undefined') return defaultUserPreferences;

  try {
    const raw = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || '{}') as Partial<UserPreferences> & {
      confirmDelete?: boolean;
      compactTables?: boolean;
      securityReminders?: boolean;
    };

    return {
      ...defaultUserPreferences,
      ...raw,
      confirmDestructiveActions: raw.confirmDestructiveActions ?? raw.confirmDelete ?? defaultUserPreferences.confirmDestructiveActions,
      denseFileTables: raw.denseFileTables ?? raw.compactTables ?? defaultUserPreferences.denseFileTables,
      securityHints: raw.securityHints ?? raw.securityReminders ?? defaultUserPreferences.securityHints
    };
  } catch {
    return defaultUserPreferences;
  }
}

export function saveUserPreferences(preferences: UserPreferences) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
  window.dispatchEvent(new CustomEvent(PREFERENCES_CHANGED_EVENT, { detail: preferences }));
}

export function useUserPreferences() {
  const [preferences, setPreferencesState] = useState<UserPreferences>(loadUserPreferences);

  useEffect(() => {
    const handleChange = () => setPreferencesState(loadUserPreferences());
    window.addEventListener(PREFERENCES_CHANGED_EVENT, handleChange);
    window.addEventListener('storage', handleChange);
    return () => {
      window.removeEventListener(PREFERENCES_CHANGED_EVENT, handleChange);
      window.removeEventListener('storage', handleChange);
    };
  }, []);

  const setPreferences = (updater: UserPreferences | ((current: UserPreferences) => UserPreferences)) => {
    setPreferencesState((current) => {
      const next = typeof updater === 'function' ? updater(current) : updater;
      saveUserPreferences(next);
      return next;
    });
  };

  return { preferences, setPreferences };
}
