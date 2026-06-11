import type { AuthState } from '../contexts/AuthContextBase';
import { apiUrl } from '../config/api';
import { authHeaders } from '../config/auth';
import { generatePreKeys } from './crypto';

export interface PreKeyStatus {
  total: number;
  available: number;
  consumed: number;
}

export const LOW_PREKEY_THRESHOLD = 20;
export const PREKEY_REFILL_COUNT = 100;
export const AUTO_PREKEY_REFILL_COOLDOWN_MS = 1000 * 60 * 60 * 6;

export function autoPreKeyRefillKey(username: string) {
  return `crypshare.auto-prekey-refill:${username}`;
}

export async function fetchPreKeyStatus(user: AuthState) {
  const res = await fetch(apiUrl(`/prekeys/${user.username}/status`), {
    headers: authHeaders(user.token)
  });
  const data = await res.json() as PreKeyStatus & { error?: string };
  if (!res.ok) throw new Error(data.error || 'Unable to load pre-key inventory.');
  return data;
}

export async function replenishPreKeys(user: AuthState, count = PREKEY_REFILL_COUNT) {
  if (!user.kek) {
    throw new Error('Session key missing. Log in again.');
  }

  const preKeys = await generatePreKeys(user.kek, count);
  const res = await fetch(apiUrl('/upload-prekeys'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(user.token)
    },
    body: JSON.stringify({ username: user.username, preKeys })
  });
  const data = await res.json() as { remaining?: number; error?: string };
  if (!res.ok) throw new Error(data.error || 'Unable to upload pre-keys.');
  return data;
}
