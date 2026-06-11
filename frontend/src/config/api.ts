const DEFAULT_API_BASE_URL = 'http://localhost:3001';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL;

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

export function wsUrl(path: string): string {
  const base = API_BASE_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
  return `${base}${path.startsWith('/') ? path : `/${path}`}`;
}
