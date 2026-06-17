const DEFAULT_API_BASE_URL = 'http://localhost:3001';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL;
export const API_CREDENTIALS_ENABLED = import.meta.env.VITE_SESSION_COOKIE_ENABLED === 'true';

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

export function wsUrl(path: string): string {
  const base = API_BASE_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
  return `${base}${path.startsWith('/') ? path : `/${path}`}`;
}

function requestUrl(input: RequestInfo | URL) {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

export function installApiFetchDefaults() {
  if (typeof window === 'undefined') return;
  const nativeFetch = window.fetch.bind(window);

  window.fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = requestUrl(input);
    if (API_CREDENTIALS_ENABLED && url.startsWith(API_BASE_URL)) {
      return nativeFetch(input, {
        ...init,
        credentials: init.credentials ?? 'include'
      });
    }

    return nativeFetch(input, init);
  };
}
