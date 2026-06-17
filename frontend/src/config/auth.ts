const CSRF_STORAGE_KEY = 'crypshare.csrf-token';

export function rememberCsrfToken(token?: string) {
  if (!token) return;
  window.sessionStorage.setItem(CSRF_STORAGE_KEY, token);
}

export function clearCsrfToken() {
  window.sessionStorage.removeItem(CSRF_STORAGE_KEY);
}

export function getCsrfToken() {
  return window.sessionStorage.getItem(CSRF_STORAGE_KEY) || '';
}

export function authHeaders(token?: string): HeadersInit {
  const csrfToken = getCsrfToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {})
  };
}
