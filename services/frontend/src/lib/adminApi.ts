/**
 * Helpers for calling admin API endpoints from client-side components.
 *
 * All requests use credentials: 'include' so the session cookie is forwarded.
 * Mutating admin endpoints require an action token in the x-admin-action header.
 * The browser automatically includes the Origin header on POST requests, which
 * satisfies the backend's require_admin_origin check.
 */

export async function adminFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const apiPath = path.startsWith('/admin') ? `/api${path}` : path;
  return fetch(apiPath, {
    ...init,
    credentials: 'include',
  });
}

export async function getActionToken(): Promise<string> {
  const res = await adminFetch('/admin/actions/token', { method: 'POST' });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`Failed to get action token: ${text}`);
  }
  const data = await res.json();
  return data.token as string;
}

export async function adminAction(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = await getActionToken();
  const existingHeaders = new Headers(init.headers ?? {});
  existingHeaders.set('x-admin-action', token);
  return adminFetch(path, { ...init, headers: existingHeaders });
}
