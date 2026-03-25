import { useState, useEffect, useRef } from 'react';
import { adminFetch, adminAction } from '../../../lib/adminApi';

interface User {
  id: string;
  email: string;
  username: string;
  is_admin: boolean;
  created_at: string;
  disabled_at: string | null;
  last_seen_at: string | null;
  active_sessions: number;
}

type ActionType = 'disable' | 'enable' | 'promote' | 'demote' | 'revoke';

interface PendingAction {
  userId: string;
  type: ActionType;
  label: string;
}

function formatDate(iso: string | null): string {
  if (!iso) return 'Never';
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

interface Props {
  currentUserId: string;
}

export default function UsersPage({ currentUserId }: Props) {
  const [users, setUsers]                 = useState<User[]>([]);
  const [loading, setLoading]             = useState(true);
  const [error, setError]                 = useState<string | null>(null);
  const [search, setSearch]               = useState('');
  const [includeDisabled, setIncludeDisabled] = useState(true);
  const [pending, setPending]             = useState<PendingAction | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const firstRender = useRef(true);

  async function loadUsers(q: string, incl: boolean, silent = false) {
    if (!silent) setLoading(true);
    try {
      const params = new URLSearchParams({ include_disabled: String(incl) });
      if (q.trim()) params.set('search', q.trim());
      const res = await adminFetch(`/admin/users?${params}`);
      if (!res.ok) throw new Error('Failed to load users.');
      const data = await res.json();
      setUsers(data.items ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load users.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers('', true);
  }, []);

  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    setLoading(true);
    const t = setTimeout(() => loadUsers(search, includeDisabled), 300);
    return () => clearTimeout(t);
  }, [search, includeDisabled]);

  async function executeAction(userId: string, type: ActionType) {
    setActionLoading(userId);
    setPending(null);
    try {
      const jsonHeaders = { 'Content-Type': 'application/json' };
      let res: Response;
      if (type === 'disable') {
        res = await adminAction(`/admin/users/${userId}/disable`, { method: 'POST' });
      } else if (type === 'enable') {
        res = await adminAction(`/admin/users/${userId}/enable`, { method: 'POST' });
      } else if (type === 'promote') {
        res = await adminAction(`/admin/users/${userId}/admin`, {
          method: 'POST', headers: jsonHeaders, body: JSON.stringify({ is_admin: true }),
        });
      } else if (type === 'demote') {
        res = await adminAction(`/admin/users/${userId}/admin`, {
          method: 'POST', headers: jsonHeaders, body: JSON.stringify({ is_admin: false }),
        });
      } else {
        res = await adminAction(`/admin/users/${userId}/sessions/revoke`, { method: 'POST' });
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError((body as { detail?: string }).detail ?? 'Action failed.');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed.');
    } finally {
      setActionLoading(null);
      loadUsers(search, includeDisabled, true);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Users</h1>
        {!loading && (
          <span className="text-sm text-gray-400">
            {users.length} {users.length === 1 ? 'user' : 'users'}
          </span>
        )}
      </div>

      {error && (
        <div className="flex items-center justify-between bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="ml-4 font-medium text-red-400 hover:text-red-600 transition-colors"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
        <div className="flex items-center gap-4 px-4 py-3 border-b border-gray-100">
          <input
            type="text"
            placeholder="Search by username or email..."
            value={search}
            onChange={e => { setPending(null); setSearch(e.target.value); }}
            className="flex-1 text-sm border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary"
          />
          <label className="flex items-center gap-2 text-sm text-gray-600 select-none cursor-pointer whitespace-nowrap">
            <input
              type="checkbox"
              checked={includeDisabled}
              onChange={e => { setPending(null); setIncludeDisabled(e.target.checked); }}
              className="accent-primary"
            />
            Show disabled
          </label>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-sm text-gray-400">
            Loading...
          </div>
        ) : users.length === 0 ? (
          <div className="flex items-center justify-center py-16 text-sm text-gray-400">
            No users found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-4 py-3 text-left font-medium">User</th>
                  <th className="px-4 py-3 text-left font-medium">Status</th>
                  <th className="px-4 py-3 text-left font-medium">Role</th>
                  <th className="px-4 py-3 text-left font-medium">Sessions</th>
                  <th className="px-4 py-3 text-left font-medium">Last Seen</th>
                  <th className="px-4 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {users.map(user => {
                  const isDisabled  = !!user.disabled_at;
                  const isSelf      = user.id === currentUserId;
                  const isPending   = pending?.userId === user.id;
                  const isActing    = actionLoading === user.id;

                  return (
                    <tr key={user.id} className="hover:bg-gray-50 transition-colors">

                      <td className="px-4 py-3">
                        <div className="font-medium text-gray-900">{user.username}</div>
                        <div className="text-xs text-gray-400">{user.email}</div>
                      </td>

                      <td className="px-4 py-3">
                        {isDisabled ? (
                          <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-red-100 text-red-700">
                            Disabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700">
                            Active
                          </span>
                        )}
                      </td>

                      <td className="px-4 py-3">
                        {user.is_admin ? (
                          <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-primary/10 text-primary">
                            Admin
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400">User</span>
                        )}
                      </td>

                      <td className="px-4 py-3 text-gray-700">
                        {user.active_sessions}
                      </td>

                      <td className="px-4 py-3 text-gray-500">
                        {formatDate(user.last_seen_at)}
                      </td>

                      <td className="px-4 py-3 text-right">
                        {isActing ? (
                          <span className="text-xs text-gray-400">Working...</span>
                        ) : isPending ? (
                          <span className="inline-flex items-center gap-2">
                            <span className="text-xs text-gray-600">
                              Confirm {pending.label}?
                            </span>
                            <button
                              onClick={() => executeAction(user.id, pending.type)}
                              className="rounded px-2 py-1 text-xs font-medium text-white bg-red-500 hover:bg-red-600 transition-colors"
                            >
                              Yes
                            </button>
                            <button
                              onClick={() => setPending(null)}
                              className="rounded border border-gray-200 px-2 py-1 text-xs font-medium text-gray-500 hover:text-gray-700 transition-colors"
                            >
                              Cancel
                            </button>
                          </span>
                        ) : (
                          <span className="inline-flex items-center justify-end gap-1.5">
                            {isDisabled ? (
                              <button
                                onClick={() => setPending({ userId: user.id, type: 'enable', label: 'enable' })}
                                className="rounded border border-green-200 px-2 py-1 text-xs text-green-700 hover:bg-green-50 transition-colors"
                              >
                                Enable
                              </button>
                            ) : (
                              <button
                                onClick={() => setPending({ userId: user.id, type: 'disable', label: 'disable' })}
                                className="rounded border border-red-200 px-2 py-1 text-xs text-red-600 hover:bg-red-50 transition-colors"
                              >
                                Disable
                              </button>
                            )}
                            {user.is_admin ? (
                              <button
                                disabled={isSelf}
                                onClick={() => setPending({ userId: user.id, type: 'demote', label: 'remove admin' })}
                                className="rounded border border-gray-200 px-2 py-1 text-xs text-gray-600 hover:bg-gray-50 transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                              >
                                Remove Admin
                              </button>
                            ) : (
                              <button
                                onClick={() => setPending({ userId: user.id, type: 'promote', label: 'make admin' })}
                                className="rounded border border-gray-200 px-2 py-1 text-xs text-gray-600 hover:bg-gray-50 transition-colors"
                              >
                                Make Admin
                              </button>
                            )}
                            <button
                              disabled={isSelf || user.active_sessions === 0}
                              onClick={() => setPending({ userId: user.id, type: 'revoke', label: 'revoke sessions' })}
                              className="rounded border border-gray-200 px-2 py-1 text-xs text-gray-600 hover:bg-gray-50 transition-colors disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              Revoke Sessions
                            </button>
                          </span>
                        )}
                      </td>

                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
