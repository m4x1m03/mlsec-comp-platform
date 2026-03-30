import { useState, useEffect, useRef } from 'react';
import { adminFetch, adminAction } from '../../../lib/adminApi';

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
  });
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface User {
  id: string;
  email: string;
  username: string;
  is_admin: boolean;
}

interface Submission {
  id: string;
  submission_type: string;
  version: string;
  display_name: string | null;
  status: string;
  is_functional: boolean | null;
  created_at: string;
  is_active: boolean;
}

interface EvalPair {
  other_submission_id: string;
  other_submission_type: string;
  other_version: string;
  other_username: string;
  evaluation_status: string | null;
  evaluation_run_id: string | null;
  score: number | null;
}

// ---------------------------------------------------------------------------
// Shared badge helpers
// ---------------------------------------------------------------------------

function TypeBadge({ type }: { type: string }) {
  const cls = type === 'defense'
    ? 'bg-blue-100 text-blue-700'
    : 'bg-amber-100 text-amber-700';
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {type}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    validated:  'bg-green-100 text-green-700',
    evaluated:  'bg-green-100 text-green-700',
    done:       'bg-green-100 text-green-700',
    error:      'bg-red-100 text-red-700',
    failed:     'bg-red-100 text-red-700',
    validating: 'bg-amber-100 text-amber-700',
    evaluating: 'bg-amber-100 text-amber-700',
    submitted:  'bg-gray-100 text-gray-600',
    running:    'bg-blue-100 text-blue-700',
  };
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${styles[status] ?? 'bg-gray-100 text-gray-600'}`}>
      {status}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Third panel: evaluation pairs for a selected submission
// ---------------------------------------------------------------------------

function EvalPairsPanel({ submissionId }: { submissionId: string }) {
  const [pairs, setPairs]     = useState<EvalPair[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setPairs(null);
    adminFetch(`/admin/submissions/${submissionId}/evaluations`).then(async res => {
      if (res.ok) {
        const data = await res.json();
        setPairs(data.pairs);
      } else {
        setPairs([]);
      }
      setLoading(false);
    });
  }, [submissionId]);

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-gray-100">
        <span className="text-sm font-semibold text-gray-700">Counterparts</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-sm text-gray-400">
            Loading...
          </div>
        ) : !pairs || pairs.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-sm text-gray-400">
            No active counterpart submissions.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 border-b border-gray-100">
                <th className="px-4 py-2 text-left font-medium">User</th>
                <th className="px-4 py-2 text-left font-medium">Type</th>
                <th className="px-4 py-2 text-left font-medium">Version</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-left font-medium">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {pairs.map(pair => (
                <tr key={pair.other_submission_id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-2 text-gray-700">{pair.other_username}</td>
                  <td className="px-4 py-2"><TypeBadge type={pair.other_submission_type} /></td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{pair.other_version}</td>
                  <td className="px-4 py-2">
                    {pair.evaluation_status
                      ? <StatusBadge status={pair.evaluation_status} />
                      : <span className="text-gray-400 text-xs">No run</span>}
                  </td>
                  <td className="px-4 py-2 text-gray-700 text-xs">
                    {pair.score != null ? pair.score.toFixed(3) : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Submission table for one type (defense or attack)
// ---------------------------------------------------------------------------

interface SubmissionTableProps {
  submissions: Submission[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function SubmissionTable({ submissions, selectedId, onSelect }: SubmissionTableProps) {
  if (submissions.length === 0) {
    return (
      <div className="px-4 py-8 text-sm text-gray-400 text-center">No submissions.</div>
    );
  }

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 border-b border-gray-100">
          <th className="px-4 py-2 text-left font-medium w-6"></th>
          <th className="px-4 py-2 text-left font-medium">Version</th>
          <th className="px-4 py-2 text-left font-medium">Status</th>
          <th className="px-4 py-2 text-left font-medium">Functional</th>
          <th className="px-4 py-2 text-left font-medium">Created</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100">
        {submissions.map(sub => {
          const isSelected = sub.id === selectedId;
          return (
            <tr
              key={sub.id}
              onClick={() => onSelect(sub.id)}
              className={`cursor-pointer transition-colors ${isSelected ? 'bg-primary/5' : 'hover:bg-gray-50'}`}
            >
              <td className="px-4 py-2">
                {sub.is_active && (
                  <span className="inline-block w-2 h-2 rounded-full bg-green-500" title="Active" />
                )}
              </td>
              <td className="px-4 py-2 font-medium text-gray-800">
                {sub.display_name ?? sub.version}
              </td>
              <td className="px-4 py-2"><StatusBadge status={sub.status} /></td>
              <td className="px-4 py-2">
                {sub.is_functional === true  && <span className="text-green-600 text-xs">Yes</span>}
                {sub.is_functional === false && <span className="text-red-500 text-xs">No</span>}
                {sub.is_functional === null  && <span className="text-gray-400 text-xs">-</span>}
              </td>
              <td className="px-4 py-2 text-gray-500 text-xs whitespace-nowrap">
                {formatDate(sub.created_at)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Middle panel: submissions for a selected user
// ---------------------------------------------------------------------------

interface UserSubmissionsPanelProps {
  user: User;
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function UserSubmissionsPanel({ user, selectedId, onSelect }: UserSubmissionsPanelProps) {
  const [submissions, setSubmissions] = useState<Submission[] | null>(null);
  const [loading, setLoading]         = useState(true);
  const [activeTab, setActiveTab]     = useState<'defense' | 'attack'>('defense');
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirming, setConfirming]   = useState(false);
  const [acting, setActing]           = useState(false);

  useEffect(() => {
    setLoading(true);
    setSubmissions(null);
    setActionError(null);
    adminFetch(`/admin/submissions/users/${user.id}`).then(async res => {
      if (res.ok) {
        const data = await res.json();
        setSubmissions(data.submissions);
      } else {
        setSubmissions([]);
      }
      setLoading(false);
    });
  }, [user.id]);

  function handleSelect(id: string) {
    onSelect(selectedId === id ? '' : id);
    setConfirming(false);
    setActionError(null);
  }

  async function handleSetActive() {
    if (!selectedId) return;
    setActing(true);
    setActionError(null);
    try {
      const res = await adminAction(`/admin/submissions/${selectedId}/activate`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setActionError(body.detail ?? 'Failed to set active submission.');
      } else {
        const res2 = await adminFetch(`/admin/submissions/users/${user.id}`);
        if (res2.ok) {
          const data = await res2.json();
          setSubmissions(data.submissions);
        }
      }
    } finally {
      setActing(false);
      setConfirming(false);
    }
  }

  const byType = (type: 'defense' | 'attack') =>
    (submissions ?? []).filter(s => s.submission_type === type);

  const selectedSub = selectedId ? (submissions ?? []).find(s => s.id === selectedId) : null;
  const canSetActive = selectedSub != null && !selectedSub.is_active;

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
        <div>
          <span className="font-semibold text-gray-900">{user.username}</span>
          <span className="ml-2 text-sm text-gray-400">{user.email}</span>
        </div>
        <div className="flex items-center gap-2">
          {actionError && (
            <span className="text-xs text-red-500">{actionError}</span>
          )}
          {confirming ? (
            <>
              <span className="text-xs text-gray-600">Set as active?</span>
              <button
                onClick={handleSetActive}
                disabled={acting}
                className="px-3 py-1 text-xs rounded bg-primary text-white font-medium disabled:opacity-50"
              >
                {acting ? 'Setting...' : 'Confirm'}
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="px-3 py-1 text-xs rounded border border-gray-200 text-gray-600"
              >
                Cancel
              </button>
            </>
          ) : (
            <button
              onClick={() => setConfirming(true)}
              disabled={!canSetActive}
              className="px-3 py-1 text-xs rounded border border-gray-200 text-gray-600 disabled:opacity-40 disabled:cursor-not-allowed hover:enabled:bg-gray-50 transition-colors"
            >
              Set Active
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-100 bg-gray-50">
        {(['defense', 'attack'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => { setActiveTab(tab); onSelect(''); setConfirming(false); }}
            className={`px-5 py-2 text-sm font-medium transition-colors border-b-2 ${
              activeTab === tab
                ? 'border-primary text-primary'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
            <span className="ml-1.5 text-xs text-gray-400">({byType(tab).length})</span>
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-sm text-gray-400">
            Loading...
          </div>
        ) : (
          <SubmissionTable
            submissions={byType(activeTab)}
            selectedId={selectedId}
            onSelect={handleSelect}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function SubmissionsPage() {
  const [users, setUsers]               = useState<User[]>([]);
  const [loading, setLoading]           = useState(true);
  const [search, setSearch]             = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedSubId, setSelectedSubId] = useState<string | null>(null);
  const firstRender = useRef(true);

  async function loadUsers(q: string, silent = false) {
    if (!silent) setLoading(true);
    const params = new URLSearchParams({ include_disabled: 'true' });
    if (q.trim()) params.set('search', q.trim());
    const res = await adminFetch(`/admin/users?${params}`);
    if (res.ok) {
      const data = await res.json();
      setUsers(data.items ?? []);
    }
    setLoading(false);
  }

  useEffect(() => { loadUsers(''); }, []);

  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    const t = setTimeout(() => loadUsers(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  function handleSelectUser(user: User) {
    if (selectedUser?.id === user.id) {
      setSelectedUser(null);
    } else {
      setSelectedUser(user);
    }
    setSelectedSubId(null);
  }

  function handleSelectSub(id: string) {
    setSelectedSubId(id || null);
  }

  return (
    <div className="flex flex-col h-full space-y-0" style={{ minHeight: 0 }}>
      <h1 className="text-xl font-semibold text-gray-900 mb-4">Submissions</h1>

      <div className="flex gap-4 flex-1 min-h-0" style={{ height: 'calc(100vh - 160px)' }}>

        {/* Panel 1: user list */}
        <div className="w-72 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm flex flex-col min-h-0">
          <div className="px-3 py-2.5 border-b border-gray-100">
            <input
              type="text"
              placeholder="Search users..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full text-sm border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary"
            />
          </div>
          <div className="flex-1 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center py-10 text-sm text-gray-400">
                Loading...
              </div>
            ) : users.length === 0 ? (
              <div className="flex items-center justify-center py-10 text-sm text-gray-400">
                No users found.
              </div>
            ) : (
              <ul className="divide-y divide-gray-50">
                {users.map((user: any) => {
                  const isSelected = selectedUser?.id === user.id;
                  return (
                    <li
                      key={user.id}
                      onClick={() => handleSelectUser(user)}
                      className={`px-4 py-3 cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-primary/5 border-l-2 border-primary'
                          : 'hover:bg-gray-50 border-l-2 border-transparent'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-gray-900">{user.username}</span>
                        {user.is_admin && (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-primary/10 text-primary">
                            Admin
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-gray-400 mt-0.5 truncate">{user.email}</div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          {!loading && (
            <div className="px-4 py-2 border-t border-gray-100 text-xs text-gray-400">
              {users.length} {users.length === 1 ? 'user' : 'users'}
            </div>
          )}
        </div>

        {/* Panel 2: submissions */}
        <div className="flex-1 bg-white rounded-xl border border-gray-200 shadow-sm min-h-0 overflow-hidden">
          {selectedUser ? (
            <UserSubmissionsPanel
              key={selectedUser.id}
              user={selectedUser}
              selectedId={selectedSubId}
              onSelect={handleSelectSub}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-sm text-gray-400">
              Select a user to view their submissions.
            </div>
          )}
        </div>

        {/* Panel 3: evaluation pairs */}
        <div className="w-80 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm min-h-0 overflow-hidden">
          {selectedSubId ? (
            <EvalPairsPanel key={selectedSubId} submissionId={selectedSubId} />
          ) : (
            <div className="flex items-center justify-center h-full text-sm text-gray-400 text-center px-4">
              Select a submission to view counterparts.
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
