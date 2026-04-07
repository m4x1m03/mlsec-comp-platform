import { useState, useEffect, useRef, Fragment } from 'react';
import { adminFetch } from '../../../lib/adminApi';

type Tab = 'audit' | 'jobs' | 'evaluations' | 'sessions';

const TABS: { id: Tab; label: string }[] = [
  { id: 'audit',       label: 'Audit'           },
  { id: 'jobs',        label: 'Jobs'            },
  { id: 'evaluations', label: 'Evaluations'     },
  { id: 'sessions',    label: 'Active Sessions' },
];

const LIMITS = [25, 50, 100, 200];

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function shortId(id: string | null | undefined): string {
  if (!id) return '';
  return id.slice(0, 8) + '...';
}

function StatusBadge({ status }: { status: string | null }) {
  if (!status) return <span className="text-gray-400">-</span>;
  const styles: Record<string, string> = {
    queued:     'bg-gray-100 text-gray-600',
    running:    'bg-blue-100 text-blue-700',
    completed:  'bg-green-100 text-green-700',
    done:       'bg-green-100 text-green-700',
    evaluated:  'bg-green-100 text-green-700',
    validated:  'bg-green-100 text-green-700',
    failed:     'bg-red-100 text-red-700',
    error:      'bg-red-100 text-red-700',
    validating: 'bg-amber-100 text-amber-700',
    evaluating: 'bg-amber-100 text-amber-700',
    submitted:  'bg-gray-100 text-gray-600',
  };
  const cls = styles[status] ?? 'bg-gray-100 text-gray-600';
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

function FilterBar({ children, onRefresh }: { children: React.ReactNode; onRefresh: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-gray-100">
      {children}
      <button
        onClick={onRefresh}
        className="ml-auto text-xs px-3 py-1.5 rounded border border-gray-200 text-gray-600 hover:bg-gray-50 transition-colors"
      >
        Refresh
      </button>
    </div>
  );
}

function LimitSelect({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  return (
    <select
      value={value}
      onChange={e => onChange(Number(e.target.value))}
      className="text-xs border border-gray-200 rounded px-2 py-1.5 text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary/30"
    >
      {LIMITS.map(l => <option key={l} value={l}>Show {l}</option>)}
    </select>
  );
}

function TableShell({ headers, children, loading, empty }: {
  headers: string[];
  children: React.ReactNode;
  loading: boolean;
  empty: boolean;
}) {
  if (loading) return (
    <div className="flex items-center justify-center py-14 text-sm text-gray-400">Loading...</div>
  );
  if (empty) return (
    <div className="flex items-center justify-center py-14 text-sm text-gray-400">No records found.</div>
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
            {headers.map(h => (
              <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">{children}</tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit tab
// ---------------------------------------------------------------------------

const AUDIT_EVENT_TYPES = [
  'admin.submissions.close',
  'admin.submissions.open',
  'admin.submissions.schedule',
  'admin.user.disable',
  'admin.user.enable',
  'admin.user.promote',
  'admin.user.demote',
  'admin.user.revoke_sessions',
  'admin.attack_template.upload',
  'admin.attack_template.deactivate',
  'admin.defense_samples.upload',
  'admin.defense_samples.deactivate',
];

interface AuditRecord {
  id: string;
  event_type: string;
  user_id: string | null;
  email: string | null;
  ip_address: string | null;
  success: boolean | null;
  message: string | null;
  created_at: string;
}

function AuditTab() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [loading, setLoading]     = useState(true);
  const [eventType, setEventType] = useState('');
  const [success, setSuccess]     = useState('');
  const [limit, setLimit]         = useState(50);
  const first = useRef(true);

  async function load(et: string, s: string, lim: number) {
    setLoading(true);
    const p = new URLSearchParams({ limit: String(lim) });
    if (et) p.set('event_type', et);
    if (s !== '') p.set('success', s);
    const res = await adminFetch(`/admin/logs/audit?${p}`);
    if (res.ok) setRecords((await res.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { load('', '', 50); }, []);

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    const t = setTimeout(() => load(eventType, success, limit), 300);
    return () => clearTimeout(t);
  }, [eventType, success, limit]);

  return (
    <>
      <FilterBar onRefresh={() => load(eventType, success, limit)}>
        <select
          value={eventType}
          onChange={e => setEventType(e.target.value)}
          className="text-xs border border-gray-200 rounded px-2 py-1.5 text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary/30"
        >
          <option value="">All event types</option>
          {AUDIT_EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={success}
          onChange={e => setSuccess(e.target.value)}
          className="text-xs border border-gray-200 rounded px-2 py-1.5 text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary/30"
        >
          <option value="">All outcomes</option>
          <option value="true">Success only</option>
          <option value="false">Failures only</option>
        </select>
        <LimitSelect value={limit} onChange={setLimit} />
      </FilterBar>
      <TableShell
        headers={['Timestamp', 'Event Type', 'User / Email', 'IP Address', 'Success', 'Message']}
        loading={loading}
        empty={records.length === 0}
      >
        {records.map(r => (
          <tr key={r.id} className="hover:bg-gray-50 transition-colors">
            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.created_at)}</td>
            <td className="px-4 py-2.5 font-mono text-xs text-gray-800">{r.event_type}</td>
            <td className="px-4 py-2.5">
              <div className="text-gray-800 text-xs">{r.email ?? '-'}</div>
            </td>
            <td className="px-4 py-2.5 text-gray-500 text-xs">{r.ip_address ?? '-'}</td>
            <td className="px-4 py-2.5">
              {r.success === true && <span className="text-green-600 font-medium text-xs">Yes</span>}
              {r.success === false && <span className="text-red-600 font-medium text-xs">No</span>}
              {r.success === null && <span className="text-gray-400 text-xs">-</span>}
            </td>
            <td className="px-4 py-2.5 text-gray-500 text-xs max-w-xs truncate">{r.message ?? '-'}</td>
          </tr>
        ))}
      </TableShell>
    </>
  );
}

// ---------------------------------------------------------------------------
// Jobs tab
// ---------------------------------------------------------------------------

interface JobRecord {
  id: string;
  job_type: string;
  status: string;
  requested_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

interface JobDetailSub {
  submission_id: string;
  version: string;
  display_name: string | null;
  status: string;
  source_type?: string | null;
  file_count?: number | null;
}

interface JobDetailRun {
  id: string;
  counterpart_id: string;
  status: string | null;
  duration_ms: number | null;
}

interface JobDetail {
  submission: JobDetailSub | null;
  evaluation_runs: JobDetailRun[];
  fetching?: boolean;
}

const JOB_STATUSES = ['queued', 'running', 'done', 'failed'];

function JobDetailPanel({ detail, jobType }: { detail: JobDetail; jobType: string }) {
  if (detail.fetching) {
    return <p className="text-xs text-gray-400">Loading details...</p>;
  }
  const { submission, evaluation_runs } = detail;
  const counterpartLabel = jobType === 'D' ? 'Attack' : 'Defense';
  return (
    <div className="flex flex-col sm:flex-row gap-6">
      <div className="space-y-1">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-2">Submission</p>
        {submission ? (
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            {submission.display_name && (
              <>
                <dt className="text-gray-400">Name</dt>
                <dd className="text-gray-700 font-medium">{submission.display_name}</dd>
              </>
            )}
            <dt className="text-gray-400">Version</dt>
            <dd className="text-gray-700 font-mono">{submission.version}</dd>
            <dt className="text-gray-400">Status</dt>
            <dd><StatusBadge status={submission.status} /></dd>
            {jobType === 'D' && submission.source_type && (
              <>
                <dt className="text-gray-400">Source</dt>
                <dd className="text-gray-700 capitalize">{submission.source_type}</dd>
              </>
            )}
            {jobType === 'A' && submission.file_count != null && (
              <>
                <dt className="text-gray-400">Files</dt>
                <dd className="text-gray-700">{submission.file_count}</dd>
              </>
            )}
          </dl>
        ) : (
          <p className="text-xs text-gray-400">No submission data.</p>
        )}
      </div>
      {evaluation_runs.length > 0 && (
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-2">Evaluation Runs</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400">
                <th className="text-left font-medium pb-1 pr-4">{counterpartLabel}</th>
                <th className="text-left font-medium pb-1 pr-4">Status</th>
                <th className="text-left font-medium pb-1">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {evaluation_runs.map(r => (
                <tr key={r.id}>
                  <td className="font-mono text-gray-600 py-1 pr-4">{shortId(r.counterpart_id)}</td>
                  <td className="py-1 pr-4"><StatusBadge status={r.status} /></td>
                  <td className="text-gray-500 py-1">{r.duration_ms != null ? `${r.duration_ms} ms` : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function JobsTab() {
  const [records, setRecords]   = useState<JobRecord[]>([]);
  const [loading, setLoading]   = useState(true);
  const [statusFilter, setStatus] = useState('');
  const [limit, setLimit]       = useState(50);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [details, setDetails]   = useState<Record<string, JobDetail>>({});
  const first = useRef(true);

  async function load(s: string, lim: number) {
    setLoading(true);
    const p = new URLSearchParams({ limit: String(lim) });
    if (s) p.set('status_filter', s);
    const res = await adminFetch(`/admin/logs/jobs?${p}`);
    if (res.ok) setRecords((await res.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { load('', 50); }, []);

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    const t = setTimeout(() => load(statusFilter, limit), 300);
    return () => clearTimeout(t);
  }, [statusFilter, limit]);

  async function toggleExpand(id: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
    if (details[id]) return;
    setDetails(prev => ({ ...prev, [id]: { submission: null, evaluation_runs: [], fetching: true } }));
    try {
      const res = await adminFetch(`/admin/logs/jobs/${id}/detail`);
      const d = res.ok ? await res.json() : null;
      setDetails(prev => ({
        ...prev,
        [id]: {
          submission: d?.submission ?? null,
          evaluation_runs: d?.evaluation_runs ?? [],
        },
      }));
    } catch {
      setDetails(prev => ({ ...prev, [id]: { submission: null, evaluation_runs: [] } }));
    }
  }

  return (
    <>
      <FilterBar onRefresh={() => load(statusFilter, limit)}>
        <select
          value={statusFilter}
          onChange={e => setStatus(e.target.value)}
          className="text-xs border border-gray-200 rounded px-2 py-1.5 text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary/30"
        >
          <option value="">All statuses</option>
          {JOB_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <LimitSelect value={limit} onChange={setLimit} />
      </FilterBar>
      <TableShell
        headers={['', 'Timestamp', 'Type', 'Status', 'Requested By', 'Updated At']}
        loading={loading}
        empty={records.length === 0}
      >
        {records.map(r => {
          const isOpen = expanded.has(r.id);
          const detail = details[r.id];
          return (
            <Fragment key={r.id}>
              <tr className="hover:bg-gray-50 transition-colors">
                <td className="pl-3 pr-1 py-2.5 w-8">
                  <button
                    onClick={() => toggleExpand(r.id)}
                    aria-label={isOpen ? 'Collapse' : 'Expand'}
                    className="text-gray-400 hover:text-gray-600 transition-colors"
                  >
                    <svg className={`w-3.5 h-3.5 transition-transform duration-150 ${isOpen ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </button>
                </td>
                <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.created_at)}</td>
                <td className="px-4 py-2.5">
                  <span className="font-medium text-gray-800">
                    {r.job_type === 'D' ? 'Defense' : r.job_type === 'A' ? 'Attack' : r.job_type === 'S' ? 'Seeding' : r.job_type}
                  </span>
                </td>
                <td className="px-4 py-2.5"><StatusBadge status={r.status} /></td>
                <td className="px-4 py-2.5 font-mono text-xs text-gray-500">{shortId(r.requested_by_user_id)}</td>
                <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.updated_at)}</td>
              </tr>
              {isOpen && (
                <tr>
                  <td colSpan={6} className="bg-gray-50 px-6 py-4 border-b border-gray-100">
                    {detail ? (
                      <JobDetailPanel detail={detail} jobType={r.job_type} />
                    ) : (
                      <p className="text-xs text-gray-400">Loading details...</p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </TableShell>
    </>
  );
}

// ---------------------------------------------------------------------------
// Evaluations tab
// ---------------------------------------------------------------------------

interface EvalRecord {
  id: string;
  defense_submission_id: string;
  attack_submission_id: string;
  status: string | null;
  error: string | null;
  duration_ms: number | null;
  created_at: string;
  updated_at: string;
}

const EVAL_STATUSES = ['submitted', 'validating', 'validated', 'evaluating', 'evaluated', 'error'];

function EvaluationsTab() {
  const [records, setRecords] = useState<EvalRecord[]>([]);
  const [loading, setLoading]       = useState(true);
  const [statusFilter, setStatus]   = useState('');
  const [limit, setLimit]           = useState(50);
  const first = useRef(true);

  async function load(s: string, lim: number) {
    setLoading(true);
    const p = new URLSearchParams({ limit: String(lim) });
    if (s) p.set('status_filter', s);
    const res = await adminFetch(`/admin/logs/evaluations?${p}`);
    if (res.ok) setRecords((await res.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { load('', 50); }, []);

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    const t = setTimeout(() => load(statusFilter, limit), 300);
    return () => clearTimeout(t);
  }, [statusFilter, limit]);

  return (
    <>
      <FilterBar onRefresh={() => load(statusFilter, limit)}>
        <select
          value={statusFilter}
          onChange={e => setStatus(e.target.value)}
          className="text-xs border border-gray-200 rounded px-2 py-1.5 text-gray-600 focus:outline-none focus:ring-2 focus:ring-primary/30"
        >
          <option value="">All statuses</option>
          {EVAL_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <LimitSelect value={limit} onChange={setLimit} />
      </FilterBar>
      <TableShell
        headers={['Timestamp', 'Defense Sub', 'Attack Sub', 'Status', 'Duration', 'Error']}
        loading={loading}
        empty={records.length === 0}
      >
        {records.map(r => (
          <tr key={r.id} className="hover:bg-gray-50 transition-colors">
            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.created_at)}</td>
            <td className="px-4 py-2.5 font-mono text-xs text-gray-600">{shortId(r.defense_submission_id)}</td>
            <td className="px-4 py-2.5 font-mono text-xs text-gray-600">{shortId(r.attack_submission_id)}</td>
            <td className="px-4 py-2.5"><StatusBadge status={r.status} /></td>
            <td className="px-4 py-2.5 text-gray-500 text-xs">
              {r.duration_ms != null ? `${r.duration_ms} ms` : '-'}
            </td>
            <td className="px-4 py-2.5 text-red-600 text-xs max-w-xs truncate">{r.error ?? '-'}</td>
          </tr>
        ))}
      </TableShell>
    </>
  );
}

// ---------------------------------------------------------------------------
// Active Sessions tab
// ---------------------------------------------------------------------------

interface SessionRecord {
  session_id: string;
  user_id: string;
  email: string;
  username: string;
  is_admin: boolean;
  created_at: string;
  last_seen_at: string | null;
  expires_at: string;
}

function SessionsTab() {
  const [records, setRecords] = useState<SessionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit]     = useState(50);
  const first = useRef(true);

  async function load(lim: number) {
    setLoading(true);
    const res = await adminFetch(`/admin/sessions/active?limit=${lim}`);
    if (res.ok) setRecords((await res.json()).items ?? []);
    setLoading(false);
  }

  useEffect(() => { load(50); }, []);

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    load(limit);
  }, [limit]);

  return (
    <>
      <FilterBar onRefresh={() => load(limit)}>
        <LimitSelect value={limit} onChange={setLimit} />
      </FilterBar>
      <TableShell
        headers={['User', 'Role', 'Created At', 'Last Seen', 'Expires At']}
        loading={loading}
        empty={records.length === 0}
      >
        {records.map(r => (
          <tr key={r.session_id} className="hover:bg-gray-50 transition-colors">
            <td className="px-4 py-2.5">
              <div className="font-medium text-gray-900 text-sm">{r.username}</div>
              <div className="text-xs text-gray-400">{r.email}</div>
            </td>
            <td className="px-4 py-2.5">
              {r.is_admin ? (
                <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-primary/10 text-primary">
                  Admin
                </span>
              ) : (
                <span className="text-xs text-gray-400">User</span>
              )}
            </td>
            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.created_at)}</td>
            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">
              {r.last_seen_at ? formatDateTime(r.last_seen_at) : '-'}
            </td>
            <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">{formatDateTime(r.expires_at)}</td>
          </tr>
        ))}
      </TableShell>
    </>
  );
}

// ---------------------------------------------------------------------------
// Main LogsPage
// ---------------------------------------------------------------------------

export default function LogsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('audit');

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900">Logs</h1>

      <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
        <div className="flex border-b border-gray-100">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={[
                'px-5 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                activeTab === tab.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-gray-500 hover:text-gray-700',
              ].join(' ')}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'audit'       && <AuditTab />}
        {activeTab === 'jobs'        && <JobsTab />}
        {activeTab === 'evaluations' && <EvaluationsTab />}
        {activeTab === 'sessions'    && <SessionsTab />}
      </div>
    </div>
  );
}
