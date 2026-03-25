import { useState, useEffect } from 'react';
import { adminFetch } from '../../../lib/adminApi';

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function shortId(id: string): string {
  return id.slice(0, 8) + '...';
}

function jobTypeLabel(type: string): string {
  if (type === 'D') return 'Defense';
  if (type === 'A') return 'Attack';
  if (type === 'S') return 'Seeding';
  return type;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
      <div className="px-5 py-4 border-b border-gray-100">
        <h2 className="text-base font-semibold text-gray-900">{title}</h2>
      </div>
      <div>{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Celery Workers
// ---------------------------------------------------------------------------

interface WorkerTask {
  task_id: string;
  name: string;
  kwargs: Record<string, unknown> | null;
}

interface Worker {
  name: string;
  active_tasks: WorkerTask[];
}

interface WorkersResponse {
  workers: Worker[];
  running_jobs: unknown[];
  queued_jobs: unknown[];
}

function CeleryWorkersSection({ refreshKey }: { refreshKey: number }) {
  const [workers, setWorkers] = useState<Worker[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    adminFetch('/admin/workers').then(async res => {
      if (cancelled) return;
      if (res.ok) {
        const data: WorkersResponse = await res.json();
        setWorkers(data.workers);
      } else {
        setWorkers([]);
      }
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [refreshKey]);

  return (
    <Section title="Celery Workers">
      {loading ? (
        <div className="flex items-center justify-center py-10 text-sm text-gray-400">
          Loading...
        </div>
      ) : !workers || workers.length === 0 ? (
        <div className="px-5 py-6 text-sm text-gray-400">
          No workers reported by Celery. The broker may be unreachable or no workers
          are currently running.
        </div>
      ) : (
        <div className="divide-y divide-gray-100">
          {workers.map(worker => (
            <div key={worker.name} className="px-5 py-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm text-gray-800">{worker.name}</span>
                <span className="text-xs text-gray-400">
                  {worker.active_tasks.length} active{' '}
                  {worker.active_tasks.length === 1 ? 'task' : 'tasks'}
                </span>
              </div>
              {worker.active_tasks.length > 0 && (
                <div className="mt-2 space-y-1">
                  {worker.active_tasks.map(task => (
                    <div
                      key={task.task_id}
                      className="ml-4 flex items-start gap-3 text-xs text-gray-500"
                    >
                      <span className="font-mono text-gray-400">{shortId(task.task_id)}</span>
                      <span className="text-gray-700">{task.name}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Jobs tables (running / queued)
// ---------------------------------------------------------------------------

interface Job {
  id: string;
  job_type: string;
  status: string;
  requested_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

interface JobsResponse {
  count: number;
  items: Job[];
}

function JobsSection({ title, statusFilter, refreshKey }: {
  title: string;
  statusFilter: string;
  refreshKey: number;
}) {
  const [jobs, setJobs]       = useState<Job[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    adminFetch(`/admin/logs/jobs?status_filter=${statusFilter}&limit=50`).then(async res => {
      if (cancelled) return;
      if (res.ok) {
        const data: JobsResponse = await res.json();
        setJobs(data.items);
      } else {
        setJobs([]);
      }
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [refreshKey, statusFilter]);

  return (
    <Section title={title}>
      {loading ? (
        <div className="flex items-center justify-center py-10 text-sm text-gray-400">
          Loading...
        </div>
      ) : !jobs || jobs.length === 0 ? (
        <div className="flex items-center justify-center py-10 text-sm text-gray-400">
          No jobs.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-xs uppercase tracking-wide text-gray-500">
                <th className="px-4 py-2.5 text-left font-medium">ID</th>
                <th className="px-4 py-2.5 text-left font-medium">Type</th>
                <th className="px-4 py-2.5 text-left font-medium">Requested By</th>
                <th className="px-4 py-2.5 text-left font-medium">Created</th>
                <th className="px-4 py-2.5 text-left font-medium">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {jobs.map(job => (
                <tr key={job.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-600">
                    {shortId(job.id)}
                  </td>
                  <td className="px-4 py-2.5 text-gray-800">{jobTypeLabel(job.job_type)}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-500">
                    {job.requested_by_user_id ? shortId(job.requested_by_user_id) : '-'}
                  </td>
                  <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">
                    {formatDateTime(job.created_at)}
                  </td>
                  <td className="px-4 py-2.5 text-gray-500 whitespace-nowrap">
                    {formatDateTime(job.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function WorkersPage() {
  const [refreshKey, setRefreshKey]       = useState(0);
  const [refreshedAt, setRefreshedAt]     = useState<Date | null>(null);

  function refresh() {
    setRefreshKey(k => k + 1);
    setRefreshedAt(new Date());
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900">Workers</h1>
        <div className="flex items-center gap-3">
          {refreshedAt && (
            <span className="text-xs text-gray-400">
              Last refreshed {refreshedAt.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={refresh}
            className="text-xs px-3 py-1.5 rounded border border-gray-200 text-gray-600 hover:bg-gray-50 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      <CeleryWorkersSection refreshKey={refreshKey} />
      <JobsSection title="Running Jobs" statusFilter="running" refreshKey={refreshKey} />
      <JobsSection title="Queued Jobs"  statusFilter="queued"  refreshKey={refreshKey} />
    </div>
  );
}
