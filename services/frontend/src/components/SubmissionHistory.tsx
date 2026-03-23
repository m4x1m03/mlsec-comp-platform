import { useState, useEffect, useCallback } from 'react';

interface Submission {
  submission_id: string;
  submission_type: string;
  status: 'submitted' | 'evaluating' | 'ready' | 'failed';
  is_functional: boolean | null;
  functional_error: string | null;
  version: string;
  display_name: string | null;
  created_at: string;
  is_active: boolean;
}

interface Props {
  type: 'attack' | 'defense';
  title: string;
}

const STATUS_STYLES: Record<string, string> = {
  submitted:  'bg-gray-100 text-gray-500',
  evaluating: 'bg-amber-50 text-amber-700',
  ready:      'bg-green-50 text-green-700',
  failed:     'bg-red-50 text-red-600',
};

const STATUS_LABELS: Record<string, string> = {
  submitted:  'Submitted',
  evaluating: 'Evaluating',
  ready:      'Evaluated',
  failed:     'Error',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function StarIcon({ filled }: { filled: boolean }) {
  if (filled) {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 20 20"
        fill="currentColor"
        className="w-4 h-4 flex-shrink-0 text-primary"
      >
        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
      </svg>
    );
  }
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth={1.5}
      stroke="currentColor"
      className="w-4 h-4 flex-shrink-0 text-gray-300 hover:text-amber-400 transition-colors"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.562.562 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z"
      />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 20 20"
      fill="currentColor"
      className={`w-4 h-4 flex-shrink-0 text-gray-400 transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
    >
      <path
        fillRule="evenodd"
        d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function ExpandedDetail({ sub }: { sub: Submission }) {
  const { status, is_functional, functional_error } = sub;

  if (status === 'submitted') {
    return <p className="text-xs text-gray-500">Queued for processing.</p>;
  }
  if (status === 'evaluating') {
    return <p className="text-xs text-amber-600">Currently being evaluated.</p>;
  }
  if (status === 'ready') {
    if (is_functional === false) {
      return (
        <p className="text-xs text-red-600">
          Validation failed{functional_error ? `: ${functional_error}` : '.'}
        </p>
      );
    }
    return <p className="text-xs text-green-600">Validation passed.</p>;
  }
  if (status === 'failed') {
    return (
      <p className="text-xs text-red-600">
        {functional_error ?? 'An error occurred during processing.'}
      </p>
    );
  }
  return null;
}

export default function SubmissionHistory({ type, title }: Props) {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const fetchSubmissions = useCallback(async () => {
    try {
      const res = await fetch(`/api/submissions/mine?type=${type}`);
      if (res.status === 401) {
        setSubmissions([]);
        return;
      }
      if (!res.ok) return;
      setSubmissions(await res.json());
    } catch {
      // user may not be logged in or network unavailable
    } finally {
      setLoading(false);
    }
  }, [type]);

  useEffect(() => {
    fetchSubmissions();

    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ type: string }>).detail;
      if (detail?.type === type) fetchSubmissions();
    };
    document.addEventListener('submission-created', handler);
    return () => document.removeEventListener('submission-created', handler);
  }, [fetchSubmissions, type]);

  const handleSetActive = async (submissionId: string) => {
    const res = await fetch(`/api/submissions/${submissionId}/active`, { method: 'PUT' });
    if (!res.ok) return;
    setSubmissions(prev =>
      prev.map(s => ({ ...s, is_active: s.submission_id === submissionId }))
    );
  };

  const toggleExpanded = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div className="flex flex-col mb-4 last:mb-0">
      <h2 className="text-base font-semibold text-gray-700 mb-2">{title}</h2>
      <div className="rounded-lg bg-gray-50 border border-gray-200 overflow-y-auto max-h-64">
        {loading ? (
          <p className="text-sm text-gray-400 p-4">Loading...</p>
        ) : submissions.length === 0 ? (
          <p className="text-sm text-gray-400 p-4">No submissions yet.</p>
        ) : (
          <ul className="divide-y divide-gray-100">
            {submissions.map(sub => (
              <li key={sub.submission_id}>
                <div className="flex items-center gap-2 px-3 py-2.5">
                  <button
                    onClick={() => handleSetActive(sub.submission_id)}
                    aria-label={sub.is_active ? 'Active submission' : 'Set as active'}
                    title={sub.is_active ? 'Active' : 'Set as active'}
                    className="p-0.5 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                  >
                    <StarIcon filled={sub.is_active} />
                  </button>

                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-medium text-gray-800 truncate block">
                      {sub.display_name ?? 'Unnamed'}
                    </span>
                    <span className="text-xs text-gray-400">{formatDate(sub.created_at)}</span>
                  </div>

                  <span className="text-xs font-mono bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded flex-shrink-0">
                    v{sub.version}
                  </span>

                  <span
                    className={`text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0 ${STATUS_STYLES[sub.status] ?? STATUS_STYLES.submitted}`}
                  >
                    {STATUS_LABELS[sub.status] ?? sub.status}
                  </span>

                  <button
                    onClick={() => toggleExpanded(sub.submission_id)}
                    aria-label="Toggle details"
                    className="p-0.5 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                  >
                    <ChevronIcon open={expanded.has(sub.submission_id)} />
                  </button>
                </div>

                {expanded.has(sub.submission_id) && (
                  <div className="px-3 pb-2.5">
                    <div className="bg-white border border-gray-100 rounded-lg px-3 py-2">
                      <ExpandedDetail sub={sub} />
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
