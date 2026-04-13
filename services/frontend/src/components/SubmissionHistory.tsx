import { useState, useEffect, useCallback } from 'react';

interface Submission {
  submission_id: string;
  submission_type: string;
  status: 'submitted' | 'validating' | 'validated' | 'evaluating' | 'evaluated' | 'error';
  is_functional: boolean | null;
  functional_error: string | null;
  version: string;
  display_name: string | null;
  created_at: string;
  is_active: boolean;
  heurval_tpr: number | null;
  heurval_fpr: number | null;
  detail_loaded?: boolean;
  source_type?: string | null;
  sha256?: string | null;
  docker_image?: string | null;
  git_repo?: string | null;
}

interface Props {
  type: 'attack' | 'defense';
  title: string;
}

const STATUS_STYLES: Record<string, string> = {
  submitted:  'text-gray-400',
  validating: 'text-blue-500 font-semibold',
  validated:  'text-blue-600 font-semibold',
  evaluating: 'text-amber-500 font-semibold',
  evaluated:  'text-green-600 font-semibold',
  error:      'text-red-600 font-semibold',
};

const STATUS_LABELS: Record<string, string> = {
  submitted:  'Submitted',
  validating: 'Validating',
  validated:  'Validated',
  evaluating: 'Evaluating',
  evaluated:  'Evaluated',
  error:      'Error',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function StarIcon({ filled }: { filled: boolean }) {
  if (filled) {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 20 20"
        fill="currentColor"
        className="w-4 h-4 flex-shrink-0 text-yellow-400"
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

function HeurvalStats({ tpr, fpr }: { tpr: number | null; fpr: number | null }) {
  if (tpr === null && fpr === null) return null;
  return (
    <div className="flex gap-3 mt-1">
      {tpr !== null && (
        <span className="text-xs text-gray-500">
          TPR: <span className="font-medium text-gray-700">{(tpr * 100).toFixed(1)}%</span>
        </span>
      )}
      {fpr !== null && (
        <span className="text-xs text-gray-500">
          FPR: <span className="font-medium text-gray-700">{(fpr * 100).toFixed(1)}%</span>
        </span>
      )}
    </div>
  );
}

function ExpandedDetail({ sub }: { sub: Submission }) {
  const { status, functional_error, submission_type, heurval_tpr, heurval_fpr } = sub;
  const showHeurval = submission_type === 'defense' && (heurval_tpr !== null || heurval_fpr !== null);

  return (
    <>
      {status === 'submitted' && <p className="text-xs text-gray-500">Queued for processing.</p>}
      {status === 'validating' && <p className="text-xs text-blue-500">Validation in progress.</p>}
      {(status === 'validated') && (
        <>
          <p className="text-xs text-blue-600">Validation passed. Waiting for evaluation.</p>
          {showHeurval && <HeurvalStats tpr={heurval_tpr} fpr={heurval_fpr} />}
        </>
      )}
      {status === 'evaluating' && (
        <>
          <p className="text-xs text-amber-600">Currently being evaluated.</p>
          {showHeurval && <HeurvalStats tpr={heurval_tpr} fpr={heurval_fpr} />}
        </>
      )}
      {status === 'evaluated' && (
        <>
          <p className="text-xs text-green-600">Evaluation complete.</p>
          {showHeurval && <HeurvalStats tpr={heurval_tpr} fpr={heurval_fpr} />}
        </>
      )}
      {status === 'error' && (
        <p className="text-xs text-red-600">
          {functional_error ?? 'An error occurred during processing.'}
        </p>
      )}

      {sub.detail_loaded ? (
        <dl className="mt-2 pt-2 border-t border-gray-100 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
          <dt className="text-gray-400 whitespace-nowrap">Submitted</dt>
          <dd className="text-gray-600">{formatDateTime(sub.created_at)}</dd>
          {sub.sha256 && (
            <>
              <dt className="text-gray-400 whitespace-nowrap">File Hash</dt>
              <dd className="font-mono text-gray-600 truncate" title={sub.sha256}>
                {sub.sha256.slice(0, 16)}...
              </dd>
            </>
          )}
          {sub.docker_image && (
            <>
              <dt className="text-gray-400 whitespace-nowrap">DockerHub</dt>
              <dd className="text-gray-600 truncate" title={sub.docker_image}>{sub.docker_image}</dd>
            </>
          )}
          {sub.git_repo && (
            <>
              <dt className="text-gray-400 whitespace-nowrap">GitHub</dt>
              <dd className="text-gray-600 truncate" title={sub.git_repo}>{sub.git_repo}</dd>
            </>
          )}
        </dl>
      ) : (
        <p className="mt-1 text-xs text-gray-400">Loading details...</p>
      )}
    </>
  );
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

  useEffect(() => {
    const hasActive = submissions.some(
      s => s.status === 'submitted' || s.status === 'validating' ||
           s.status === 'validated'  || s.status === 'evaluating'
    );
    if (!hasActive) return;
    const id = setInterval(fetchSubmissions, 5000);
    return () => clearInterval(id);
  }, [submissions, fetchSubmissions]);

  const handleSetActive = async (submissionId: string) => {
    const res = await fetch(`/api/submissions/${submissionId}/active`, { method: 'PUT' });
    if (!res.ok) return;
    setSubmissions(prev =>
      prev.map(s => ({ ...s, is_active: s.submission_id === submissionId }))
    );
  };

  const toggleExpanded = async (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
    const sub = submissions.find(s => s.submission_id === id);
    if (!sub || sub.detail_loaded) return;
    try {
      const res = await fetch(`/api/submissions/${id}/detail`);
      if (!res.ok) return;
      const d = await res.json();
      setSubmissions(prev => prev.map(s =>
        s.submission_id === id
          ? { ...s, detail_loaded: true, source_type: d.source_type, sha256: d.sha256, docker_image: d.docker_image, git_repo: d.git_repo }
          : s
      ));
    } catch {}
  };

  return (
    <div className="flex flex-col flex-1 min-h-48">
      <h2 className="text-base font-semibold text-gray-700 mb-2 shrink-0">{title}</h2>
      <div className="flex-1 min-h-0 rounded-lg bg-gray-50 border border-gray-200 overflow-y-auto p-1.5">
        {loading ? (
          <p className="text-sm text-gray-400 p-4">Loading...</p>
        ) : submissions.length === 0 ? (
          <p className="text-sm text-gray-400 p-4">No submissions yet.</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {submissions.map(sub => (
              <li key={sub.submission_id} className="bg-white rounded-lg border border-gray-200 overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2.5">
                  <button
                    onClick={() => handleSetActive(sub.submission_id)}
                    disabled={sub.status !== 'validated' && sub.status !== 'evaluated'}
                    aria-label={sub.is_active ? 'Active submission' : 'Set as active'}
                    title={
                      sub.status === 'error' ? 'Cannot activate errored submission' :
                      sub.status === 'validated' || sub.status === 'evaluated' ? (sub.is_active ? 'Active' : 'Set as active') :
                      'Submission is still processing'
                    }
                    className={`p-0.5 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-primary${sub.status !== 'validated' && sub.status !== 'evaluated' ? ' cursor-not-allowed opacity-40' : ''}`}
                  >
                    <StarIcon filled={sub.is_active} />
                  </button>

                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-medium text-gray-800 truncate block">
                      {sub.display_name ?? 'Unnamed'}
                    </span>
                    <span className="text-xs text-gray-400">{formatDate(sub.created_at)}</span>
                  </div>

                  <span
                    className="text-xs font-mono bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded flex-shrink-0 max-w-[6rem] truncate block"
                    title={`v${sub.version}`}
                  >
                    v{sub.version}
                  </span>

                  <span
                    className={`text-xs flex-shrink-0 ${STATUS_STYLES[sub.status] ?? STATUS_STYLES.submitted}`}
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
                  <div className="px-3 pb-2.5 border-t border-gray-100">
                    <div className="pt-2">
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
