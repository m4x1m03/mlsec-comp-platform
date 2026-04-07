import { useState, useEffect } from 'react';
import { adminFetch, adminAction } from '../../../lib/adminApi';

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function shortHash(hash: string): string {
  return hash.slice(0, 16) + '...';
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
      <div className="px-5 py-4 border-b border-gray-100">
        <h2 className="text-base font-semibold text-gray-900">{title}</h2>
      </div>
      <div className="p-5 space-y-4">{children}</div>
    </div>
  );
}

function ErrorBanner({ message, onDismiss }: { message: string; onDismiss: () => void }) {
  return (
    <div className="flex items-center justify-between bg-red-50 border border-red-200 text-red-700 text-sm px-4 py-3 rounded-lg">
      <span>{message}</span>
      <button
        onClick={onDismiss}
        className="ml-4 font-medium text-red-400 hover:text-red-600 transition-colors"
      >
        Dismiss
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Submission Window
// ---------------------------------------------------------------------------

interface SubmissionStatus {
  manual_closed: boolean;
  close_at: string | null;
  is_closed: boolean;
  updated_at: string | null;
  updated_by: string | null;
}

function SubmissionSection() {
  const [status, setStatus]               = useState<SubmissionStatus | null>(null);
  const [loading, setLoading]             = useState(true);
  const [error, setError]                 = useState<string | null>(null);
  const [acting, setActing]               = useState(false);
  const [confirmAction, setConfirmAction] = useState<'open' | 'close' | null>(null);
  const [scheduleInput, setScheduleInput] = useState('');

  async function loadStatus() {
    setLoading(true);
    const res = await adminFetch('/admin/submissions/status');
    if (res.ok) {
      const data: SubmissionStatus = await res.json();
      setStatus(data);
      if (data.close_at) {
        const d = new Date(data.close_at);
        const pad = (n: number) => String(n).padStart(2, '0');
        setScheduleInput(
          `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
          `T${pad(d.getHours())}:${pad(d.getMinutes())}`
        );
      } else {
        setScheduleInput('');
      }
    } else {
      setError('Failed to load submission status.');
    }
    setLoading(false);
  }

  useEffect(() => { loadStatus(); }, []);

  async function doAction(action: 'open' | 'close') {
    setActing(true);
    setConfirmAction(null);
    const res = await adminAction(`/admin/submissions/${action}`, { method: 'POST' });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError((body as { detail?: string }).detail ?? 'Action failed.');
    }
    await loadStatus();
    setActing(false);
  }

  async function setSchedule() {
    if (!scheduleInput) return;
    setActing(true);
    const res = await adminAction('/admin/submissions/schedule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ close_at: new Date(scheduleInput).toISOString() }),
    });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      setError((b as { detail?: string }).detail ?? 'Failed to set schedule.');
    }
    await loadStatus();
    setActing(false);
  }

  async function clearSchedule() {
    setActing(true);
    const res = await adminAction('/admin/submissions/schedule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ close_at: null }),
    });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      setError((b as { detail?: string }).detail ?? 'Failed to clear schedule.');
    }
    await loadStatus();
    setActing(false);
  }

  return (
    <Section title="Submission Window">
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {loading ? (
        <p className="text-sm text-gray-400">Loading...</p>
      ) : status ? (
        <>
          <div className="flex items-center gap-4">
            {status.is_closed ? (
              <span className="inline-flex items-center rounded px-2.5 py-1 text-sm font-medium bg-red-100 text-red-700">
                Closed
              </span>
            ) : (
              <span className="inline-flex items-center rounded px-2.5 py-1 text-sm font-medium bg-green-100 text-green-700">
                Open
              </span>
            )}
            {status.updated_at && (
              <span className="text-xs text-gray-400">
                Last updated {formatDateTime(status.updated_at)}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {confirmAction ? (
              <>
                <span className="text-sm text-gray-600">
                  Confirm {confirmAction === 'open' ? 'open' : 'close'} submissions?
                </span>
                <button
                  onClick={() => doAction(confirmAction)}
                  className="rounded px-3 py-1.5 text-xs font-medium text-white bg-red-500 hover:bg-red-600 transition-colors"
                >
                  Yes
                </button>
                <button
                  onClick={() => setConfirmAction(null)}
                  className="rounded border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-500 hover:text-gray-700 transition-colors"
                >
                  Cancel
                </button>
              </>
            ) : acting ? (
              <span className="text-sm text-gray-400">Working...</span>
            ) : (
              <>
                <button
                  disabled={!status.is_closed}
                  onClick={() => setConfirmAction('open')}
                  className="rounded border border-green-200 px-3 py-1.5 text-xs font-medium text-green-700 hover:bg-green-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Open Submissions
                </button>
                <button
                  disabled={status.is_closed}
                  onClick={() => setConfirmAction('close')}
                  className="rounded border border-red-200 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Close Submissions
                </button>
              </>
            )}
          </div>

          <div className="border-t border-gray-100 pt-4 space-y-2">
            <p className="text-xs font-medium text-gray-600 uppercase tracking-wide">
              Schedule Auto-Close
            </p>
            <p className="text-xs font-small text-gray-400 tracking-wide">Opening submissions after scheduled auto-close will empty the auto-close date.</p>
            {status.close_at && (
              <p className="text-sm text-gray-500">
                Scheduled:{' '}
                <span className="font-medium text-gray-700">
                  {formatDateTime(status.close_at)}
                </span>
                {' '}
                <button
                  onClick={clearSchedule}
                  disabled={acting}
                  className="text-xs text-red-500 hover:text-red-700 transition-colors disabled:opacity-40"
                >
                  Clear
                </button>
              </p>
            )}
            <div className="flex items-center gap-2">
              <input
                type="datetime-local"
                value={scheduleInput}
                onChange={e => setScheduleInput(e.target.value)}
                className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary"
              />
              <button
                onClick={setSchedule}
                disabled={acting || !scheduleInput}
                className="rounded border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Set Schedule
              </button>
            </div>
          </div>
        </>
      ) : null}
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Attack Template
// ---------------------------------------------------------------------------

interface AttackTemplate {
  id: string;
  object_key: string;
  sha256: string;
  file_count: number;
  uploaded_at: string;
  seeded_count: number;
  fully_seeded: boolean;
}

function AttackTemplateSection() {
  const [template, setTemplate] = useState<AttackTemplate | null>(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [fileInput, setFileInput] = useState<File | null>(null);

  async function loadTemplate() {
    setLoading(true);
    const res = await adminFetch('/admin/attack-template');
    if (res.ok) {
      setTemplate(await res.json());
    } else if (res.status === 404) {
      setTemplate(null);
    } else {
      setError('Failed to load attack template.');
    }
    setLoading(false);
  }

  useEffect(() => { loadTemplate(); }, []);

  async function uploadTemplate() {
    if (!fileInput) return;
    setUploading(true);
    const form = new FormData();
    form.append('file', fileInput);
    const res = await adminAction('/admin/attack-template', { method: 'POST', body: form });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      setError((b as { detail?: string }).detail ?? 'Upload failed.');
    } else {
      setFileInput(null);
    }
    await loadTemplate();
    setUploading(false);
  }

  return (
    <Section title="Attack Template">
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {loading ? (
        <p className="text-sm text-gray-400">Loading...</p>
      ) : (
        <>
          {template ? (
            <div className="rounded-lg border border-gray-100 bg-gray-50 p-4 space-y-3">
              <p className="text-sm font-medium text-gray-700">Current Template</p>
              <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-xs">
                <span className="text-gray-400">Files</span>
                <span className="text-gray-700">{template.file_count}</span>
                <span className="text-gray-400">SHA256</span>
                <span className="font-mono text-gray-700">{shortHash(template.sha256)}</span>
                <span className="text-gray-400">Uploaded</span>
                <span className="text-gray-700">{formatDateTime(template.uploaded_at)}</span>
                <span className="text-gray-400">Seeded</span>
                <span className="text-gray-700">
                  {template.seeded_count} / {template.file_count}
                  {template.fully_seeded && (
                    <span className="ml-1.5 text-green-600">(complete)</span>
                  )}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-gray-400">No attack template uploaded.</p>
          )}

          <div className="border-t border-gray-100 pt-4 space-y-2">
            <p className="text-xs font-medium text-gray-600 uppercase tracking-wide">
              {template ? 'Replace Template' : 'Upload Template'}
            </p>
            <p className="text-xs text-gray-400">
              ZIP file only. Uploading replaces the current template.
            </p>
            <div className="flex items-center gap-2">
              <input
                type="file"
                accept=".zip"
                onChange={e => setFileInput(e.target.files?.[0] ?? null)}
                className="text-sm text-gray-600 file:mr-2 file:rounded file:border file:border-gray-200 file:px-3 file:py-1 file:text-xs file:font-medium file:text-gray-700 file:bg-white hover:file:bg-gray-50"
              />
              <button
                onClick={uploadTemplate}
                disabled={!fileInput || uploading}
                className="rounded border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {uploading ? 'Uploading...' : template ? 'Replace Template' : 'Upload Template'}
              </button>
            </div>
          </div>
        </>
      )}
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Defense Validation Samples
// ---------------------------------------------------------------------------

interface SampleSet {
  sha256: string;
  malware_count: number;
  goodware_count: number;
  uploaded_at: string;
  is_active: boolean;
}

function ValidationSamplesSection() {
  const [current, setCurrent]     = useState<SampleSet | null>(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [fileInput, setFileInput] = useState<File | null>(null);

  async function loadSets() {
    setLoading(true);
    const res = await adminFetch('/admin/defense-validation-samples');
    if (res.ok) {
      const sets: SampleSet[] = await res.json();
      setCurrent(sets.find(s => s.is_active) ?? null);
    } else {
      setError('Failed to load sample sets.');
    }
    setLoading(false);
  }

  useEffect(() => { loadSets(); }, []);

  async function uploadSet() {
    if (!fileInput) return;
    setUploading(true);
    const form = new FormData();
    form.append('file', fileInput);
    const res = await adminAction('/admin/defense-validation-samples', { method: 'POST', body: form });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      setError((b as { detail?: string }).detail ?? 'Upload failed.');
    } else {
      setFileInput(null);
    }
    await loadSets();
    setUploading(false);
  }

  return (
    <Section title="Defense Validation Samples">
      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {loading ? (
        <p className="text-sm text-gray-400">Loading...</p>
      ) : current ? (
        <div className="rounded-lg border border-gray-100 bg-gray-50 p-4 space-y-3">
          <p className="text-sm font-medium text-gray-700">Current Sample Set</p>
          <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-xs">
            <span className="text-gray-400">Malware</span>
            <span className="text-gray-700">{current.malware_count}</span>
            <span className="text-gray-400">Goodware</span>
            <span className="text-gray-700">{current.goodware_count}</span>
            <span className="text-gray-400">SHA256</span>
            <span className="font-mono text-gray-700">{shortHash(current.sha256)}</span>
            <span className="text-gray-400">Uploaded</span>
            <span className="text-gray-700">{formatDateTime(current.uploaded_at)}</span>
          </div>
        </div>
      ) : (
        <p className="text-sm text-gray-400">No sample set uploaded.</p>
      )}

      <div className="border-t border-gray-100 pt-4 space-y-2">
        <p className="text-xs font-medium text-gray-600 uppercase tracking-wide">
          {current ? 'Replace Sample Set' : 'Upload Sample Set'}
        </p>
        <p className="text-xs text-gray-400">
          ZIP with malware/ and goodware/ folders. Uploading replaces the current set.
        </p>
        <div className="flex items-center gap-2">
          <input
            type="file"
            accept=".zip"
            onChange={e => setFileInput(e.target.files?.[0] ?? null)}
            className="text-sm text-gray-600 file:mr-2 file:rounded file:border file:border-gray-200 file:px-3 file:py-1 file:text-xs file:font-medium file:text-gray-700 file:bg-white hover:file:bg-gray-50"
          />
          <button
            onClick={uploadSet}
            disabled={!fileInput || uploading}
            className="rounded border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {uploading ? 'Uploading...' : current ? 'Replace Sample Set' : 'Upload Sample Set'}
          </button>
        </div>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

interface UserOption { id: string; username: string; email: string; }
interface SubOption  { id: string; display_name: string | null; version: string; status: string; }

async function triggerCsvDownload(path: string, filename: string): Promise<void> {
  const res = await adminFetch(path);
  if (!res.ok) throw new Error(`Download failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function DownloadButton({
  label, path, filename,
}: { label: string; path: string; filename: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState<string | null>(null);

  async function handle() {
    setBusy(true);
    setErr(null);
    try {
      await triggerCsvDownload(path, filename);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Download failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-3 shrink-0">
      <button
        onClick={handle}
        disabled={busy}
        className="rounded border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-100 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? 'Downloading...' : label}
      </button>
      {err && <span className="text-xs text-red-600">{err}</span>}
    </div>
  );
}

function IndividualScoresDownload() {
  const [users, setUsers]           = useState<UserOption[]>([]);
  const [defUserId, setDefUserId]   = useState('');
  const [atkUserId, setAtkUserId]   = useState('');
  const [defSubs, setDefSubs]       = useState<SubOption[]>([]);
  const [atkSubs, setAtkSubs]       = useState<SubOption[]>([]);
  const [defSubId, setDefSubId]     = useState('');
  const [atkSubId, setAtkSubId]     = useState('');
  const [busy, setBusy]             = useState(false);
  const [err, setErr]               = useState<string | null>(null);

  useEffect(() => {
    adminFetch('/admin/users?limit=200')
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setUsers(d.items ?? []); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!defUserId) { setDefSubs([]); setDefSubId(''); return; }
    adminFetch(`/admin/submissions/users/${defUserId}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        setDefSubs((d?.submissions ?? []).filter((s: { submission_type: string }) => s.submission_type === 'defense'));
        setDefSubId('');
      })
      .catch(() => {});
  }, [defUserId]);

  useEffect(() => {
    if (!atkUserId) { setAtkSubs([]); setAtkSubId(''); return; }
    adminFetch(`/admin/submissions/users/${atkUserId}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        setAtkSubs((d?.submissions ?? []).filter((s: { submission_type: string }) => s.submission_type === 'attack'));
        setAtkSubId('');
      })
      .catch(() => {});
  }, [atkUserId]);

  async function handle() {
    if (!defSubId || !atkSubId) return;
    setBusy(true);
    setErr(null);
    try {
      await triggerCsvDownload(
        `/admin/export/scores/individual?defense_submission_id=${defSubId}&attack_submission_id=${atkSubId}`,
        'evaluation_scores_individual.csv',
      );
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Download failed.');
    } finally {
      setBusy(false);
    }
  }

  const selectCls = "text-xs border border-gray-200 rounded px-2 py-1.5 m-1 text-gray-700 focus:outline-none focus:ring-2 focus:ring-primary/30 disabled:opacity-40 max-w-48";

  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-medium text-gray-800">Individual Evaluation Scores</p>
        <p className="text-xs text-gray-500">Per-file model output for a specific attacker-defender submission pair.</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <p className="text-xs text-gray-400">Defender</p>
          <select value={defUserId} onChange={e => setDefUserId(e.target.value)} className={selectCls}>
            <option value="">Select user...</option>
            {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <select value={defSubId} onChange={e => setDefSubId(e.target.value)} disabled={!defSubs.length} className={selectCls}>
            <option value="">Select submission...</option>
            {defSubs.map(s => <option key={s.id} value={s.id}>{s.display_name || s.version} (v{s.version})</option>)}
          </select>
        </div>
        <div className="space-y-1.5">
          <p className="text-xs text-gray-400">Attacker</p>
          <select value={atkUserId} onChange={e => setAtkUserId(e.target.value)} className={selectCls}>
            <option value="">Select user...</option>
            {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
          <select value={atkSubId} onChange={e => setAtkSubId(e.target.value)} disabled={!atkSubs.length} className={selectCls}>
            <option value="">Select submission...</option>
            {atkSubs.map(s => <option key={s.id} value={s.id}>{s.display_name || s.version} (v{s.version})</option>)}
          </select>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={handle}
          disabled={busy || !defSubId || !atkSubId}
          className="rounded border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-100 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? 'Downloading...' : 'Download CSV'}
        </button>
        {err && <span className="text-xs text-red-600">{err}</span>}
      </div>
    </div>
  );
}

const BULK_EXPORTS: { label: string; description: string; path: string; filename: string }[] = [
  {
    label: 'All Evaluation Scores',
    description: 'Confusion-matrix results (TP/FP/FN/TN) for every active attacker-defender pair.',
    path: '/admin/export/scores/all',
    filename: 'evaluation_scores_all.csv',
  },
  {
    label: 'Defense Validation Scores',
    description: 'Per-sample model output for each defense submission across all defense validation samples.',
    path: '/admin/export/validation-scores',
    filename: 'validation_scores.csv',
  },
  {
    label: 'Behavioral Analysis',
    description: 'Behavior classification status for each attack file relative to its source template.',
    path: '/admin/export/behavioral-analysis',
    filename: 'behavioral_analysis.csv',
  },
];

function DownloadsSection() {
  return (
    <Section title="Export Data">
      <div className="space-y-2">
        {BULK_EXPORTS.map(({ label, description, path, filename }) => (
          <div key={path} className="flex items-center justify-between gap-4 rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
            <div>
              <p className="text-sm font-medium text-gray-800">{label}</p>
              <p className="text-xs text-gray-500">{description}</p>
            </div>
            <DownloadButton label="Download CSV" path={path} filename={filename} />
          </div>
        ))}
        <div className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
          <IndividualScoresDownload />
        </div>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function CompetitionPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900">Competition</h1>
      <SubmissionSection />
      <AttackTemplateSection />
      <ValidationSamplesSection />
      <DownloadsSection />
    </div>
  );
}
