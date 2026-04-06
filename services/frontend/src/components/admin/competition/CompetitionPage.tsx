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
// Main
// ---------------------------------------------------------------------------

export default function CompetitionPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900">Competition</h1>
      <SubmissionSection />
      <AttackTemplateSection />
      <ValidationSamplesSection />
    </div>
  );
}
