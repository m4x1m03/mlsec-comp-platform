import { useState, useEffect } from 'react';

interface Axis {
  user_id: string;
  username: string;
  submission_id: string;
  display_name: string | null;
  version: string;
}

interface Score {
  score: number;
  n_files_scored: number;
  n_files_error: number;
  computed_at: string;
}

interface LeaderboardData {
  attackers: Axis[];
  defenders: Axis[];
  // keys are "{attack_submission_id}/{defense_submission_id}"
  scores: Record<string, Score>;
}

/**
 * Maps a score (0.0 to 1.0) to an RGB color.
 * 0%  = orange   rgb(254, 179, 56)
 * 50% = white rgb(230, 230, 230)
 * 100% = blue rgb(2, 81, 150)
 */
function scoreToColor(score: number): string {
  const s = Math.max(0, Math.min(1, score));
  if (s <= 0.5) {
    const t = s / 0.5;
    const r = Math.round(254 + (230 - 254) * t);
    const g = Math.round(179  + (230 - 179)  * t);
    const b = Math.round(56  + (230 - 56)  * t);
    return `rgb(${r},${g},${b})`;
  }
  const t = (s - 0.5) / 0.5;
  const r = Math.round(230 + (2  - 230) * t);
  const g = Math.round(230 + (81 - 230) * t);
  const b = Math.round(230 + (150  - 230) * t);
  return `rgb(${r},${g},${b})`;
}

function textColorForScore(score: number): string {
  return score > 0.70 ? '#ffffff' : '#374151';
}

export default function EvaluationMatrix() {
  const [data, setData] = useState<LeaderboardData | null>(null);
  const [showPercentages, setShowPercentages] = useState(true);
  const [showGradient, setShowGradient] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  useEffect(() => {
    // Initial fetch so the matrix is populated before the first SSE push.
    fetch('/api/leaderboard')
      .then(r => (r.ok ? r.json() : null))
      .then((d: LeaderboardData | null) => {
        if (d) { setData(d); setLastUpdated(new Date()); }
      })
      .catch(() => {});

    const es = new EventSource('/api/leaderboard/stream');
    es.onmessage = (e: MessageEvent) => {
      try {
        setData(JSON.parse(e.data) as LeaderboardData);
        setLastUpdated(new Date());
      } catch {
        // malformed payload, skip
      }
    };

    return () => es.close();
  }, []);

  if (!data) {
    return <p className="text-sm text-gray-400">Loading matrix...</p>;
  }

  const { attackers, defenders, scores } = data;

  if (attackers.length === 0 && defenders.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        No active submissions yet. Once participants activate a submission, the matrix will appear here.
      </p>
    );
  }

  const hasScores = Object.keys(scores).length > 0;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-6 flex-wrap">
        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showPercentages}
            onChange={e => setShowPercentages(e.target.checked)}
            className="w-4 h-4 accent-primary"
          />
          Toggle percentages
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showGradient}
            onChange={e => setShowGradient(e.target.checked)}
            className="w-4 h-4 accent-primary"
          />
          Toggle gradient
        </label>
        {lastUpdated && (
          <span className="ml-auto text-xs text-gray-400">
            Updated {lastUpdated.toLocaleTimeString()}
          </span>
        )}
      </div>

      {!hasScores && (
        <div className="rounded-lg border border-gray-200 bg-gray-50 px-5 py-4 text-sm text-gray-500">
          Active submissions are registered. Scores will appear here as evaluation pairs finish running.
        </div>
      )}

      <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table className="min-w-full border-collapse text-sm">
          <thead>
            {/* Axis label row */}
            <tr>
              <th className="sticky left-0 z-10 bg-gray-50 border-b border-r border-gray-200 w-5 min-w-[20px]" />
              <th className="sticky left-5 z-10 bg-gray-50 border-b border-gray-200 w-[88px] min-w-[88px] md:w-[132px] md:min-w-[132px]" />
              {attackers.length > 0 && (
                <th
                  colSpan={attackers.length}
                  className="border-b border-r border-gray-200 bg-gray-50 py-1.5 text-center text-xs font-semibold text-gray-400"
                >
                  Attack
                </th>
              )}
            </tr>
            {/* Column headers row */}
            <tr>
              <th className="sticky left-0 z-10 bg-gray-50 border-r border-gray-200 w-5 min-w-[20px]" />
              <th className="sticky left-5 z-10 bg-gray-50 border-b border-r border-gray-200 px-2 py-2 md:px-4 md:py-3 w-[88px] min-w-[88px] md:w-[132px] md:min-w-[132px]" />
              {attackers.map(atk => (
                <th
                  key={atk.submission_id}
                  className="border-b border-r border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center bg-gray-50 w-[72px] min-w-[72px] max-w-[72px] md:w-[112px] md:min-w-[112px] md:max-w-[112px]"
                  title={[atk.username, atk.display_name, `v${atk.version}`].filter(Boolean).join(' · ')}
                >
                  <div className="w-full overflow-hidden">
                    <div className="text-xs font-semibold text-gray-700 truncate">{atk.username}</div>
                    {atk.display_name && (
                      <div className="hidden md:block text-xs font-normal text-gray-400 mt-0.5 truncate">{atk.display_name}</div>
                    )}
                    <div className="hidden md:block text-xs font-mono font-normal text-gray-400 truncate">v{atk.version}</div>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {defenders.map((def, di) => (
              <tr key={def.submission_id} className={di % 2 === 0 ? 'bg-white' : 'bg-gray-50/40'}>
                {di === 0 && (
                  <td
                    rowSpan={defenders.length}
                    className="sticky left-0 z-10 bg-gray-50 border-r border-gray-200 w-5 min-w-[20px] text-center align-middle"
                  >
                    <span
                      className="text-xs font-semibold text-gray-400 select-none"
                      style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}
                    >
                      Defense
                    </span>
                  </td>
                )}
                <td
                  className={`sticky left-5 z-10 border-b border-r border-gray-200 px-2 py-2 md:px-3 md:py-3 w-[88px] min-w-[88px] max-w-[88px] md:w-[132px] md:min-w-[132px] md:max-w-[132px] ${di % 2 === 0 ? 'bg-white' : 'bg-gray-50'}`}
                  title={[def.username, def.display_name, `v${def.version}`].filter(Boolean).join(' · ')}
                >
                  <div className="w-full overflow-hidden">
                    <div className="text-xs font-semibold text-gray-700 truncate">{def.username}</div>
                    {def.display_name && (
                      <div className="hidden md:block text-xs text-gray-400 truncate">{def.display_name}</div>
                    )}
                    <div className="hidden md:block text-xs font-mono text-gray-400 truncate">v{def.version}</div>
                  </div>
                </td>
                {attackers.map(atk => {
                  const key = `${atk.submission_id}/${def.submission_id}`;
                  const entry = scores[key];
                  const bgColor = entry && showGradient ? scoreToColor(entry.score) : undefined;
                  const fgColor = entry && showGradient ? textColorForScore(entry.score) : '#374151';

                  return (
                    <td
                      key={atk.submission_id}
                      className="border-b border-r border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center transition-colors duration-300 w-[72px] min-w-[72px] md:w-[112px] md:min-w-[112px]"
                      style={bgColor ? { backgroundColor: bgColor } : undefined}
                      title={
                        entry
                          ? `${(entry.score * 100).toFixed(1)}% accuracy\nFiles scored: ${entry.n_files_scored}\nFiles errored: ${entry.n_files_error}`
                          : 'Not yet evaluated'
                      }
                    >
                      {entry ? (
                        showPercentages && (
                          <span
                            className="text-xs font-semibold tabular-nums"
                            style={{ color: fgColor }}
                          >
                            {(entry.score * 100).toFixed(0)}%
                          </span>
                        )
                      ) : (
                        <span className="text-xs text-gray-300">--</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
