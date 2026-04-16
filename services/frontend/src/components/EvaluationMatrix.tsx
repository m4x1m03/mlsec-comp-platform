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

function summaryScoreToColor(score: number): string {
  const s = Math.max(0, Math.min(1, score));
  // Purple (0%) -> light neutral (50%) -> green (100%)
  // Routing through a neutral midpoint avoids a muddy intermediate hue.
  const purple  = [152, 110, 172] as const;
  const neutral = [235, 235, 235] as const;
  const green   = [92,  174,  99] as const;
  const [from, to, t] = s <= 0.5
    ? [purple, neutral, s / 0.5]
    : [neutral, green, (s - 0.5) / 0.5];
  return `rgb(${Math.round(from[0] + (to[0] - from[0]) * t)},${Math.round(from[1] + (to[1] - from[1]) * t)},${Math.round(from[2] + (to[2] - from[2]) * t)})`;
}

function summaryTextColor(): string {
  // All pastel summary colors are light enough for dark text throughout.
  return '#374151';
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

  if (attackers.length === 0 || defenders.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        The matrix will appear once there is at least one active attack submission and one active defense submission.
      </p>
    );
  }

  const hasScores = Object.keys(scores).length > 0;

  const defenderTotals = new Map<string, { correct: number; total: number } | null>(
    defenders.map(def => {
      let correct = 0;
      let total = 0;
      attackers.forEach(atk => {
        const entry = scores[`${atk.submission_id}/${def.submission_id}`];
        if (entry) {
          correct += entry.score * entry.n_files_scored;
          total += entry.n_files_scored;
        }
      });
      return [def.submission_id, total > 0 ? { correct, total } : null];
    })
  );

  const attackerEvasions = new Map<string, { evaded: number; total: number } | null>(
    attackers.map(atk => {
      let evaded = 0;
      let total = 0;
      defenders.forEach(def => {
        const entry = scores[`${atk.submission_id}/${def.submission_id}`];
        if (entry) {
          evaded += (1 - entry.score) * entry.n_files_scored;
          total += entry.n_files_scored;
        }
      });
      return [atk.submission_id, total > 0 ? { evaded, total } : null];
    })
  );

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

      <div className="overflow-x-auto">
        <div className="w-fit rounded-xl border border-gray-200 bg-white shadow-sm" style={{ overflow: 'clip' }}>
        <table className="w-auto border-collapse text-sm">
          <tbody>
            {/* Row 1: Attack axis label spans all columns including the Total Detections column. */}
            <tr>
              {/* Transparent so the wrapper's rounded-xl corner shows through. */}
              <th className="sticky left-0 z-10 bg-transparent border-b border-r border-gray-200 w-7 min-w-[28px]" />
              {attackers.length > 0 && (
                <th
                  colSpan={attackers.length + 2}
                  className="border-b border-gray-200 bg-white py-1.5 text-center text-xs font-semibold text-gray-600"
                >
                  Attack
                </th>
              )}
            </tr>
            {/* Row 2: Column headers. Defense label starts here and spans down through all defender rows. */}
            <tr>
              <th
                rowSpan={defenders.length + 2}
                className="sticky left-0 z-10 bg-white border-r border-gray-200 w-7 min-w-[28px]"
                style={{ verticalAlign: 'middle', textAlign: 'center' }}
              >
                <span
                  className="text-xs font-semibold text-gray-600 select-none"
                  style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', display: 'inline-block' }}
                >
                  Defense
                </span>
              </th>
              <th className="sticky left-7 z-10 bg-white border-b border-r border-gray-200 px-2 py-2 md:px-4 md:py-3 w-[112px] min-w-[112px] md:w-[160px] md:min-w-[160px]" />
              {attackers.map((atk, ai) => (
                <th
                  key={atk.submission_id}
                  className={`border-b border-r border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center w-[96px] min-w-[96px] max-w-[96px] md:w-[144px] md:min-w-[144px] md:max-w-[144px] ${ai % 2 === 0 ? 'bg-white' : 'bg-gray-100'}`}
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
              <th className={`border-b border-l-2 border-l-gray-400 border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center w-[96px] min-w-[96px] max-w-[96px] md:w-[144px] md:min-w-[144px] md:max-w-[144px] ${attackers.length % 2 === 0 ? 'bg-white' : 'bg-gray-100'}`}>
                <div className="text-xs font-semibold text-gray-700">Total Detections</div>
              </th>
            </tr>
            {/* Defender rows. Defense label column is covered by the rowSpan above. */}
            {defenders.map((def, di) => {
              const defTotal = defenderTotals.get(def.submission_id) ?? null;
              const defPct = defTotal ? defTotal.correct / defTotal.total : null;
              return (
                <tr key={def.submission_id}>
                  <td
                    className={`sticky left-7 z-10 border-b border-r border-gray-200 px-2 py-2 md:px-3 md:py-3 w-[112px] min-w-[112px] max-w-[112px] md:w-[160px] md:min-w-[160px] md:max-w-[160px] ${di % 2 === 0 ? 'bg-white' : 'bg-gray-100'}`}
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
                        className="border-b border-r border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center transition-colors duration-300 w-[96px] min-w-[96px] md:w-[144px] md:min-w-[144px] bg-white"
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
                  <td
                    className="border-b border-l-2 border-l-gray-400 border-gray-200 px-1 py-2 md:px-3 md:py-3 text-center transition-colors duration-300 w-[96px] min-w-[96px] md:w-[144px] md:min-w-[144px] bg-white"
                    style={defPct !== null && showGradient ? { backgroundColor: summaryScoreToColor(defPct) } : undefined}
                    title={defTotal ? `${Math.round(defTotal.correct)}/${defTotal.total}` : 'Not yet evaluated'}
                  >
                    {defPct !== null ? (
                      showPercentages && (
                        <span
                          className="text-xs font-semibold tabular-nums"
                          style={{ color: showGradient ? summaryTextColor() : '#374151' }}
                        >
                          {(defPct * 100).toFixed(0)}%
                        </span>
                      )
                    ) : (
                      <span className="text-xs text-gray-300">--</span>
                    )}
                  </td>
                </tr>
              );
            })}
            {/* Total Evasions row: Defense rowSpan covers the leftmost column, no stub needed. */}
            <tr>
              <td className={`sticky left-7 z-10 border-t-2 border-t-gray-400 border-r border-gray-200 px-2 py-2 md:px-3 md:py-3 w-[112px] min-w-[112px] max-w-[112px] md:w-[160px] md:min-w-[160px] md:max-w-[160px] ${defenders.length % 2 === 0 ? 'bg-white' : 'bg-gray-100'}`} style={{ boxShadow: '1px 0 0 #e5e7eb' }}>
                <div className="w-full overflow-hidden">
                  <div className="hidden md:block text-xs text-gray-400 truncate invisible">&nbsp;</div>
                  <div className="text-xs font-semibold text-gray-700 truncate">Total Evasions</div>
                  <div className="hidden md:block text-xs font-mono text-gray-400 truncate invisible">&nbsp;</div>
                </div>
              </td>
              {attackers.map(atk => {
                const atkEvasion = attackerEvasions.get(atk.submission_id) ?? null;
                const evasionPct = atkEvasion ? atkEvasion.evaded / atkEvasion.total : null;
                return (
                  <td
                    key={atk.submission_id}
                    className="border-t-2 border-t-gray-400 px-1 py-2 md:px-3 md:py-3 text-center transition-colors duration-300 w-[96px] min-w-[96px] md:w-[144px] md:min-w-[144px] bg-white"
                    style={evasionPct !== null && showGradient ? { backgroundColor: summaryScoreToColor(evasionPct) } : undefined}
                    title={atkEvasion ? `${Math.round(atkEvasion.evaded)}/${atkEvasion.total}` : 'Not yet evaluated'}
                  >
                    {evasionPct !== null ? (
                      showPercentages && (
                        <span
                          className="text-xs font-semibold tabular-nums"
                          style={{ color: summaryTextColor() }}
                        >
                          {(evasionPct * 100).toFixed(0)}%
                        </span>
                      )
                    ) : (
                      <span className="text-xs text-gray-300">--</span>
                    )}
                  </td>
                );
              })}
              <td className="border-t-2 border-t-gray-400 border-l-2 border-l-gray-400 w-[96px] min-w-[96px] md:w-[144px] md:min-w-[144px] bg-transparent" />
            </tr>
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
}
