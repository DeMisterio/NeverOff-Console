import { useId, useState } from 'react';

/**
 * Chart primitives.
 *
 * Hand-rolled SVG rather than a charting library. Two reasons: the shapes here
 * are a stacked bar and a stat tile, which are forty lines of geometry between
 * them, and every dependency added to an unverified codebase is another thing
 * that can fail on first boot for reasons unrelated to the console.
 *
 * Colour comes from the validated categorical palette, slots 1–3, used in fixed
 * order and never cycled. Those three clear the colourblind-separation floors
 * on all pairs in both light and dark. A fourth series is deliberately not
 * available: past three, the next slot puts yellow beside orange and fails the
 * all-pairs floor. If a fourth surface ever exists it folds into "Other".
 *
 * Aqua sits below 3:1 on the light surface, so the relief rule applies — every
 * chart here ships a table view toggle, and identity is never colour alone.
 */

export const SERIES = ['var(--series-1)', 'var(--series-2)', 'var(--series-3)'] as const;

/** Palette roles. Dark is a selected set of steps, not an inverted light. */
export function VizStyles() {
  return (
    <style>{`
      .viz-root {
        color-scheme: light;
        --surface-1: #fcfcfb;
        --text-primary: #0b0b0b;
        --text-secondary: #52514e;
        --text-muted: #898781;
        --gridline: #e1e0d9;
        --baseline: #c3c2b7;
        --series-1: #2a78d6;
        --series-2: #eb6834;
        --series-3: #1baf7a;
        --status-good: #0ca30c;
        --status-warning: #fab219;
        --status-critical: #d03b3b;
      }
      @media (prefers-color-scheme: dark) {
        :root:where(:not([data-theme="light"])) .viz-root {
          color-scheme: dark;
          --surface-1: #1a1a19;
          --text-primary: #ffffff;
          --text-secondary: #c3c2b7;
          --text-muted: #898781;
          --gridline: #2c2c2a;
          --baseline: #383835;
          --series-1: #3987e5;
          --series-2: #d95926;
          --series-3: #199e70;
        }
      }
      :root[data-theme="dark"] .viz-root {
        color-scheme: dark;
        --surface-1: #1a1a19;
        --text-primary: #ffffff;
        --text-secondary: #c3c2b7;
        --text-muted: #898781;
        --gridline: #2c2c2a;
        --baseline: #383835;
        --series-1: #3987e5;
        --series-2: #d95926;
        --series-3: #199e70;
      }
    `}</style>
  );
}

export interface StackedPoint {
  label: string;
  /** Values in fixed series order; never reordered by magnitude. */
  values: number[];
}

/**
 * Stacked bars over time.
 *
 * One axis, always. Two measures of different scale get two charts, never a
 * second y-scale — that is the single most common way a chart lies.
 */
export function StackedBars({
  data,
  seriesLabels,
  title,
  valueFormat = (n: number) => n.toLocaleString(),
}: {
  data: StackedPoint[];
  seriesLabels: string[];
  title: string;
  valueFormat?: (n: number) => string;
}) {
  const [showTable, setShowTable] = useState(false);
  const [hover, setHover] = useState<{ i: number; s: number } | null>(null);
  const titleId = useId();

  const totals = data.map((d) => d.values.reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);

  const width = 720;
  const height = 220;
  const padLeft = 48;
  const padBottom = 28;
  const plotW = width - padLeft - 8;
  const plotH = height - padBottom - 8;
  const slot = plotW / Math.max(data.length, 1);
  const barW = Math.max(2, Math.min(28, slot - 6));

  return (
    <div className="viz-root">
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <h3 id={titleId} className="text-sm font-semibold">
          {title}
        </h3>
        {/* Legend is always present for ≥2 series, so identity is never colour alone. */}
        <ul className="flex flex-wrap gap-3 text-xs" aria-hidden="true">
          {seriesLabels.map((label, i) => (
            <li key={label} className="flex items-center gap-1.5">
              <span
                className="inline-block h-2.5 w-2.5 rounded-sm"
                style={{ background: SERIES[i % SERIES.length] }}
              />
              <span className="text-slate-700 dark:text-slate-300">{label}</span>
            </li>
          ))}
        </ul>
        <button
          type="button"
          onClick={() => setShowTable((v) => !v)}
          className="ml-auto rounded border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
        >
          {showTable ? 'Show chart' : 'Show table'}
        </button>
      </div>

      {showTable ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm tabular-nums">
            <caption className="sr-only">{title}, as a table</caption>
            <thead className="text-xs uppercase text-slate-600 dark:text-slate-400">
              <tr>
                <th scope="col" className="py-1 pr-4">Period</th>
                {seriesLabels.map((l) => (
                  <th key={l} scope="col" className="py-1 pr-4">{l}</th>
                ))}
                <th scope="col" className="py-1">Total</th>
              </tr>
            </thead>
            <tbody>
              {data.map((d, i) => (
                <tr key={d.label} className="border-t border-slate-100 dark:border-slate-800">
                  <th scope="row" className="py-1 pr-4 font-normal">{d.label}</th>
                  {d.values.map((v, s) => (
                    <td key={s} className="py-1 pr-4">{valueFormat(v)}</td>
                  ))}
                  <td className="py-1 font-medium">{valueFormat(totals[i] ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="relative">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full"
            role="img"
            aria-labelledby={titleId}
          >
            {/* Recessive grid: hairlines, never competing with the marks. */}
            {[0, 0.25, 0.5, 0.75, 1].map((t) => (
              <g key={t}>
                <line
                  x1={padLeft}
                  x2={width - 8}
                  y1={8 + plotH * (1 - t)}
                  y2={8 + plotH * (1 - t)}
                  stroke="var(--gridline)"
                  strokeWidth={1}
                />
                <text
                  x={padLeft - 6}
                  y={8 + plotH * (1 - t) + 4}
                  textAnchor="end"
                  fontSize={10}
                  fill="var(--text-muted)"
                  className="tabular-nums"
                >
                  {valueFormat(Math.round(max * t))}
                </text>
              </g>
            ))}

            {data.map((point, i) => {
              let cursor = 0;
              const x = padLeft + slot * i + (slot - barW) / 2;
              return (
                <g key={point.label}>
                  {point.values.map((value, s) => {
                    if (value <= 0) return null;
                    const h = (value / max) * plotH;
                    const y = 8 + plotH - cursor - h;
                    cursor += h;
                    const isTop = point.values.slice(s + 1).every((v) => v <= 0);
                    return (
                      <rect
                        key={s}
                        x={x}
                        // 2px surface gap between stacked segments.
                        y={y + (s === 0 ? 0 : 2)}
                        width={barW}
                        height={Math.max(1, h - (s === 0 ? 0 : 2))}
                        // 4px rounded data-end on the top of the stack only;
                        // the rest stays anchored square to the baseline.
                        rx={isTop ? 4 : 0}
                        fill={SERIES[s % SERIES.length]}
                        opacity={hover && hover.i !== i ? 0.45 : 1}
                        onMouseEnter={() => setHover({ i, s })}
                        onMouseLeave={() => setHover(null)}
                      />
                    );
                  })}
                </g>
              );
            })}

            <line
              x1={padLeft}
              x2={width - 8}
              y1={8 + plotH}
              y2={8 + plotH}
              stroke="var(--baseline)"
              strokeWidth={1}
            />

            {/* Selective labels only — never a number on every bar. */}
            {data.map((point, i) =>
              i % Math.ceil(data.length / 6) === 0 ? (
                <text
                  key={point.label}
                  x={padLeft + slot * i + slot / 2}
                  y={height - 8}
                  textAnchor="middle"
                  fontSize={10}
                  fill="var(--text-muted)"
                >
                  {point.label}
                </text>
              ) : null,
            )}
          </svg>

          {hover && (
            <div
              role="status"
              className="pointer-events-none absolute left-2 top-2 rounded border border-slate-300 bg-white px-2 py-1 text-xs shadow dark:border-slate-700 dark:bg-slate-900"
            >
              <strong>{data[hover.i]?.label}</strong>
              <ul className="mt-1 space-y-0.5">
                {seriesLabels.map((label, s) => (
                  <li key={label} className="flex items-center gap-1.5 tabular-nums">
                    <span
                      className="inline-block h-2 w-2 rounded-sm"
                      style={{ background: SERIES[s % SERIES.length] }}
                    />
                    {label}: {valueFormat(data[hover.i]?.values[s] ?? 0)}
                  </li>
                ))}
                <li className="border-t border-slate-200 pt-0.5 font-medium tabular-nums dark:border-slate-700">
                  Total: {valueFormat(totals[hover.i] ?? 0)}
                </li>
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * A single headline number. §2.6's real-time strip is five of these, and a
 * five-slice chart of unrelated counters would be worse than useless.
 */
export function StatTile({
  label,
  value,
  hint,
  status,
}: {
  label: string;
  value: string | number;
  hint?: string;
  status?: 'good' | 'warning' | 'critical';
}) {
  // Status colour never carries meaning alone — it always arrives with the
  // glyph and the label beside it.
  const glyph = status === 'critical' ? '!' : status === 'warning' ? '•' : null;
  const colour =
    status === 'critical'
      ? 'var(--status-critical)'
      : status === 'warning'
        ? 'var(--status-warning)'
        : undefined;

  return (
    <div className="viz-root rounded-lg border border-slate-200 p-3 dark:border-slate-800">
      <div className="text-xs text-slate-600 dark:text-slate-400">{label}</div>
      <div className="mt-1 flex items-baseline gap-2">
        {glyph && (
          <span aria-hidden="true" className="text-sm font-bold" style={{ color: colour }}>
            {glyph}
          </span>
        )}
        <span className="text-2xl font-semibold">{value}</span>
      </div>
      {hint && <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </div>
  );
}
