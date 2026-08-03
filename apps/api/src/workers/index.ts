import { closePool, getPool } from '@neveroff-console/db';

import { getConfig } from '../config.js';
import { detectAutomodDrift } from './automod.js';
import {
  captureChannelGrowth,
  detectChannelAnomalies,
  processExpiredChannelActions,
} from './channels.js';
import { deliverNotifications } from './notifications.js';
import { purgeExpiredData } from './retention.js';
import { refreshRollups } from './rollups.js';
import { escalateAppeals, processExpiredEnforcements } from './enforcement-expiry.js';

/**
 * Background worker process.
 *
 * Separate from the API so a wedged worker cannot take request serving down,
 * and so the API can scale horizontally without every replica racing to lift
 * the same expired ban.
 *
 * Every job is idempotent and claims its rows with FOR UPDATE SKIP LOCKED, so
 * running two worker processes is safe — they split the work rather than
 * duplicating it. That matters because the obvious deployment mistake is to run
 * one per API replica.
 *
 * The important design property: if this process never runs, users are still
 * correctly unbanned on time, because every access check evaluates expiry
 * against NOW() rather than reading a flag this worker sets. What stops is the
 * *notification* that it happened. That is the right thing to degrade.
 */

interface Job {
  readonly name: string;
  readonly intervalMs: number;
  readonly run: () => Promise<number>;
}

const JOBS: Job[] = [
  {
    name: 'enforcement-expiry',
    intervalMs: 60_000,
    run: processExpiredEnforcements,
  },
  {
    name: 'appeal-sla-escalation',
    intervalMs: 300_000,
    run: escalateAppeals,
  },
  {
    name: 'channel-restriction-expiry',
    intervalMs: 60_000,
    run: processExpiredChannelActions,
  },
  {
    name: 'notification-delivery',
    intervalMs: 15_000,
    run: deliverNotifications,
  },
  {
    name: 'analytics-rollups',
    // Five minutes. §2.6 wants a visible "data as of" rather than live numbers,
    // and recomputing whole buckets more often than this is pure load.
    intervalMs: 300_000,
    run: refreshRollups,
  },
  {
    name: 'channel-growth-snapshot',
    // Hourly. The anomaly check compares a day against a fortnight, so
    // sampling more often buys nothing but rows.
    intervalMs: 3_600_000,
    run: captureChannelGrowth,
  },
  {
    name: 'channel-anomaly-detection',
    intervalMs: 3_600_000,
    run: detectChannelAnomalies,
  },
  {
    name: 'automod-drift-detection',
    intervalMs: 3_600_000,
    run: detectAutomodDrift,
  },
  {
    name: 'retention-purge',
    // Hourly. Retention is measured in days; running it more often only adds
    // load, and running it less risks holding data past a configured TTL.
    intervalMs: 3_600_000,
    run: purgeExpiredData,
  },
];

let shuttingDown = false;
const timers: NodeJS.Timeout[] = [];

async function runJob(job: Job): Promise<void> {
  if (shuttingDown) return;

  const pool = getPool();
  try {
    await pool.query(`SELECT admin.worker_started($1)`, [job.name]);
    const processed = await job.run();
    await pool.query(`SELECT admin.worker_succeeded($1, $2)`, [job.name, processed]);

    if (processed > 0) {
      console.log(`[worker] ${job.name}: processed ${processed}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[worker] ${job.name} failed: ${message}`);

    try {
      await pool.query(`SELECT admin.worker_failed($1, $2)`, [job.name, message]);

      // Persistent failure of the expiry job means users may be sitting past
      // their ban expiry without being told. That deserves an alert, not just
      // a log line nobody reads.
      const { rows } = await pool.query<{ consecutive_failures: number }>(
        `SELECT consecutive_failures FROM admin.worker_runs WHERE name = $1`,
        [job.name],
      );
      const failures = rows[0]?.consecutive_failures ?? 0;

      if (failures === 5) {
        await pool.query(
          `INSERT INTO admin.alerts (kind, severity, title, detail, evidence)
           VALUES ('worker_stalled', 'critical', $1, $2, $3)`,
          [
            `Background job "${job.name}" has failed 5 times in a row`,
            'Enforcement expiry notifications and retention purging depend on this job. ' +
              'Investigate before users start noticing.',
            JSON.stringify({ job: job.name, error: message }),
          ],
        );
      }
    } catch (alertErr) {
      // The database is unreachable. Nothing useful left to do but say so.
      console.error('[worker] could not record failure:', alertErr);
    }
  }
}

function schedule(job: Job): void {
  // Run immediately on boot, then on the interval. Without the immediate run, a
  // restart every 55 seconds would mean the hourly job never fires.
  void runJob(job);
  const timer = setInterval(() => void runJob(job), job.intervalMs);
  timers.push(timer);
}

async function shutdown(signal: string): Promise<void> {
  console.log(`[worker] ${signal} received, stopping`);
  shuttingDown = true;
  for (const timer of timers) clearInterval(timer);
  await closePool();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

const config = getConfig();
console.log(
  `[worker] starting ${JOBS.length} jobs` +
    (config.pushEnabled ? '' : ' — push is NOT configured, notifications will queue unsent'),
);

for (const job of JOBS) schedule(job);
