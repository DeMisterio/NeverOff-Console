import { closePool } from '@neveroff-console/db';

import { buildApp } from './app.js';
import { getConfig } from './config.js';

/**
 * API entry point.
 *
 * Workers run as a separate process (`npm run worker`) rather than on a timer
 * inside this one. Two reasons: the API can then be scaled horizontally without
 * every replica racing to lift the same expired ban, and a worker that wedges
 * cannot take request serving down with it.
 */

const config = getConfig();
const app = await buildApp();

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, 'shutting down');
  try {
    // Stop accepting connections first, then drain the pool, so an in-flight
    // enforcement transaction is allowed to commit rather than being cut off.
    await app.close();
    await closePool();
    process.exit(0);
  } catch (err) {
    app.log.error({ err }, 'error during shutdown');
    process.exit(1);
  }
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  app.log.fatal({ reason }, 'unhandled rejection');
  process.exit(1);
});

try {
  await app.listen({ port: config.API_PORT, host: config.API_HOST });
  app.log.info(
    {
      port: config.API_PORT,
      docs: config.isProduction ? 'disabled' : `http://${config.API_HOST}:${config.API_PORT}/docs`,
    },
    'NeverOff console API listening',
  );
} catch (err) {
  app.log.fatal({ err }, 'failed to start');
  process.exit(1);
}
