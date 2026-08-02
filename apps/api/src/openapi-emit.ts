import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { closePool } from '@neveroff-console/db';

import { buildApp } from './app.js';

/**
 * Emit the OpenAPI document (§12 deliverable 3).
 *
 * Generated from the live route definitions rather than hand-maintained, so a
 * route whose schema changes cannot leave the published spec stale.
 */
const app = await buildApp();
await app.ready();

const spec = app.swagger();
const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'openapi.json');

writeFileSync(outPath, JSON.stringify(spec, null, 2), 'utf8');
console.log(`  OpenAPI written to ${outPath}`);

const paths = Object.keys((spec as { paths?: Record<string, unknown> }).paths ?? {});
console.log(`  ${paths.length} paths documented`);

await app.close();
await closePool();
