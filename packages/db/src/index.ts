export {
  assertAllowedHost,
  assertLocalOnly,
  assertProductionAck,
  closePool,
  describeTarget,
  getPool,
  withTransaction,
  PRODUCTION_ACK_PHRASE,
  type DbTarget,
} from './client.js';

export { syncCatalogue, type SyncSummary } from './sync-catalogue.js';
