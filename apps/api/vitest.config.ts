import { defineConfig } from 'vitest/config';

/**
 * The database invariant tests talk to a real Postgres: each one creates a few
 * users, files reports through the actual RPC, and triggers case recomputation
 * with its priority scoring. The 5s default is comfortably too short for that,
 * and a timeout mid-query leaves the client checked out — so a handful of slow
 * tests exhaust the pool and everything after them times out too, which reads
 * as nineteen failures when the real count is zero.
 */
export default defineConfig({
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // These tests share one database and create rows with overlapping shapes.
    // Running them in parallel would make clustering assertions depend on what
    // another file happened to insert a moment earlier.
    fileParallelism: false,
  },
});
