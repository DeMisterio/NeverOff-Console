import {
  PERMISSIONS,
  ROLES,
  ROLE_KEYS,
  resolvePermissions,
  type Permission,
} from '@neveroff-console/shared';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { getConfig } from '../config.js';
import { actorOf } from '../plugins/auth.js';
import { requirePermission } from '../rbac.js';

/**
 * Roles and the permission matrix.
 *
 * Read-only, and served from the TypeScript catalogue rather than the database
 * copy. The catalogue is the source of truth; the database copy exists for
 * referential integrity and for SQL-based compliance reporting. Serving from
 * code means the console can never display a matrix that disagrees with what
 * the authorisation layer will actually do.
 *
 * The §12 deliverable "permission matrix documentation" is generated from the
 * same data by scripts/generate-permission-matrix.ts.
 */
export default async function roleRoutes(fastify: FastifyInstance): Promise<void> {
  const app = fastify.withTypeProvider<ZodTypeProvider>();
  const config = getConfig();

  app.get(
    '/permissions',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['roles'],
        summary: 'The permission atom catalogue',
        response: {
          200: z.array(
            z.object({
              key: z.string(),
              label: z.string(),
              description: z.string(),
              category: z.string(),
              breakGlass: z.string(),
              pii: z.boolean(),
              superAdminOnly: z.boolean(),
              addedBeyondSpec: z.string().nullable(),
              heldByYou: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      return PERMISSIONS.map((p) => ({
        key: p.key,
        label: p.label,
        description: p.description,
        category: p.category,
        breakGlass: p.breakGlass,
        pii: p.pii,
        superAdminOnly: p.superAdminOnly,
        addedBeyondSpec: p.addedBeyondSpec ?? null,
        heldByYou: actor.permissions.has(p.key),
      }));
    },
  );

  app.get(
    '/',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['roles'],
        summary: 'Role definitions with their bundled permissions',
        response: {
          200: z.array(
            z.object({
              key: z.string(),
              label: z.string(),
              description: z.string(),
              rank: z.number(),
              maxBanDays: z.number().nullable(),
              singleton: z.boolean(),
              scopable: z.boolean(),
              permissions: z.array(z.string()),
              assignableByYou: z.boolean(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);

      return ROLE_KEYS.map((key) => {
        const role = ROLES[key];
        const permissions = [...resolvePermissions({
          id: '', role: key,
          scope: { countries: null, languages: null, channelIds: null, reportCategories: null },
          extraPermissions: [], revokedPermissions: [], active: true,
        })];

        return {
          key: role.key,
          label: role.label,
          description: role.description,
          rank: role.rank,
          // The Tier 2 cap is configuration; show the value actually in force
          // rather than the compiled-in fallback.
          maxBanDays:
            key === 'tier2_moderation_lead' ? config.MAX_BAN_DAYS_T2 : role.maxBanDays,
          singleton: role.singleton,
          scopable: role.scopable,
          permissions,
          // Mirrors canDelegate's rank rule, for greying out the UI. The write
          // path re-checks; this is presentation only.
          assignableByYou:
            key !== 'super_admin' &&
            role.rank < ROLES[actor.role].rank &&
            actor.permissions.has('admins.create') &&
            permissions.every((p) => actor.permissions.has(p as Permission)),
        };
      });
    },
  );

  app.get(
    '/matrix',
    {
      preHandler: fastify.requireAuth,
      schema: {
        tags: ['roles'],
        summary: 'Role × permission grid (§12 deliverable)',
        response: {
          200: z.object({
            roles: z.array(z.object({ key: z.string(), label: z.string(), rank: z.number() })),
            permissions: z.array(
              z.object({
                key: z.string(),
                label: z.string(),
                category: z.string(),
                superAdminOnly: z.boolean(),
                breakGlass: z.string(),
                grantedTo: z.array(z.string()),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const actor = actorOf(request);
      requirePermission(actor, 'users.view');

      const resolved = new Map<string, ReadonlySet<Permission>>(
        ROLE_KEYS.map((key) => [
          key,
          resolvePermissions({
            id: '', role: key,
            scope: { countries: null, languages: null, channelIds: null, reportCategories: null },
            extraPermissions: [], revokedPermissions: [], active: true,
          }),
        ]),
      );

      return {
        roles: ROLE_KEYS.map((key) => ({
          key,
          label: ROLES[key].label,
          rank: ROLES[key].rank,
        })),
        permissions: PERMISSIONS.map((p) => ({
          key: p.key,
          label: p.label,
          category: p.category,
          superAdminOnly: p.superAdminOnly,
          breakGlass: p.breakGlass,
          grantedTo: ROLE_KEYS.filter((key) => resolved.get(key)?.has(p.key)),
        })),
      };
    },
  );
}
