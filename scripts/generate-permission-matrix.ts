import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PERMISSIONS,
  ROLES,
  ROLE_KEYS,
  permissionsByCategory,
  resolvePermissions,
  type PermissionCategory,
} from '@neveroff-console/shared';

/**
 * Regenerate docs/PERMISSION_MATRIX.md from the catalogue.
 *
 * Generated rather than hand-maintained because a matrix that disagrees with
 * the code is worse than no matrix — it is the document a compliance reviewer
 * will trust.
 */

const CATEGORY_LABELS: Record<PermissionCategory, string> = {
  analytics: 'Analytics',
  users: 'Users',
  channels: 'Channels',
  reports: 'Reports',
  support: 'Support',
  administration: 'Administration',
  compliance: 'Compliance',
  child_safety: 'Child safety (§6.7)',
};

const resolved = new Map(
  ROLE_KEYS.map((role) => [
    role,
    resolvePermissions({
      id: '',
      role,
      scope: { countries: null, languages: null, channelIds: null, reportCategories: null },
      extraPermissions: [],
      revokedPermissions: [],
      active: true,
    }),
  ]),
);

const lines: string[] = [
  '# Permission matrix',
  '',
  'Role × permission grid. **Generated** — regenerate after any change to',
  '`packages/shared/src/permissions.ts` or `roles.ts`:',
  '',
  '```bash',
  'npm run docs:matrix',
  '```',
  '',
  'Legend: **✓** granted · **·** not granted · **SA** reserved to the Super Admin regardless of role',
  '· **BG** requires break-glass friction at the point of use · **PII** use is recorded as a',
  'personal-data access',
  '',
  `| Permission | ${ROLE_KEYS.map((r) => ROLES[r].label).join(' | ')} | Notes |`,
  `|---|${ROLE_KEYS.map(() => ':--:').join('|')}|---|`,
];

for (const [category, permissions] of permissionsByCategory()) {
  lines.push(`| **${CATEGORY_LABELS[category]}** |`);

  for (const meta of permissions) {
    const cells = ROLE_KEYS.map((role) => (resolved.get(role)!.has(meta.key) ? '✓' : '·'));

    const notes: string[] = [];
    if (meta.superAdminOnly) notes.push('SA');
    if (meta.breakGlass !== 'none') {
      notes.push(meta.breakGlass === 'second_admin' ? 'BG (second admin)' : 'BG');
    }
    if (meta.pii) notes.push('PII');

    lines.push(`| \`${meta.key}\` | ${cells.join(' | ')} | ${notes.join(' · ')} |`);
  }
}

lines.push('');
lines.push(
  `**Totals:** ${ROLE_KEYS.map((r) => `${ROLES[r].label} ${resolved.get(r)!.size}`).join(' · ')}`,
);
lines.push('');
lines.push(`Catalogue size: ${PERMISSIONS.length} atoms.`);
lines.push('');

const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'PERMISSION_MATRIX.md');
writeFileSync(outPath, lines.join('\n'), 'utf8');

console.log(`  Wrote ${outPath}`);
console.log(`  ${PERMISSIONS.length} permissions × ${ROLE_KEYS.length} roles`);
