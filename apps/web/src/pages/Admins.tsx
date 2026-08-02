import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNote,
  Field,
  Input,
  Select,
  Spinner,
  formatDate,
} from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

/**
 * Admin accounts and delegation (§1.3).
 *
 * The role picker only offers roles the signed-in admin can actually assign —
 * the API computes `assignableByYou` by the same rule `canDelegate` enforces on
 * write, so the list cannot drift from what the server will accept.
 */

interface AdminRow {
  id: string;
  email: string;
  displayName: string;
  role: string;
  roleLabel: string;
  rank: number;
  status: string;
  scope: {
    countries: string[] | null;
    languages: string[] | null;
    channelIds: string[] | null;
    reportCategories: string[] | null;
  };
  extraPermissions: string[];
  revokedPermissions: string[];
  effectivePermissionCount: number;
  totpEnrolled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  manageableByYou: boolean;
}

interface RoleRow {
  key: string;
  label: string;
  rank: number;
  maxBanDays: number | null;
  scopable: boolean;
  permissions: string[];
  assignableByYou: boolean;
}

export function AdminsPage() {
  const { can } = useAuth();

  const admins = useQuery<AdminRow[]>({
    queryKey: ['admins'],
    queryFn: () => api.get('/api/admins'),
  });

  const roles = useQuery<RoleRow[]>({
    queryKey: ['roles'],
    queryFn: () => api.get('/api/roles'),
  });

  return (
    <div className="space-y-4">
      {can('admins.create') && roles.data && <CreateAdminForm roles={roles.data} />}

      <ErrorNote error={admins.error} />

      <Card title="Admin accounts">
        {admins.isLoading ? (
          <Spinner label="Loading admins" />
        ) : admins.data?.length === 0 ? (
          <Empty>No admin accounts.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Admin accounts and their roles</caption>
              <thead className="border-b border-slate-200 text-xs uppercase text-slate-600 dark:border-slate-800 dark:text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4">Name</th>
                  <th scope="col" className="py-2 pr-4">Role</th>
                  <th scope="col" className="py-2 pr-4">Scope</th>
                  <th scope="col" className="py-2 pr-4">Permissions</th>
                  <th scope="col" className="py-2 pr-4">2FA</th>
                  <th scope="col" className="py-2 pr-4">Status</th>
                  <th scope="col" className="py-2">Last sign-in</th>
                </tr>
              </thead>
              <tbody>
                {admins.data?.map((admin) => (
                  <tr
                    key={admin.id}
                    className="border-b border-slate-100 last:border-0 dark:border-slate-800"
                  >
                    <td className="py-2 pr-4">
                      <span className="font-medium">{admin.displayName}</span>
                      <span className="block text-xs text-slate-600 dark:text-slate-400">
                        {admin.email}
                      </span>
                    </td>
                    <td className="py-2 pr-4">{admin.roleLabel}</td>
                    <td className="py-2 pr-4">
                      {admin.scope.countries ? (
                        <Badge tone="warn">{admin.scope.countries.join(', ')}</Badge>
                      ) : (
                        <span className="text-slate-600 dark:text-slate-400">Global</span>
                      )}
                    </td>
                    <td className="py-2 pr-4">{admin.effectivePermissionCount}</td>
                    <td className="py-2 pr-4">
                      {admin.totpEnrolled ? (
                        <Badge>Enrolled</Badge>
                      ) : (
                        <Badge tone="warn">Not enrolled</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-4">{admin.status}</td>
                    <td className="py-2">{formatDate(admin.lastLoginAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function CreateAdminForm({ roles }: { roles: RoleRow[] }) {
  const queryClient = useQueryClient();
  const assignable = roles.filter((r) => r.assignableByYou);

  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [role, setRole] = useState(assignable[0]?.key ?? '');
  const [countries, setCountries] = useState('');
  const [created, setCreated] = useState<{ email: string; setupPassword: string; notice: string } | null>(
    null,
  );

  const create = useMutation({
    mutationFn: () =>
      api.post<{ id: string; email: string; setupPassword: string; notice: string }>(
        '/api/admins',
        {
          email,
          displayName,
          role,
          scope: {
            countries: countries.trim()
              ? countries.split(',').map((c) => c.trim().toUpperCase())
              : null,
            languages: null,
            channelIds: null,
            reportCategories: null,
          },
        },
      ),
    onSuccess: (data) => {
      setCreated(data);
      setEmail('');
      setDisplayName('');
      setCountries('');
      queryClient.invalidateQueries({ queryKey: ['admins'] });
    },
  });

  if (assignable.length === 0) {
    return (
      <Card title="Create an admin">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          There is no role you can assign. You can only create admins of strictly lower rank whose
          permissions you hold yourself.
        </p>
      </Card>
    );
  }

  if (created) {
    return (
      <Card title="Admin created">
        <p className="text-sm">
          Setup password for <strong>{created.email}</strong>:
        </p>
        <p className="my-3 rounded bg-slate-100 px-3 py-2 font-mono text-sm dark:bg-slate-800">
          {created.setupPassword}
        </p>
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-400">{created.notice}</p>
        <Button onClick={() => setCreated(null)}>Create another</Button>
      </Card>
    );
  }

  const selected = roles.find((r) => r.key === role);

  return (
    <Card
      title="Create an admin"
      description="You cannot grant a permission you do not hold, or a scope broader than your own."
    >
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <Field label="Email" htmlFor="new-email">
          <Input
            id="new-email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>

        <Field label="Display name" htmlFor="new-name">
          <Input
            id="new-name"
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>

        <Field
          label="Role"
          htmlFor="new-role"
          hint={
            selected
              ? `${selected.permissions.length} permissions · ` +
                (selected.maxBanDays === null
                  ? 'no ban limit'
                  : selected.maxBanDays === 0
                    ? 'cannot ban'
                    : `bans up to ${selected.maxBanDays} days`)
              : undefined
          }
        >
          <Select id="new-role" value={role} onChange={(e) => setRole(e.target.value)}>
            {assignable.map((r) => (
              <option key={r.key} value={r.key}>
                {r.label}
              </option>
            ))}
          </Select>
        </Field>

        <Field
          label="Scope to countries"
          htmlFor="new-scope"
          hint={
            selected?.scopable
              ? 'Comma-separated ISO codes, e.g. DE, AT. Leave blank for global.'
              : 'This role cannot be scoped.'
          }
        >
          <Input
            id="new-scope"
            disabled={!selected?.scopable}
            value={countries}
            onChange={(e) => setCountries(e.target.value)}
            placeholder="DE, AT"
          />
        </Field>

        <div className="sm:col-span-2">
          <ErrorNote error={create.error} />
        </div>

        <div className="sm:col-span-2">
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create admin'}
          </Button>
        </div>
      </form>
    </Card>
  );
}
