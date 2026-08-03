import { useMutation, useQueryClient } from '@tanstack/react-query';
import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { Badge, Button, Spinner } from './components/ui';
import { api } from './lib/api';
import { useAuth } from './lib/auth';
import { AdminsPage } from './pages/Admins';
import { AppealsPage } from './pages/Appeals';
import { AuditPage } from './pages/Audit';
import { CaseDetailPage } from './pages/CaseDetail';
import { ChannelDetailPage } from './pages/ChannelDetail';
import { ChannelsPage } from './pages/Channels';
import { LoginPage } from './pages/Login';
import { QueuePage } from './pages/Queue';
import { SupportPage } from './pages/Support';
import { UserDetailPage } from './pages/UserDetail';
import { UsersPage } from './pages/Users';

/**
 * Shell and routing.
 *
 * Navigation entries are permission-gated, so a Tier 3 moderator scoped to one
 * country simply does not see the admin management or audit sections. That is
 * presentation only — §11's acceptance criterion requires the block to hold "in
 * both the UI and the API", and the API is where it actually holds.
 */

interface NavEntry {
  to: string;
  label: string;
  permission: string;
}

const NAV: NavEntry[] = [
  // Queue first: it is where a moderator spends their shift.
  { to: '/queue', label: 'Queue', permission: 'reports.view' },
  { to: '/users', label: 'Users', permission: 'users.view' },
  { to: '/channels', label: 'Channels', permission: 'channels.view' },
  { to: '/support', label: 'Support', permission: 'support.view' },
  { to: '/appeals', label: 'Appeals', permission: 'reports.view' },
  { to: '/audit', label: 'Audit log', permission: 'audit.view' },
  { to: '/admins', label: 'Admins', permission: 'users.view' },
];

function Shell({ children }: { children: React.ReactNode }) {
  const { me, can, isScoped } = useAuth();
  const queryClient = useQueryClient();

  const logout = useMutation({
    mutationFn: () => api.post('/api/auth/logout'),
    onSuccess: () => {
      queryClient.clear();
      window.location.href = '/login';
    },
  });

  const visible = NAV.filter((entry) => can(entry.permission));

  return (
    <div className="min-h-screen">
      <a href="#main" className="skip-link">
        Skip to content
      </a>

      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
          <span className="text-sm font-semibold">NeverOff Console</span>

          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {visible.map((entry) => (
              <NavLink
                key={entry.to}
                to={entry.to}
                className={({ isActive }) =>
                  'rounded-md px-3 py-1.5 text-sm font-medium ' +
                  (isActive
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800')
                }
              >
                {entry.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3 text-sm">
            {isScoped && (
              // Worth showing prominently: a scoped admin who does not realise
              // they are scoped will read missing records as missing data.
              <Badge tone="warn">
                Scoped to {me?.scope.countries?.join(', ') ?? 'a subset'}
              </Badge>
            )}
            <span className="text-slate-600 dark:text-slate-400">
              {me?.displayName} · {me?.roleLabel}
            </span>
            <Button variant="ghost" onClick={() => logout.mutate()} disabled={logout.isPending}>
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <main id="main" className="mx-auto max-w-7xl px-4 py-6">
        {children}
      </main>
    </div>
  );
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();

  if (loading) return <Spinner label="Checking your session" />;
  if (!me) return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  return <Shell>{children}</Shell>;
}

function Forbidden() {
  return (
    <div className="rounded-lg border border-slate-200 p-8 text-center dark:border-slate-800">
      <h1 className="text-lg font-semibold">Not available to your role</h1>
      <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
        Your role does not include this area. If you need it for a case you are working, ask a
        Platform Manager rather than working around it.
      </p>
    </div>
  );
}

function Guarded({ permission, children }: { permission: string; children: React.ReactNode }) {
  const { can } = useAuth();
  return <>{can(permission) ? children : <Forbidden />}</>;
}

export function App() {
  const { me, loading } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={loading ? <Spinner /> : me ? <Navigate to="/users" replace /> : <LoginPage />}
      />

      <Route
        path="/queue"
        element={
          <RequireAuth>
            <Guarded permission="reports.view">
              <QueuePage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/queue/:id"
        element={
          <RequireAuth>
            <Guarded permission="reports.view">
              <CaseDetailPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/users"
        element={
          <RequireAuth>
            <Guarded permission="users.view">
              <UsersPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/users/:id"
        element={
          <RequireAuth>
            <Guarded permission="users.view">
              <UserDetailPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/channels"
        element={
          <RequireAuth>
            <Guarded permission="channels.view">
              <ChannelsPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/channels/:id"
        element={
          <RequireAuth>
            <Guarded permission="channels.view">
              <ChannelDetailPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/support"
        element={
          <RequireAuth>
            <Guarded permission="support.view">
              <SupportPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/appeals"
        element={
          <RequireAuth>
            <Guarded permission="reports.view">
              <AppealsPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/audit"
        element={
          <RequireAuth>
            <Guarded permission="audit.view">
              <AuditPage />
            </Guarded>
          </RequireAuth>
        }
      />
      <Route
        path="/admins"
        element={
          <RequireAuth>
            <Guarded permission="users.view">
              <AdminsPage />
            </Guarded>
          </RequireAuth>
        }
      />

      <Route path="*" element={<Navigate to="/users" replace />} />
    </Routes>
  );
}
