import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { createContext, useContext, useMemo, type ReactNode } from 'react';

import { ApiError, api, type Me } from './api';

/**
 * Session context and permission helpers.
 *
 * `can()` shapes the UI — hiding a button an admin cannot use is kinder than
 * showing it and returning 403. It is explicitly NOT a security boundary: every
 * endpoint re-checks server-side, and the exhaustive permission tests in
 * packages/shared cover the real decisions. If this file disagreed with the
 * server, the server would win and the user would see an error, which is the
 * correct failure direction.
 */

interface AuthValue {
  me: Me | null;
  loading: boolean;
  error: Error | null;
  can: (permission: string) => boolean;
  canAny: (...permissions: string[]) => boolean;
  isScoped: boolean;
  refetch: UseQueryResult<Me>['refetch'];
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const query = useQuery<Me>({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('/api/auth/me'),
    // A 401 means "not signed in", which is an answer, not a failure worth
    // retrying three times while the login page waits.
    retry: (failureCount, error) =>
      !(error instanceof ApiError && (error.status === 401 || error.status === 403)) &&
      failureCount < 2,
    staleTime: 60_000,
  });

  const value = useMemo<AuthValue>(() => {
    const permissions = new Set(query.data?.permissions ?? []);
    const scope = query.data?.scope;

    return {
      me: query.data ?? null,
      loading: query.isLoading,
      error: query.error instanceof Error ? query.error : null,
      can: (permission: string) => permissions.has(permission),
      canAny: (...list: string[]) => list.some((p) => permissions.has(p)),
      isScoped: Boolean(
        scope &&
          (scope.countries !== null ||
            scope.languages !== null ||
            scope.channelIds !== null ||
            scope.reportCategories !== null),
      ),
      refetch: query.refetch,
    };
  }, [query.data, query.isLoading, query.error, query.refetch]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside AuthProvider.');
  return context;
}

/** Renders children only when the permission is held. */
export function Gated({
  permission,
  fallback = null,
  children,
}: {
  permission: string;
  fallback?: ReactNode;
  children: ReactNode;
}) {
  const { can } = useAuth();
  return <>{can(permission) ? children : fallback}</>;
}
