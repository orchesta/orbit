import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, UNAUTHORIZED_EVENT } from '../services/api';
import { AuthContext } from './auth';

const STATUS_KEY = ['auth', 'status'];
const ME_KEY = ['auth', 'me'];

// clearUserData drops every cached query except auth state, so one user's
// data never shows up for the next.
function clearUserData(queryClient) {
  queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== 'auth' });
}

export function AuthProvider({ children }) {
  const queryClient = useQueryClient();
  const [token, setToken] = useState(() => localStorage.getItem('orbit_token'));

  // Auth state only changes through login/setup/logout, so never refetch on mount.
  const statusQuery = useQuery({ queryKey: STATUS_KEY, queryFn: authApi.status, staleTime: Infinity });
  const setupCompleted = !!statusQuery.data?.setup_completed;

  const meQuery = useQuery({
    queryKey: ME_KEY,
    queryFn: authApi.me,
    enabled: !!token && setupCompleted,
    staleTime: Infinity,
  });

  useEffect(() => {
    function onUnauthorized() {
      // api.js has already removed the stored token.
      setToken(null);
      clearUserData(queryClient);
      queryClient.setQueryData(ME_KEY, null);
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [queryClient]);

  // A failed status check or a non-401 `me` failure (network/5xx) is an outage,
  // not a logout: it is surfaced as authError so guards can show it with a Retry
  // instead of redirecting. A 401 from `me` is handled by the unauthorized event.
  const meError = token && meQuery.error?.status !== 401 ? meQuery.error : null;
  const authError = (statusQuery.data ? null : statusQuery.error) ?? meError ?? null;
  const loading = statusQuery.isPending || (!!token && setupCompleted && meQuery.isPending);
  const setupRequired = !!statusQuery.data && !setupCompleted;
  const setupTokenRequired = !!statusQuery.data?.setup_token_required;
  const user = token ? (meQuery.data ?? null) : null;

  async function retryAuth() {
    if (statusQuery.error || !statusQuery.data) await statusQuery.refetch();
    if (meError) await meQuery.refetch();
  }

  async function login(email, password) {
    const data = await authApi.login(email, password);
    localStorage.setItem('orbit_token', data.token);
    clearUserData(queryClient);
    queryClient.setQueryData(ME_KEY, data.user);
    setToken(data.token);
    return data;
  }

  async function setup(email, password, displayName, setupToken) {
    const data = await authApi.setup({ email, password, display_name: displayName, setup_token: setupToken || undefined });
    localStorage.setItem('orbit_token', data.token);
    queryClient.setQueryData(ME_KEY, data.user);
    queryClient.setQueryData(STATUS_KEY, (old) => ({ ...old, setup_completed: true }));
    setToken(data.token);
    return data;
  }

  function logout() {
    localStorage.removeItem('orbit_token');
    clearUserData(queryClient);
    queryClient.setQueryData(ME_KEY, null);
    setToken(null);
  }

  return (
    <AuthContext.Provider value={{ user, token, loading, authError, retryAuth, setupRequired, setupTokenRequired, login, setup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
