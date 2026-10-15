import { describe, it, expect, beforeEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './AuthContext';
import { useAuth } from './auth';
import { mockFetch } from '../test/fetch';
import { UNAUTHORIZED_EVENT } from '../services/api';

function wrapperFor(client) {
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={client}>
        <AuthProvider>{children}</AuthProvider>
      </QueryClientProvider>
    );
  };
}

const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function wrapper({ children }) {
  const client = newClient();
  return (
    <QueryClientProvider client={client}>
      <AuthProvider>{children}</AuthProvider>
    </QueryClientProvider>
  );
}

const completed = { 'GET /auth/status': { body: { data: { setup_completed: true } } } };

describe('AuthProvider', () => {
  beforeEach(() => localStorage.clear());

  it('reports setupRequired when setup is not completed', async () => {
    mockFetch({ 'GET /auth/status': { body: { data: { setup_completed: false, setup_token_required: true } } } });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.setupRequired).toBe(true);
    expect(result.current.setupTokenRequired).toBe(true);
    expect(result.current.user).toBeNull();
  });

  it('logs out and clears the token when me returns 401', async () => {
    localStorage.setItem('orbit_token', 'stale');
    mockFetch({ ...completed, 'GET /auth/me': { status: 401, body: { error: 'unauthorized' } } });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    await waitFor(() => expect(result.current.token).toBeNull());
    expect(result.current.user).toBeNull();
    expect(localStorage.getItem('orbit_token')).toBeNull();
  });

  it('sets the user after a successful login', async () => {
    mockFetch({
      ...completed,
      'POST /auth/login': { body: { data: { token: 't1', user: { id: 'u1', email: 'a@b.c' } } } },
    });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.user).toBeNull();
    await act(async () => {
      await result.current.login('a@b.c', 'pw');
    });
    expect(result.current.user).toEqual({ id: 'u1', email: 'a@b.c' });
    expect(result.current.token).toBe('t1');
    expect(localStorage.getItem('orbit_token')).toBe('t1');
  });

  it('drops cached data of the previous user on logout and on a 401', async () => {
    localStorage.setItem('orbit_token', 't1');
    mockFetch({ ...completed, 'GET /auth/me': { body: { data: { id: 'u1' } } } });
    const client = newClient();
    const { result } = renderHook(() => useAuth(), { wrapper: wrapperFor(client) });
    await waitFor(() => expect(result.current.user).toEqual({ id: 'u1' }));

    client.setQueryData(['repositories', { page: 1 }], { data: [{ id: 'secret' }] });
    act(() => result.current.logout());
    expect(client.getQueryData(['repositories', { page: 1 }])).toBeUndefined();
    expect(client.getQueryData(['auth', 'status'])).toEqual({ setup_completed: true });

    client.setQueryData(['vulnerabilities', { page: 1 }], { data: [] });
    act(() => window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)));
    expect(client.getQueryData(['vulnerabilities', { page: 1 }])).toBeUndefined();
  });

  it('exposes authError instead of a logged-out state when the status check fails', async () => {
    localStorage.setItem('orbit_token', 't1');
    mockFetch({ 'GET /auth/status': { status: 500, body: { error: 'boom' } } });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.authError).not.toBeNull());
    expect(result.current.authError.status).toBe(500);
    expect(result.current.loading).toBe(false);
    expect(result.current.user).toBeNull();
    expect(localStorage.getItem('orbit_token')).toBe('t1');
  });

  it('keeps the token and sets authError when me fails with a 5xx', async () => {
    localStorage.setItem('orbit_token', 't1');
    mockFetch({ ...completed, 'GET /auth/me': { status: 503, body: { error: 'service unavailable' } } });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.authError?.status).toBe(503));
    expect(result.current.token).toBe('t1');
    expect(localStorage.getItem('orbit_token')).toBe('t1');
  });

  it('has no authError after a 401 from me', async () => {
    localStorage.setItem('orbit_token', 'stale');
    mockFetch({ ...completed, 'GET /auth/me': { status: 401, body: { error: 'unauthorized' } } });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.token).toBeNull());
    expect(result.current.authError).toBeNull();
  });

  it('retryAuth recovers once the server is back', async () => {
    let up = false;
    mockFetch({
      'GET /auth/status': () => (up ? { body: { data: { setup_completed: false } } } : { status: 500, body: { error: 'boom' } }),
    });
    const { result } = renderHook(() => useAuth(), { wrapper });
    await waitFor(() => expect(result.current.authError).not.toBeNull());
    up = true;
    await act(async () => {
      await result.current.retryAuth();
    });
    await waitFor(() => expect(result.current.authError).toBeNull());
    expect(result.current.setupRequired).toBe(true);
  });
});
