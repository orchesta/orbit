import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from '../context/AuthContext';
import { ProtectedRoute, AuthRoute, SetupRoute } from './RouteGuards';
import Login from '../pages/Login';
import { mockFetch } from '../test/fetch';

function renderApp(route) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<AuthRoute>login page</AuthRoute>} />
            <Route path="/setup" element={<SetupRoute>setup page</SetupRoute>} />
            <Route path="/" element={<ProtectedRoute>the app</ProtectedRoute>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('route guards during an outage', () => {
  beforeEach(() => localStorage.clear());

  it.each(['/', '/login', '/setup'])('shows "Orbit is unavailable" with Retry at %s, not a redirect', async (route) => {
    mockFetch({ 'GET /auth/status': { status: 500, body: { error: 'boom' } } });
    renderApp(route);
    expect(await screen.findByText('Orbit is unavailable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.queryByText('login page')).not.toBeInTheDocument();
    expect(screen.queryByText('setup page')).not.toBeInTheDocument();
  });

  it('shows the outage when me fails with a 503 and keeps the token', async () => {
    localStorage.setItem('orbit_token', 't1');
    mockFetch({
      'GET /auth/status': { body: { data: { setup_completed: true } } },
      'GET /auth/me': { status: 503, body: { error: 'service unavailable' } },
    });
    renderApp('/');
    expect(await screen.findByText('Orbit is unavailable')).toBeInTheDocument();
    expect(localStorage.getItem('orbit_token')).toBe('t1');
  });

  it('Retry shows the app once the server recovers', async () => {
    localStorage.setItem('orbit_token', 't1');
    let up = false;
    mockFetch({
      'GET /auth/status': () => (up ? { body: { data: { setup_completed: true } } } : { status: 500, body: { error: 'boom' } }),
      'GET /auth/me': { body: { data: { id: 'u1' } } },
    });
    renderApp('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Orbit is unavailable')).toBeInTheDocument();
    up = true;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(screen.getByText('the app')).toBeInTheDocument());
    expect(screen.queryByText('Orbit is unavailable')).not.toBeInTheDocument();
  });
});

describe('login with wrong credentials', () => {
  beforeEach(() => localStorage.clear());

  it('shows the server message and stays on the login page, not the outage screen', async () => {
    mockFetch({
      'GET /auth/status': { body: { data: { setup_completed: true } } },
      'POST /auth/login': { status: 401, body: { error: 'invalid email or password' } },
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/login']}>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<AuthRoute><Login /></AuthRoute>} />
              <Route path="/" element={<ProtectedRoute>the app</ProtectedRoute>} />
            </Routes>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await userEvent.type(await screen.findByPlaceholderText('admin@orbit.io'), 'a@b.co');
    await userEvent.type(screen.getByPlaceholderText('••••••••'), 'wrong-password');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText('invalid email or password')).toBeInTheDocument();
    expect(screen.getByText('Sign in to your account')).toBeInTheDocument();
    expect(screen.queryByText('Orbit is unavailable')).not.toBeInTheDocument();
    expect(screen.queryByText('the app')).not.toBeInTheDocument();
    expect(localStorage.getItem('orbit_token')).toBeNull();
  });
});
