import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
import Dashboard from './Dashboard';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';

const stats = { total_repos: 3, active_repos: 2, vulnerable_deps: 4, total_vulns: 9 };

describe('Dashboard', () => {
  it('shows real stats with accurate labels and recent repositories', async () => {
    const { calls } = mockFetch({
      'GET /dashboard/stats': { body: { data: stats } },
      'GET /repositories': { body: { data: { data: [{ id: 'r1', name: 'newest', url: 'u', provider: 'github', is_active: true }], total: 1, page: 1, per_page: 5, total_pages: 1 } } },
    });
    renderWithProviders(<Dashboard />);
    expect(await screen.findByText('Active Repos')).toBeInTheDocument();
    expect(screen.queryByText('Active Scans')).not.toBeInTheDocument();
    expect(screen.queryByText('Scan Interval')).not.toBeInTheDocument();
    expect(screen.getByText('9')).toBeInTheDocument();
    expect(await screen.findByText('newest')).toBeInTheDocument();
    expect(calls.find((c) => c.path.startsWith('/repositories')).path).toContain('sort=recent');
  });

  it('shows an error instead of zeros when stats fail', async () => {
    mockFetch({
      'GET /dashboard/stats': { status: 500, body: { error: 'internal server error (request id: x)' } },
      'GET /repositories': { body: { data: { data: [], total: 0, page: 1, per_page: 5, total_pages: 1 } } },
    });
    renderWithProviders(<Dashboard />);
    expect(await screen.findByRole('alert')).toHaveTextContent('internal server error');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('warns when repositories have no successful vulnerability check', async () => {
    mockFetch({
      'GET /dashboard/stats': { body: { data: { ...stats, unverified_repos: 2 } } },
      'GET /repositories': { body: { data: { data: [], total: 0, page: 1, per_page: 5, total_pages: 1 } } },
    });
    renderWithProviders(<Dashboard />);
    expect(await screen.findByRole('alert')).toHaveTextContent('2 repositories have no successful vulnerability check yet');
  });

  it('shows no warning when every repository was verified', async () => {
    mockFetch({
      'GET /dashboard/stats': { body: { data: { ...stats, unverified_repos: 0 } } },
      'GET /repositories': { body: { data: { data: [], total: 0, page: 1, per_page: 5, total_pages: 1 } } },
    });
    renderWithProviders(<Dashboard />);
    await screen.findByText('Active Repos');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows how many findings are malicious packages', async () => {
    mockFetch({
      'GET /dashboard/stats': { body: { data: { ...stats, malicious_vulns: 2 } } },
      'GET /repositories': { body: { data: { data: [], total: 0, page: 1, per_page: 5, total_pages: 1 } } },
    });
    renderWithProviders(<Dashboard />);
    expect(await screen.findByText('2 malicious')).toBeInTheDocument();
  });
});
