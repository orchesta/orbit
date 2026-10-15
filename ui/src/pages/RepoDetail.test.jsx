import { describe, it, expect } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RepoDetail from './RepoDetail';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';

const repo = { id: 'r1', name: 'web', url: 'https://github.com/o/web', provider: 'github', is_active: true };
const at = { route: '/repositories/r1', path: '/repositories/:id' };

describe('RepoDetail', () => {
  it('says not found only for 404', async () => {
    mockFetch({ 'GET /repositories/r1': { status: 404, body: { error: 'repository not found' } }, 'GET /repositories/r1/scans': { body: { data: [] } } });
    renderWithProviders(<RepoDetail />, at);
    expect(await screen.findByText('Repository not found.')).toBeInTheDocument();
  });

  it('shows a server error as an error, not as not-found', async () => {
    mockFetch({ 'GET /repositories/r1': { status: 500, body: { error: 'internal server error' } }, 'GET /repositories/r1/scans': { body: { data: [] } } });
    renderWithProviders(<RepoDetail />, at);
    expect(await screen.findByRole('alert')).toHaveTextContent('internal server error');
    expect(screen.queryByText('Repository not found.')).not.toBeInTheDocument();
  });

  it('shows dashes, not zeros, before the first completed scan', async () => {
    mockFetch({ 'GET /repositories/r1': { body: { data: repo } }, 'GET /repositories/r1/scans': { body: { data: [{ id: 's1', status: 'failed', error: 'clone failed' }] } } });
    renderWithProviders(<RepoDetail />, at);
    expect(await screen.findByText(/Latest scan failed/)).toBeInTheDocument();
    expect(screen.getByTestId('stat-total-dependencies')).toHaveTextContent('—');
    expect(screen.getByTestId('stat-vulnerable-packs')).toHaveTextContent('—');
  });

  it('tracks its scan until it finishes', async () => {
    let status = 'running';
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [] } },
      'POST /repositories/r1/scan': { status: 202, body: { data: { scan_id: 's9', status: 'pending', queued: true } } },
      'GET /scans/s9': () => ({ body: { data: { id: 's9', status } } }),
    });
    renderWithProviders(<RepoDetail />, at);
    const button = await screen.findByRole('button', { name: 'Scan Now' });
    await userEvent.click(button);
    await waitFor(() => expect(screen.getByRole('button', { name: /Scanning/ })).toBeDisabled());
    status = 'completed';
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan Now' })).toBeEnabled(), { timeout: 5000 });
  });

  const done = { id: 's1', status: 'completed', total_deps: 3, outdated_deps: 1, vulnerable_deps: 1, total_vulns: 1, duration: 1e9, started_at: '2026-01-01T00:00:00Z' };

  it('shows an error, not an empty list, when vulnerabilities fail to load', async () => {
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [done] } },
      'GET /scans/s1/dependencies': { body: { data: [] } },
      'GET /scans/s1/vulnerabilities': { status: 500, body: { error: 'vuln store down' } },
    });
    renderWithProviders(<RepoDetail />, at);
    await userEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('vuln store down');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Vulnerabilities (—)' })).toBeInTheDocument();
  });

  it('shows a loading state, not an empty table, while dependencies load', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [done] } },
      'GET /scans/s1/dependencies': () => gate.then(() => ({ body: { data: [] } })),
      'GET /scans/s1/vulnerabilities': { body: { data: [] } },
    });
    renderWithProviders(<RepoDetail />, at);
    expect(await screen.findByRole('button', { name: 'Dependencies (…)' })).toBeInTheDocument();
    expect(screen.queryByText('No dependencies found')).not.toBeInTheDocument();
    release();
    expect(await screen.findByText('No dependencies found')).toBeInTheDocument();
  });

  it('shows a scan that is already running on the server and follows it to the end', async () => {
    let scans = [{ id: 's1', status: 'running' }];
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': () => ({ body: { data: scans } }),
      'GET /scans/s1/dependencies': { body: { data: [] } },
      'GET /scans/s1/vulnerabilities': { body: { data: [] } },
    });
    renderWithProviders(<RepoDetail />, at);
    expect(await screen.findByRole('button', { name: /Scanning/ })).toBeDisabled();
    scans = [{ ...done, id: 's1' }];
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan Now' })).toBeEnabled(), { timeout: 5000 });
  });

  it('shows the new scan in the history as soon as it is queued', async () => {
    let queued = false;
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': () => ({ body: { data: queued ? [{ id: 's9', status: 'pending', started_at: '2026-10-14T10:00:00Z' }] : [] } }),
      'POST /repositories/r1/scan': () => { queued = true; return { status: 202, body: { data: { scan_id: 's9', status: 'pending', queued: true } } }; },
      'GET /scans/s9': { body: { data: { id: 's9', status: 'pending' } } },
    });
    renderWithProviders(<RepoDetail />, at);
    await userEvent.click(await screen.findByRole('button', { name: 'Scan Now' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Scan History (1)' }));
    expect(screen.getByText('pending')).toBeInTheDocument();
  });

  it('refreshes the scan history after a tracked scan completes', async () => {
    let status = 'running';
    const { calls } = mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [] } },
      'POST /repositories/r1/scan': { status: 202, body: { data: { scan_id: 's9', status: 'pending', queued: true } } },
      'GET /scans/s9': () => ({ body: { data: { id: 's9', status } } }),
    });
    renderWithProviders(<RepoDetail />, at);
    await userEvent.click(await screen.findByRole('button', { name: 'Scan Now' }));
    await waitFor(() => expect(screen.getByRole('button', { name: /Scanning/ })).toBeDisabled());
    const before = calls.filter((c) => c.path === '/repositories/r1/scans').length;
    status = 'completed';
    await waitFor(() => expect(calls.filter((c) => c.path === '/repositories/r1/scans').length).toBeGreaterThan(before), { timeout: 5000 });
  });
  describe('dependency table', () => {
    const depsFixture = [
      { id: 'd1', name: 'express', ecosystem: 'npm', current_version: '^4.0.0', is_direct: true, is_resolved: false, is_dev: false },
      { id: 'd2', name: 'jest', ecosystem: 'npm', current_version: '29.0.0', is_direct: true, is_resolved: true, is_dev: true },
      { id: 'd3', name: 'qs', ecosystem: 'npm', current_version: '6.11.0', is_direct: false, is_resolved: true, is_dev: false },
      { id: 'd4', name: 'github.com/go-chi/chi/v5', ecosystem: 'Go', current_version: 'v5.4.0', is_direct: true, is_resolved: false, is_dev: false },
    ];
    const setup = () => {
      mockFetch({
        'GET /repositories/r1': { body: { data: repo } },
        'GET /repositories/r1/scans': { body: { data: [done] } },
        'GET /scans/s1/dependencies': { body: { data: depsFixture } },
        'GET /scans/s1/vulnerabilities': { body: { data: [] } },
      });
      renderWithProviders(<RepoDetail />, at);
    };

    it('marks approximate versions and dev dependencies', async () => {
      setup();
      const row = (name) => screen.getByText(name).closest('tr');
      await screen.findByText('express');
      expect(within(row('express')).getByText('approximate version').parentElement).toHaveAttribute('title', 'Version taken from a manifest range; add a lockfile for exact results');
      expect(within(row('express')).queryByText('dev')).not.toBeInTheDocument();
      expect(within(row('jest')).getByText('dev')).toBeInTheDocument();
      expect(within(row('jest')).queryByText('approximate version')).not.toBeInTheDocument();
      expect(within(row('qs')).queryByText('approximate version')).not.toBeInTheDocument();
      // go.mod has no lockfile to add: its versions are minimums.
      expect(within(row('github.com/go-chi/chi/v5')).getByText('approximate version').parentElement).toHaveAttribute('title', 'Version from go.mod (minimum version selection)');
    });

    it('filters direct and transitive dependencies', async () => {
      setup();
      await screen.findByText('qs');
      await userEvent.selectOptions(screen.getByLabelText('Dependency type'), 'direct');
      expect(screen.getByText('express')).toBeInTheDocument();
      expect(screen.queryByText('qs')).not.toBeInTheDocument();
      await userEvent.selectOptions(screen.getByLabelText('Dependency type'), 'transitive');
      expect(screen.getByText('qs')).toBeInTheDocument();
      expect(screen.queryByText('express')).not.toBeInTheDocument();
      await userEvent.selectOptions(screen.getByLabelText('Dependency type'), 'all');
      expect(screen.getByText('express')).toBeInTheDocument();
      expect(screen.getByText('qs')).toBeInTheDocument();
    });

    it('shows an empty message when the filter matches nothing, keeping the tab count', async () => {
      mockFetch({
        'GET /repositories/r1': { body: { data: repo } },
        'GET /repositories/r1/scans': { body: { data: [done] } },
        'GET /scans/s1/dependencies': { body: { data: depsFixture.filter((d) => d.is_direct) } },
        'GET /scans/s1/vulnerabilities': { body: { data: [] } },
      });
      renderWithProviders(<RepoDetail />, at);
      await screen.findByText('express');
      await userEvent.selectOptions(screen.getByLabelText('Dependency type'), 'transitive');
      expect(screen.getByText('No transitive dependencies')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Dependencies (3)' })).toBeInTheDocument();
    });
  });
});
