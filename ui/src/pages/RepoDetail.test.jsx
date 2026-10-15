import { describe, it, expect, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RepoDetail from './RepoDetail';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';
import { stubDownload } from '../test/download';

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

  it('marks malicious packages in the vulnerability table', async () => {
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [done] } },
      'GET /scans/s1/dependencies': { body: { data: [{ id: 'd1', name: 'chalk', ecosystem: 'npm', current_version: '5.6.1', is_direct: true, is_resolved: true, is_dev: false }] } },
      'GET /scans/s1/recommendations': { body: { data: [] } },
      'GET /scans/s1/vulnerabilities': { body: { data: [
        { id: 'v1', dependency_id: 'd1', osv_id: 'MAL-2025-46969', summary: 'Malicious code in chalk (npm)', severity: 'critical', malicious: true },
        { id: 'v2', dependency_id: 'd1', osv_id: 'GHSA-xxxx-yyyy-zzzz', summary: 'Prototype pollution', severity: 'high', malicious: false },
      ] } },
    });
    renderWithProviders(<RepoDetail />, at);
    await userEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
    expect(await screen.findByText('Malicious code in chalk (npm)')).toBeInTheDocument();
    expect(screen.getAllByText('Malicious')).toHaveLength(1);
  });

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
  describe('SBOM download', () => {
    it('downloads the last completed scan in the chosen format', async () => {
      const { names } = stubDownload();
      const { calls } = mockFetch({
        'GET /repositories/r1': { body: { data: repo } },
        'GET /repositories/r1/scans': { body: { data: [{ id: 's2', status: 'failed', error: 'clone failed' }, done] } },
        'GET /scans/s1/dependencies': { body: { data: [] } },
        'GET /scans/s1/vulnerabilities': { body: { data: [] } },
        'GET /scans/s1/sbom': { body: {}, headers: { 'Content-Disposition': 'attachment; filename=web-s1.spdx.json' } },
      });
      renderWithProviders(<RepoDetail />, at);
      const group = await screen.findByRole('group', { name: 'Download SBOM' });
      await userEvent.click(within(group).getByRole('button', { name: 'SPDX' }));
      await waitFor(() => expect(names).toEqual(['web-s1.spdx.json']));
      expect(calls.some((c) => c.path === '/scans/s1/sbom?format=spdx')).toBe(true);
    });

    it('is disabled before the first completed scan', async () => {
      mockFetch({ 'GET /repositories/r1': { body: { data: repo } }, 'GET /repositories/r1/scans': { body: { data: [{ id: 's1', status: 'running' }] } } });
      renderWithProviders(<RepoDetail />, at);
      const group = await screen.findByRole('group', { name: 'Download SBOM' });
      expect(within(group).getByRole('button', { name: 'CycloneDX' })).toBeDisabled();
      expect(within(group).getByRole('button', { name: 'SPDX' })).toBeDisabled();
    });

    it('reports a failed download and enables the buttons again', async () => {
      const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
      stubDownload();
      mockFetch({
        'GET /repositories/r1': { body: { data: repo } },
        'GET /repositories/r1/scans': { body: { data: [done] } },
        'GET /scans/s1/dependencies': { body: { data: [] } },
        'GET /scans/s1/vulnerabilities': { body: { data: [] } },
        'GET /scans/s1/sbom': { status: 500, body: { error: 'internal server error' } },
      });
      renderWithProviders(<RepoDetail />, at);
      await userEvent.click(await screen.findByRole('button', { name: 'CycloneDX' }));
      await waitFor(() => expect(alert).toHaveBeenCalledWith('SBOM download failed: internal server error'));
      await waitFor(() => expect(screen.getByRole('button', { name: 'CycloneDX' })).toBeEnabled());
    });
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

  describe('upgrade recommendations', () => {
    const deps = [{ id: 'd1', name: 'lodash', ecosystem: 'npm', current_version: '4.17.15', is_direct: true, is_resolved: true, is_dev: false }];
    const vulns = [{ id: 'v1', dependency_id: 'd1', osv_id: 'CVE-2021-23337', summary: 'Command injection', severity: 'high', fixed_version: '4.17.21' }];
    const recs = [
      { ecosystem: 'npm', package: 'lodash', current: '4.17.15', upgrade: '4.17.21', fixes: ['CVE-2020-8203', 'CVE-2021-23337'], no_fix: [], manifest: 'package-lock.json', via: '', malicious: false },
      { ecosystem: 'npm', package: 'express', current: '4.18.2', upgrade: '', fixes: [], no_fix: ['GHSA-esc-0005'], manifest: 'package-lock.json', via: '', malicious: false },
      { ecosystem: 'npm', package: 'evil-pkg', current: '1.0.0', upgrade: '', fixes: [], no_fix: ['MAL-2025-1234'], manifest: 'package-lock.json', via: '', malicious: true },
      { ecosystem: 'npm', package: 'debug', current: '4.4.2', upgrade: '4.4.3', fixes: ['CVE-2025-59144'], no_fix: [], manifest: 'package-lock.json', via: '', malicious: true },
    ];
    const routes = (recsRoute) => ({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [done] } },
      'GET /scans/s1/dependencies': { body: { data: deps } },
      'GET /scans/s1/vulnerabilities': { body: { data: vulns } },
      'GET /scans/s1/recommendations': recsRoute,
    });

    it('shows the smallest upgrade per package with a caution', async () => {
      mockFetch(routes({ body: { data: recs } }));
      renderWithProviders(<RepoDetail />, at);
      await userEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
      const panel = await screen.findByRole('region', { name: 'Recommended upgrades' });
      const items = within(panel).getAllByRole('listitem');
      expect(items[0]).toHaveTextContent('lodash 4.17.15 → 4.17.21 fixes 2 advisories');
      expect(items[1]).toHaveTextContent('express 4.18.2 — no known fix for GHSA-esc-0005');
      expect(items[2]).toHaveTextContent('evil-pkg 1.0.0 — reported as malicious; remove it');
      expect(items[3]).toHaveTextContent('debug 4.4.2 — reported as malicious; remove it (a non-malicious advisory names 4.4.3 as fixed)');
      expect(items[3]).not.toHaveTextContent('→');
      expect(panel).toHaveTextContent('It can still break your build; check the release notes. Orbit does not check that the version exists or that no other advisory affects it.');
      expect(screen.getByText('Command injection')).toBeInTheDocument();
    });

    it('asks for recommendations only on the vulnerabilities tab', async () => {
      const { calls } = mockFetch(routes({ body: { data: recs } }));
      renderWithProviders(<RepoDetail />, at);
      await screen.findByText('lodash');
      expect(calls.some((c) => c.path === '/scans/s1/recommendations')).toBe(false);
      await userEvent.click(screen.getByRole('button', { name: /^Vulnerabilities/ }));
      expect(await screen.findByRole('region', { name: 'Recommended upgrades' })).toBeInTheDocument();
    });

    it('keeps the vulnerability list when recommendations fail', async () => {
      mockFetch(routes({ status: 500, body: { error: 'boom' } }));
      renderWithProviders(<RepoDetail />, at);
      await userEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
      expect(await screen.findByText('Upgrade recommendations could not be loaded.')).toBeInTheDocument();
      expect(screen.getByText('Command injection')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  it('marks known exploited vulnerabilities of the scan', async () => {
    mockFetch({
      'GET /repositories/r1': { body: { data: repo } },
      'GET /repositories/r1/scans': { body: { data: [done] } },
      'GET /scans/s1/dependencies': { body: { data: [{ id: 'd1', name: 'jquery', current_version: '3.4.1', ecosystem: 'npm' }] } },
      'GET /scans/s1/recommendations': { body: { data: [] } },
      'GET /scans/s1/vulnerabilities': { body: { data: [{ id: 'v1', dependency_id: 'd1', osv_id: 'CVE-2020-11023', summary: 'XSS in jQuery', severity: 'medium', kev: true, kev_date_added: '2025-01-23T00:00:00Z', epss: 0.84887, epss_percentile: 0.9971 }] } },
    });
    renderWithProviders(<RepoDetail />, at);
    await userEvent.click(await screen.findByRole('button', { name: /^Vulnerabilities/ }));
    expect(await screen.findByText('KEV')).toHaveAttribute('title', expect.stringContaining('2025'));
    expect(screen.getByText('84.9%')).toBeInTheDocument();
  });

  describe('licenses', () => {
    const licensed = [
      { id: 'd1', name: 'express', ecosystem: 'npm', current_version: '4.18.2', is_direct: true, is_resolved: true, license: 'MIT' },
      { id: 'd2', name: 'qs', ecosystem: 'npm', current_version: '6.11.0', is_direct: false, is_resolved: true, license: 'BSD-3-Clause' },
      { id: 'd3', name: 'ms', ecosystem: 'npm', current_version: '2.1.3', is_direct: false, is_resolved: true, license: 'MIT' },
      { id: 'd4', name: 'private', ecosystem: 'npm', current_version: '1.0.0', is_direct: true, is_resolved: true, license: '' },
    ];
    const setup = (data) => {
      mockFetch({
        'GET /repositories/r1': { body: { data: repo } },
        'GET /repositories/r1/scans': { body: { data: [done] } },
        'GET /scans/s1/dependencies': { body: { data } },
        'GET /scans/s1/vulnerabilities': { body: { data: [] } },
      });
      renderWithProviders(<RepoDetail />, at);
    };

    it('shows a license column and a breakdown', async () => {
      setup(licensed);
      await screen.findByText('express');
      const row = (name) => screen.getByText(name).closest('tr');
      expect(within(row('express')).getByTestId('dep-license')).toHaveTextContent('MIT');
      expect(within(row('private')).getByTestId('dep-license')).toHaveTextContent('-');
      const breakdown = screen.getByRole('region', { name: 'License breakdown' });
      const items = within(breakdown).getAllByRole('listitem').map((li) => li.textContent);
      expect(items).toEqual(['MIT2', 'BSD-3-Clause1', 'Unknown1']);
    });

    it('hides the breakdown when no license is known', async () => {
      setup([{ id: 'd1', name: 'express', ecosystem: 'npm', current_version: '4.18.2', is_direct: true, is_resolved: true }]);
      await screen.findByText('express');
      expect(screen.queryByRole('region', { name: 'License breakdown' })).not.toBeInTheDocument();
      expect(screen.getByTestId('dep-license')).toHaveTextContent('-');
    });

    it('sums licenses beyond the first eight into Other', async () => {
      const many = Array.from({ length: 10 }, (_, i) => ({
        id: `d${i}`, name: `pkg${i}`, ecosystem: 'npm', current_version: '1.0.0', is_direct: true, is_resolved: true, license: `LicenseRef-L${i}`,
      }));
      setup(many);
      await screen.findByText('pkg0');
      const items = within(screen.getByRole('region', { name: 'License breakdown' })).getAllByRole('listitem');
      expect(items).toHaveLength(9);
      expect(items[8]).toHaveTextContent('Other2');
    });
  });
});
