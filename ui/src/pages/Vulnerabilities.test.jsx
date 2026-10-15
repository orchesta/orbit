import { describe, it, expect } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Vulnerabilities from './Vulnerabilities';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';

const finding = (over = {}) => ({
  id: 'v1', osv_id: 'GHSA-1', aliases: ['CVE-1'], summary: 'Prototype pollution', severity: 'high',
  fixed_version: '4.17.21', published_at: '2026-01-01T00:00:00Z', package_name: 'lodash',
  current_version: '4.17.0', ecosystem: 'npm', repository_id: 'r1', repository_name: 'web', ...over,
});
const page = (over = {}) => ({
  data: [], total: 0, page: 1, per_page: 25, total_pages: 1,
  counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, unverified_repositories: 0, ...over,
});

describe('Vulnerabilities', () => {
  it('lists findings from the server with package and repository', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ data: [finding()], total: 1, counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 } }) } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByText('Prototype pollution')).toBeInTheDocument();
    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'web' })).toHaveAttribute('href', '/repositories/r1');
  });

  it('counts unknown severity separately', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 7 } }) } } });
    renderWithProviders(<Vulnerabilities />);
    // Stat cards are labelled "<title>: <count>"; filter chips are labelled by severity alone.
    expect(await screen.findByRole('button', { name: 'Unknown: 7' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unknown' })).toBeInTheDocument();
  });

  it('shows an error instead of an empty state', async () => {
    mockFetch({ 'GET /vulnerabilities': { status: 500, body: { error: 'internal server error' } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByRole('alert')).toHaveTextContent('internal server error');
    expect(screen.queryByText(/Great job/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('warns about unverified repositories and never says great job then', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ unverified_repositories: 2 }) } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByText(/2 repositories have no successful vulnerability check/)).toBeInTheDocument();
    expect(screen.queryByText(/Great job/)).not.toBeInTheDocument();
  });

  it('filters by severity on the server', async () => {
    const { calls } = mockFetch({ 'GET /vulnerabilities': ({ path }) => ({ body: { data: page({ data: path.includes('severity=critical') ? [finding({ id: 'c', severity: 'critical', summary: 'RCE' })] : [] }) } }) });
    renderWithProviders(<Vulnerabilities />, { route: '/vulnerabilities', path: '/vulnerabilities' });
    await userEvent.click(await screen.findByRole('button', { name: 'Critical' }));
    expect(await screen.findByText('RCE')).toBeInTheDocument();
    expect(calls.at(-1).path).toContain('severity=critical');
  });

  it('moves back to the last page when the URL points past it', async () => {
    // Match the page param exactly: 'per_page=25' also contains 'page=3'.
    mockFetch({
      'GET /vulnerabilities': ({ path }) => ({
        body: { data: /[?&]page=3(&|$)/.test(path)
          ? page({ page: 3, total: 1, counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 } })
          : page({ data: [finding()], total: 1, counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 } }) },
      }),
    });
    renderWithProviders(<Vulnerabilities />, { route: '/vulnerabilities?page=3', path: '/vulnerabilities' });
    expect(await screen.findByText('Prototype pollution')).toBeInTheDocument();
    expect(screen.queryByText(/Great job/)).not.toBeInTheDocument();
  });

  it('says a severity filter has no rows instead of great job', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ counts: { critical: 0, high: 3, medium: 0, low: 0, unknown: 0 } }) } } });
    renderWithProviders(<Vulnerabilities />, { route: '/vulnerabilities?severity=critical', path: '/vulnerabilities' });
    expect(await screen.findByText('No Critical vulnerabilities in the latest scans.')).toBeInTheDocument();
    expect(screen.queryByText(/Great job/)).not.toBeInTheDocument();
    expect(screen.queryByText('No vulnerabilities found')).not.toBeInTheDocument();
  });

  it('marks malicious packages and warns about them', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({
      data: [
        finding({ id: 'm', osv_id: 'MAL-2025-46969', aliases: ['GHSA-2v46-p5h4-248w'], summary: 'Malicious code in chalk (npm)',
          severity: 'critical', fixed_version: null, package_name: 'chalk', current_version: '5.6.1', malicious: true }),
        finding({ malicious: false }),
      ],
      total: 2,
      counts: { critical: 1, high: 1, medium: 0, low: 0, unknown: 0, malicious: 1 },
    }) } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByText('Malicious code in chalk (npm)')).toBeInTheDocument();
    expect(screen.getAllByText('Malicious')).toHaveLength(1);
    expect(screen.getByRole('alert')).toHaveTextContent('1 finding is a known malicious package. Remove it and treat machines that installed it as compromised.');
  });

  it('pluralises the malicious warning for several findings', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({
      data: [finding({ malicious: true }), finding({ id: 'v2', malicious: true })],
      total: 2,
      counts: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0, malicious: 2 },
    }) } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByRole('alert')).toHaveTextContent('2 findings are known malicious packages. Remove them and treat machines that installed them as compromised.');
  });

  it('shows no malicious warning when the server reports none', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ data: [finding()], total: 1, counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0, malicious: 0 } }) } } });
    renderWithProviders(<Vulnerabilities />);
    await screen.findByText('Prototype pollution');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText('Malicious')).not.toBeInTheDocument();
  });

  it('shows the KEV badge and the EPSS score of a finding', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ data: [finding({ kev: true, kev_date_added: '2025-01-23T00:00:00Z', epss: 0.84887, epss_percentile: 0.9971 })], total: 1 }) } } });
    renderWithProviders(<Vulnerabilities />);
    expect(await screen.findByText('KEV')).toHaveAttribute('title', expect.stringContaining('Known Exploited Vulnerabilities'));
    expect(screen.getByText('84.9%')).toBeInTheDocument();
  });

  it('filters known exploited findings, sets a minimum EPSS and sorts by EPSS on the server', async () => {
    const { calls } = mockFetch({ 'GET /vulnerabilities': { body: { data: page({ counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0, kev: 1 } }) } } });
    renderWithProviders(<Vulnerabilities />, { route: '/vulnerabilities', path: '/vulnerabilities' });
    await userEvent.click(await screen.findByRole('button', { name: 'Known exploited (1)' }));
    await waitFor(() => expect(calls.at(-1).path).toContain('kev=true'));
    await userEvent.selectOptions(screen.getByLabelText('Sort by'), 'epss');
    await waitFor(() => expect(calls.at(-1).path).toContain('sort=epss'));
    await userEvent.selectOptions(screen.getByLabelText('Minimum EPSS'), '0.1');
    await waitFor(() => expect(calls.at(-1).path).toMatch(/min_epss=0\.1(&|$)/));
    expect(calls.at(-1).path).toContain('kev=true');
  });

  it('says when no finding matches the exploit filters', async () => {
    mockFetch({ 'GET /vulnerabilities': { body: { data: page({ counts: { critical: 0, high: 2, medium: 0, low: 0, unknown: 0, kev: 0 } }) } } });
    renderWithProviders(<Vulnerabilities />, { route: '/vulnerabilities?kev=true', path: '/vulnerabilities' });
    expect(await screen.findByText('No findings match the exploit filters.')).toBeInTheDocument();
    expect(screen.queryByText(/Great job/)).not.toBeInTheDocument();
  });
});
