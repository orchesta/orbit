import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
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
});
