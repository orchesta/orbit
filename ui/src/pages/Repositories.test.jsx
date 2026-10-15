import { describe, it, expect, vi } from 'vitest';
import { screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link } from 'react-router-dom';
import Repositories from './Repositories';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';
import { TOKEN_PLACEHOLDERS } from '../providers';

const repo = (id, name = id) => ({ id, name, url: `https://github.com/o/${name}`, provider: 'github', is_active: true, vulnerable_deps: 0, outdated_deps: 0, total_deps: 0 });
const list = (repos, over = {}) => ({ body: { data: { data: repos, total: repos.length, page: 1, per_page: 25, total_pages: 1, ...over } } });
const route = { route: '/repositories', path: '/repositories' };

const importRoutes = {
  'GET /tokens': { body: { data: [{ id: 't1', provider: 'github', label: 'gh', masked_token: '***' }] } },
  'POST /repositories/github/fetch': { body: { data: ['n1', 'n2'].map((n) => ({ full_name: `o/${n}`, name: n, url: `https://github.com/o/${n}`, default_branch: 'main' })) } },
};

// importAll walks the GitHub import wizard and imports every fetched repository.
async function importAll() {
  await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
  await userEvent.click(screen.getByRole('button', { name: 'Import from GitHub' }));
  const fetchButton = await screen.findByRole('button', { name: 'Fetch Repositories' });
  await waitFor(() => expect(fetchButton).toBeEnabled());
  await userEvent.click(fetchButton);
  await userEvent.click(await screen.findByRole('button', { name: 'Select All' }));
  await userEvent.click(screen.getByRole('button', { name: 'Import Selected (2)' }));
}

describe('Repositories', () => {
  it('keeps the search box when a search has no results', async () => {
    mockFetch({ 'GET /repositories': ({ path }) => (path.includes('q=zzz') ? list([]) : list([repo('a')])) });
    renderWithProviders(<Repositories />, route);
    const search = await screen.findByPlaceholderText('Search repositories...');
    await userEvent.type(search, 'zzz');
    expect(await screen.findByText(/No repositories match/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Search repositories...')).toHaveValue('zzz');
    expect(screen.queryByText('No repositories yet')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByText('a')).toBeInTheDocument();
  });

  it('debounces search and ignores stale responses', async () => {
    let releaseSlow;
    const { calls } = mockFetch({
      'GET /repositories': ({ path }) => {
        // 'q=api' must be checked first: it also contains 'q=ap'.
        if (path.includes('q=api')) return list([repo('fresh')]);
        if (path.includes('q=ap')) return new Promise((r) => { releaseSlow = () => r(list([repo('stale')])); });
        return list([repo('a')]);
      },
    });
    renderWithProviders(<Repositories />, route);
    const search = await screen.findByPlaceholderText('Search repositories...');
    await userEvent.type(search, 'ap');
    await waitFor(() => expect(calls.some((c) => c.path.includes('q=ap'))).toBe(true));
    await userEvent.type(search, 'i');
    expect(await screen.findByText('fresh')).toBeInTheDocument();
    releaseSlow?.();
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText('stale')).not.toBeInTheDocument();
    expect(calls.filter((c) => c.path.includes('q=a&') || c.path.endsWith('q=a')).length).toBe(0); // 'a' alone never fired: debounced
  });

  it('treats a server-side running scan as scanning and re-enables the button once it completes', async () => {
    let polls = 0;
    mockFetch({
      'GET /repositories': () => {
        polls += 1;
        return list([{ ...repo('a'), scan_status: polls === 1 ? 'running' : 'completed' }]);
      },
    });
    renderWithProviders(<Repositories />, route);
    expect(await screen.findByRole('button', { name: 'Scan a' })).toBeDisabled();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan a' })).toBeEnabled(), { timeout: 5000 });
    expect(polls).toBe(2);
    // Polling stops once no row has an active scan: wait past the 2 s interval.
    await new Promise((r) => setTimeout(r, 2600));
    expect(polls).toBe(2);
  }, 15000);

  it('clears selection on page change', async () => {
    // Match the page param exactly: 'per_page=25' also contains 'page=2'.
    mockFetch({ 'GET /repositories': ({ path }) => (/[?&]page=2(&|$)/.test(path) ? list([repo('c')], { page: 2, total: 26, total_pages: 2 }) : list([repo('a'), repo('b')], { total: 26, total_pages: 2 })) });
    renderWithProviders(<Repositories />, route);
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select a' }));
    expect(screen.getByRole('button', { name: 'Delete selected (1)' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Page 2' }));
    expect(await screen.findByText('c')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete selected/ })).not.toBeInTheDocument();
  });

  it('does not let placeholder rows be selected while the next page loads', async () => {
    let releasePage2;
    mockFetch({
      'GET /repositories': ({ path }) => (/[?&]page=2(&|$)/.test(path)
        ? new Promise((r) => { releasePage2 = () => r(list([repo('c')], { page: 2, total: 26, total_pages: 2 })); })
        : list([repo('a'), repo('b')], { total: 26, total_pages: 2 })),
    });
    renderWithProviders(<Repositories />, route);
    await screen.findByRole('checkbox', { name: 'Select a' });
    await userEvent.click(screen.getByRole('button', { name: 'Page 2' }));
    await waitFor(() => expect(releasePage2).toBeDefined());
    // Page 1's rows are still on screen as placeholders; they must not be selectable.
    expect(screen.getByRole('checkbox', { name: 'Select a' })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: 'Select all' })).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select a' }));
    releasePage2();
    expect(await screen.findByText('c')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete selected/ })).not.toBeInTheDocument();
  });

  it('moves back a page when the last repository on the last page is deleted', async () => {
    let deleted = false;
    mockFetch({
      'GET /repositories': ({ path }) => {
        if (/[?&]page=2(&|$)/.test(path)) return deleted ? list([], { page: 2, total: 25, total_pages: 1 }) : list([repo('c')], { page: 2, total: 26, total_pages: 2 });
        return list([repo('a'), repo('b')], { total: deleted ? 25 : 26, total_pages: deleted ? 1 : 2 });
      },
      'DELETE /repositories/c': () => { deleted = true; return { status: 204 }; },
    });
    renderWithProviders(<Repositories />, { route: '/repositories?page=2', path: '/repositories' });
    await screen.findByText('c');
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('a')).toBeInTheDocument();
    expect(screen.queryByText(/No repositories match/)).not.toBeInTheDocument();
  });

  it('resets the search box when the URL search changes from outside', async () => {
    const { calls } = mockFetch({ 'GET /repositories': list([repo('a')]) });
    renderWithProviders(<><Link to="/repositories">All repositories</Link><Repositories /></>, { route: '/repositories?q=foo', path: '/repositories' });
    const search = await screen.findByPlaceholderText('Search repositories...');
    expect(search).toHaveValue('foo');
    await userEvent.type(search, 'x'); // debounce for 'foox' is now pending
    await userEvent.click(screen.getByRole('link', { name: 'All repositories' }));
    expect(screen.getByPlaceholderText('Search repositories...')).toHaveValue('');
    await new Promise((r) => setTimeout(r, 400));
    expect(screen.getByPlaceholderText('Search repositories...')).toHaveValue('');
    expect(calls.some((c) => c.path.includes('q=foox'))).toBe(false);
    expect(calls.at(-1).path).not.toContain('q=');
  });

  it('deletes only the selected repositories and reports failures', async () => {
    const { calls } = mockFetch({
      'GET /repositories': list([repo('a'), repo('b'), repo('c')]),
      'DELETE /repositories/a': { status: 204 },
      'DELETE /repositories/b': { status: 500, body: { error: 'boom' } },
    });
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    renderWithProviders(<Repositories />, route);
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select a' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select b' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete selected (2)' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('2 selected repositories');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(alert).toHaveBeenCalledWith(expect.stringContaining('1 of 2')));
    const deleted = calls.filter((c) => c.method === 'DELETE').map((c) => c.path);
    expect(deleted.sort()).toEqual(['/repositories/a', '/repositories/b']);
    expect(screen.queryByRole('button', { name: /Delete All/ })).not.toBeInTheDocument();
  });

  it('shows scanning until the scan finishes, then refreshes the list', async () => {
    let status = 'running';
    const { calls } = mockFetch({
      'GET /repositories': list([repo('a')]),
      'POST /repositories/a/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      'GET /scans/s1': () => ({ body: { data: { id: 's1', status } } }),
    });
    renderWithProviders(<Repositories />, route);
    await userEvent.click(await screen.findByRole('button', { name: 'Scan a' }));
    expect(screen.getByRole('button', { name: 'Scan a' })).toBeDisabled();
    const listCallsBefore = calls.filter((c) => c.path.startsWith('/repositories?') || c.path === '/repositories').length;
    status = 'completed';
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan a' })).toBeEnabled(), { timeout: 5000 });
    await waitFor(() => expect(calls.filter((c) => c.path.startsWith('/repositories?') || c.path === '/repositories').length).toBeGreaterThan(listCallsBefore));
  });

  it('hides the bulk actions when the list fails to refresh', async () => {
    let deleted = false;
    mockFetch({
      'GET /repositories': () => (deleted ? { status: 500, body: { error: 'internal server error' } } : list([repo('a'), repo('b')])),
      'DELETE /repositories/b': () => { deleted = true; return { status: 204 }; },
    });
    renderWithProviders(<Repositories />, route);
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select a' }));
    expect(screen.getByRole('button', { name: 'Delete selected (1)' })).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole('button', { name: 'Delete' })[1]);
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('internal server error');
    expect(screen.queryByRole('button', { name: /Delete selected/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Scan selected/ })).not.toBeInTheDocument();
  });

  it('starts scans of imported repositories without polling each one', async () => {
    const { calls } = mockFetch({
      'GET /repositories': list([repo('a')]),
      ...importRoutes,
      'POST /repositories/import': { status: 201, body: { data: { created: [{ id: 'n1' }, { id: 'n2' }], skipped: [] } } },
      'POST /repositories/n1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      'POST /repositories/n2/scan': { status: 202, body: { data: { scan_id: 's2', status: 'pending', queued: true } } },
    });
    renderWithProviders(<Repositories />, route);
    await importAll();
    await waitFor(() => expect(calls.filter((c) => /^\/repositories\/n\d\/scan$/.test(c.path)).length).toBe(2));
    await new Promise((r) => setTimeout(r, 50));
    expect(calls.some((c) => c.path.startsWith('/scans/'))).toBe(false);
  });

  it('refreshes the list when an import fails part way', async () => {
    const { calls } = mockFetch({
      'GET /repositories': list([repo('a')]),
      ...importRoutes,
      'POST /repositories/import': { status: 500, body: { error: 'boom' } },
    });
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    renderWithProviders(<Repositories />, route);
    await screen.findByText('a');
    const listCalls = () => calls.filter((c) => c.path.startsWith('/repositories?')).length;
    const before = listCalls();
    await importAll();
    await waitFor(() => expect(alert).toHaveBeenCalledWith('Import error: boom'));
    await waitFor(() => expect(listCalls()).toBeGreaterThan(before));
  });

  it('shows an error instead of the empty state when the list fails', async () => {
    mockFetch({ 'GET /repositories': { status: 500, body: { error: 'internal server error' } } });
    renderWithProviders(<Repositories />, route);
    expect(await screen.findByRole('alert')).toHaveTextContent('internal server error');
    expect(screen.queryByText('No repositories yet')).not.toBeInTheDocument();
  });

  describe('Azure DevOps', () => {
    const host = { id: 'h1', kind: 'azuredevops', name: 'Contoso', base_url: 'https://dev.azure.com/contoso' };
    const azToken = { id: 'ta', provider: 'azuredevops', label: 'az-pat', masked_token: '***', git_host_id: 'h1' };
    const azRepo = { full_name: 'Proj/Repo', name: 'Repo', url: 'https://dev.azure.com/contoso/Proj/_git/Repo', default_branch: 'main' };

    it('imports through the Azure wizard using the Azure endpoints', async () => {
      const { calls } = mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /tokens': { body: { data: [{ id: 't1', provider: 'github', label: 'gh', masked_token: '***' }, azToken] } },
        'GET /git-hosts': { body: { data: [host] } },
        'POST /repositories/azuredevops/fetch': { body: { data: [azRepo] } },
        'POST /repositories/import': { status: 201, body: { data: { created: [{ id: 'n1' }], skipped: [] } } },
        'POST /repositories/n1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Import from Azure DevOps' }));
      expect(await screen.findByText('az-pat')).toBeInTheDocument();
      expect(await screen.findByText('Contoso')).toBeInTheDocument();
      expect(screen.queryByText('gh')).not.toBeInTheDocument();
      const fetchButton = screen.getByRole('button', { name: 'Fetch Repositories' });
      await waitFor(() => expect(fetchButton).toBeEnabled());
      await userEvent.click(fetchButton);
      expect(await screen.findByText('Proj/Repo')).toBeInTheDocument();
      await userEvent.click(screen.getByRole('button', { name: 'Select All' }));
      await userEvent.click(screen.getByRole('button', { name: 'Import Selected (1)' }));
      await waitFor(() => expect(calls.some((c) => c.path === '/repositories/import')).toBe(true));
      const imp = calls.find((c) => c.path === '/repositories/import');
      expect(JSON.parse(imp.body)).toEqual({ token_id: 'ta', provider: 'azuredevops', repositories: [{ name: 'Repo', url: azRepo.url, default_branch: 'main' }] });
      expect(calls.some((c) => c.path === '/repositories/azuredevops/fetch' && JSON.parse(c.body).token_id === 'ta')).toBe(true);
    });

    it('shows the API message when the Azure token is rejected', async () => {
      mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /tokens': { body: { data: [azToken] } },
        'GET /git-hosts': { body: { data: [host] } },
        'POST /repositories/azuredevops/fetch': { status: 400, body: { error: 'Azure DevOps rejected the token' } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Import from Azure DevOps' }));
      const fetchButton = await screen.findByRole('button', { name: 'Fetch Repositories' });
      await waitFor(() => expect(fetchButton).toBeEnabled());
      await userEvent.click(fetchButton);
      expect(await screen.findByText('Azure DevOps rejected the token')).toBeInTheDocument();
    });

    it('requires a connection when adding an Azure repository manually', async () => {
      const { calls } = mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /git-hosts': { body: { data: [host] } },
        'POST /repositories': { status: 201, body: { data: { id: 'z1' } } },
        'POST /repositories/z1/scan': { status: 202, body: { data: { scan_id: 's1', status: 'pending', queued: true } } },
        'GET /scans/s1': { body: { data: { id: 's1', status: 'completed' } } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Add Manually' }));
      expect(screen.queryByLabelText('Connection')).not.toBeInTheDocument();
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
      const conn = await screen.findByLabelText('Connection');
      expect(conn).toBeRequired();
      await userEvent.type(screen.getByLabelText('Name'), 'Repo');
      await userEvent.type(screen.getByLabelText('Repository URL'), 'https://dev.azure.com/contoso/Proj/_git/Repo');
      await userEvent.click(screen.getByRole('button', { name: 'Save Repository' }));
      expect(calls.some((c) => c.method === 'POST' && c.path === '/repositories')).toBe(false);
      expect(screen.getByRole('alert')).toHaveTextContent('Select a connection');

      await userEvent.selectOptions(conn, 'h1');
      expect(screen.getByLabelText('Repository URL')).toHaveAttribute('placeholder', 'https://dev.azure.com/contoso/Project/_git/Repo');
      await userEvent.click(screen.getByRole('button', { name: 'Save Repository' }));
      await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/repositories')).toBe(true));
      const body = JSON.parse(calls.find((c) => c.method === 'POST' && c.path === '/repositories').body);
      expect(body).toMatchObject({ name: 'Repo', provider: 'azuredevops', git_host_id: 'h1' });
    });

    it('shows the chosen provider\'s token placeholder in the manual form', async () => {
      mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /git-hosts': { body: { data: [host] } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Add Manually' }));
      const token = screen.getByLabelText(/Auth Token/);
      expect(token).toHaveAttribute('placeholder', TOKEN_PLACEHOLDERS.github);
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
      expect(token).toHaveAttribute('placeholder', TOKEN_PLACEHOLDERS.azuredevops);
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'gitlab');
      expect(token).toHaveAttribute('placeholder', TOKEN_PLACEHOLDERS.gitlab);
    });

    it('does not send git_host_id for a manual GitHub repository', async () => {
      const { calls } = mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /git-hosts': { body: { data: [host] } },
        'POST /repositories': { status: 201, body: { data: {} } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Add Manually' }));
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'github');
      await userEvent.type(screen.getByLabelText('Name'), 'x');
      await userEvent.type(screen.getByLabelText('Repository URL'), 'https://github.com/o/x');
      await userEvent.click(screen.getByRole('button', { name: 'Save Repository' }));
      await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/repositories')).toBe(true));
      expect(JSON.parse(calls.find((c) => c.method === 'POST').body)).not.toHaveProperty('git_host_id');
    });

    it('shows a load error, not the empty hint, when connections fail to load in the manual modal', async () => {
      let fail = true;
      mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /git-hosts': () => (fail ? { status: 500, body: { error: 'hosts exploded' } } : { body: { data: [host] } }),
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Add Manually' }));
      await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
      expect(await screen.findByText('hosts exploded')).toBeInTheDocument();
      expect(screen.queryByText(/No Azure DevOps connection yet/)).not.toBeInTheDocument();
      fail = false;
      await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
      expect(await screen.findByLabelText('Connection')).toBeInTheDocument();
    });

    it('shows the settings hint when the user has no token for the chosen provider', async () => {
      mockFetch({
        'GET /repositories': list([repo('a')]),
        'GET /tokens': { body: { data: [{ id: 't1', provider: 'github', label: 'gh', masked_token: '***' }] } },
        'GET /git-hosts': { body: { data: [host] } },
      });
      renderWithProviders(<Repositories />, route);
      await userEvent.click(await screen.findByRole('button', { name: 'Import' }));
      await userEvent.click(screen.getByRole('button', { name: 'Import from Azure DevOps' }));
      expect(await screen.findByRole('link', { name: 'Go to Settings' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Fetch Repositories' })).not.toBeInTheDocument();
    });

    it('shows an Azure row with the Azure icon, not GitLab, and offers the filter', async () => {
      mockFetch({
        'GET /repositories': list([{ ...repo('az'), provider: 'azuredevops', url: azRepo.url, git_host_id: 'h1' }, { ...repo('gl'), provider: 'gitlab' }]),
      });
      renderWithProviders(<Repositories />, route);
      const row = (await screen.findByText('az')).closest('tr');
      // Decorative icon next to the visible name.
      expect(row.querySelector('svg[data-provider="azuredevops"]')).toHaveAttribute('aria-hidden', 'true');
      expect(row.querySelector('svg[data-provider="gitlab"]')).toBeNull();
      expect(within(row).getByText('Azure DevOps')).toBeInTheDocument();
      const glRow = screen.getByText('gl').closest('tr');
      expect(glRow.querySelector('svg[data-provider="gitlab"]')).not.toBeNull();
      expect(within(glRow).getByText('GitLab')).toBeInTheDocument();
      expect(screen.getByRole('option', { name: 'Azure DevOps' })).toHaveValue('azuredevops');
    });
  });
});
