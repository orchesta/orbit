import { describe, it, expect, vi, afterEach } from 'vitest';
import { screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Settings from './Settings';
import { renderWithProviders } from '../test/render';
import { mockFetch } from '../test/fetch';

const token = { id: 't1', provider: 'github', label: 'ci', masked_token: 'ghp_***', created_at: '2026-10-01T00:00:00Z' };

function routes(deleteResponse) {
  let deleted = false;
  return {
    'GET /health': { body: { data: { status: 'ok' } } },
    'GET /tokens': () => ({ body: { data: deleted ? [] : [token] } }),
    'DELETE /tokens/t1': () => {
      const res = deleteResponse();
      if (res.status === 204) deleted = true;
      return res;
    },
  };
}

async function confirmDelete() {
  await userEvent.click(await screen.findByTitle('Delete Token'));
  const dialog = screen.getByRole('dialog', { name: 'Delete Token' });
  await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
  return dialog;
}

describe('Settings token deletion', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps the confirm dialog open when the delete fails, so it can be retried', async () => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    let fail = true;
    const { calls } = mockFetch(routes(() => (fail ? { status: 500, body: { error: 'internal server error' } } : { status: 204 })));
    renderWithProviders(<Settings />);

    const dialog = await confirmDelete();
    await waitFor(() => expect(alert).toHaveBeenCalledWith('Error: internal server error'));
    expect(dialog).toBeInTheDocument();

    fail = false;
    const retry = within(dialog).getByRole('button', { name: 'Delete' });
    await waitFor(() => expect(retry).toBeEnabled());
    await userEvent.click(retry);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(2);
    await waitFor(() => expect(screen.queryByText('ci')).not.toBeInTheDocument());
  });

  it('closes the confirm dialog once the delete succeeds', async () => {
    mockFetch(routes(() => ({ status: 204 })));
    renderWithProviders(<Settings />);

    await confirmDelete();
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(screen.queryByText('ci')).not.toBeInTheDocument());
  });
});

const host = { id: 'h1', kind: 'azuredevops', name: 'Contoso', base_url: 'https://dev.azure.com/contoso', created_at: '2026-10-01T00:00:00Z' };

describe('Settings Azure DevOps connections', () => {
  afterEach(() => vi.restoreAllMocks());

  it('lists connections and adds a new one', async () => {
    let hosts = [host];
    const { calls } = mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': () => ({ body: { data: hosts } }),
      'POST /git-hosts': ({ body }) => {
        const b = JSON.parse(body);
        hosts = [...hosts, { id: 'h2', created_at: '2026-10-02T00:00:00Z', ...b }];
        return { status: 201, body: { data: hosts[1] } };
      },
    });
    renderWithProviders(<Settings />);

    expect(await screen.findByText('Azure DevOps connections')).toBeInTheDocument();
    expect(await screen.findByText('Contoso')).toBeInTheDocument();
    expect(screen.getByText('https://dev.azure.com/contoso')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Add Connection' }));
    expect(screen.getByText(/https:\/\/tfs\.company\.local\/tfs\/DefaultCollection/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Connection name'), 'On-prem');
    await userEvent.type(screen.getByLabelText('Base URL'), 'https://tfs.company.local/tfs/DefaultCollection');
    await userEvent.click(screen.getByRole('button', { name: 'Save Connection' }));

    expect(await screen.findByText('On-prem')).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST' && c.path === '/git-hosts');
    expect(JSON.parse(post.body)).toEqual({ kind: 'azuredevops', name: 'On-prem', base_url: 'https://tfs.company.local/tfs/DefaultCollection' });
  });

  it('requires a connection for an Azure DevOps token and sends git_host_id', async () => {
    const { calls } = mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': { body: { data: [host] } },
      'POST /tokens': { status: 201, body: { data: { id: 't9' } } },
    });
    renderWithProviders(<Settings />);
    await screen.findByText('Contoso');

    await userEvent.click(screen.getByRole('button', { name: 'Add Token' }));
    expect(screen.queryByLabelText('Connection')).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Label'), 'azure');
    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
    const conn = screen.getByLabelText('Connection');
    expect(conn).toBeRequired();
    expect(screen.getByPlaceholderText('Personal access token with Code (Read) scope')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Token'), 'pat');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(calls.some((c) => c.method === 'POST' && c.path === '/tokens')).toBe(false);
    expect(screen.getByRole('alert')).toHaveTextContent('Select a connection');

    await userEvent.selectOptions(conn, 'h1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/tokens')).toBe(true));
    const post = calls.find((c) => c.method === 'POST' && c.path === '/tokens');
    expect(JSON.parse(post.body)).toEqual({ label: 'azure', provider: 'azuredevops', token: 'pat', git_host_id: 'h1' });
  });

  it('points to adding a connection when none exist, and does not send git_host_id for GitHub', async () => {
    const { calls } = mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': { body: { data: [] } },
      'POST /tokens': { status: 201, body: { data: { id: 't9' } } },
    });
    renderWithProviders(<Settings />);
    await userEvent.click(await screen.findByRole('button', { name: 'Add Token' }));
    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
    expect(screen.getByText(/Add an Azure DevOps connection first/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'github');
    await userEvent.type(screen.getByLabelText('Label'), 'gh');
    await userEvent.type(screen.getByLabelText('Token'), 'ghp');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/tokens' && c.method === 'POST')).toBe(true));
    expect(JSON.parse(calls.find((c) => c.method === 'POST').body)).toEqual({ label: 'gh', provider: 'github', token: 'ghp' });
  });

  it('shows the connection name and Azure icon on Azure tokens', async () => {
    mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [{ id: 't2', provider: 'azuredevops', label: 'az', masked_token: '***', git_host_id: 'h1', created_at: '2026-10-01T00:00:00Z' }] } },
      'GET /git-hosts': { body: { data: [host] } },
    });
    renderWithProviders(<Settings />);
    expect(await screen.findByText('az')).toBeInTheDocument();
    expect(await screen.findByText('Connection: Contoso')).toBeInTheDocument();
    const row = screen.getByText('az').closest('.divide-y > div');
    // The icon is decorative here: the provider is not announced twice.
    expect(row.querySelector('svg[data-provider="azuredevops"]')).toHaveAttribute('aria-hidden', 'true');
    expect(within(row).queryByRole('img')).not.toBeInTheDocument();
  });

  it('warns about cascading deletes and keeps the dialog open on a 409', async () => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': { body: { data: [host] } },
      'DELETE /git-hosts/h1': { status: 409, body: { error: 'connection still has repositories' } },
    });
    renderWithProviders(<Settings />);
    await userEvent.click(await screen.findByRole('button', { name: 'Delete connection Contoso' }));
    const dialog = screen.getByRole('dialog', { name: 'Delete Connection' });
    expect(dialog).toHaveTextContent('Tokens of this connection are deleted too. Connections that still have repositories cannot be deleted.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(alert).toHaveBeenCalledWith('Error: connection still has repositories'));
    expect(dialog).toBeInTheDocument();
  });

  it('shows a load error with Retry instead of the empty hint when connections fail to load', async () => {
    let fail = true;
    mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': () => (fail ? { status: 500, body: { error: 'hosts exploded' } } : { body: { data: [host] } }),
    });
    renderWithProviders(<Settings />);
    expect(await screen.findByText('hosts exploded')).toBeInTheDocument();
    expect(screen.queryByText('No Azure DevOps connections yet.')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Add Token' }));
    await userEvent.selectOptions(screen.getByLabelText('Provider'), 'azuredevops');
    expect(screen.queryByText(/Add an Azure DevOps connection first/)).not.toBeInTheDocument();

    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('https://dev.azure.com/contoso')).toBeInTheDocument();
    expect(screen.queryByText('hosts exploded')).not.toBeInTheDocument();
  });

  it('shows the API message when a duplicate connection is rejected', async () => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {});
    mockFetch({
      'GET /health': { body: { data: { status: 'ok' } } },
      'GET /tokens': { body: { data: [] } },
      'GET /git-hosts': { body: { data: [host] } },
      'POST /git-hosts': { status: 409, body: { error: 'a connection with this base URL already exists' } },
    });
    renderWithProviders(<Settings />);
    await userEvent.click(await screen.findByRole('button', { name: 'Add Connection' }));
    await userEvent.type(screen.getByLabelText('Connection name'), 'Dup');
    await userEvent.type(screen.getByLabelText('Base URL'), 'https://dev.azure.com/contoso');
    await userEvent.click(screen.getByRole('button', { name: 'Save Connection' }));
    await waitFor(() => expect(alert).toHaveBeenCalledWith('Error: a connection with this base URL already exists'));
  });
});
