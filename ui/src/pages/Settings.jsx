import { useState, useEffect } from 'react';
import { dashboardApi, tokenApi, gitHostApi } from '../services/api';
import ConfirmDialog from '../components/ConfirmDialog';
import ProviderIcon from '../components/ProviderIcon';
import ConnectionsStatus from '../components/ConnectionsStatus';
import { PROVIDERS, TOKEN_PLACEHOLDERS, needsConnection } from '../providers';

const emptyToken = { label: '', provider: 'github', token: '', git_host_id: '' };
const emptyHost = { name: '', base_url: '' };

export default function Settings() {
  const [health, setHealth] = useState(null);
  const [tokens, setTokens] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newToken, setNewToken] = useState(emptyToken);
  const [hosts, setHosts] = useState([]);
  const [hostsLoading, setHostsLoading] = useState(true);
  const [hostsError, setHostsError] = useState(null);
  const [tokenFormError, setTokenFormError] = useState('');
  const [showHostForm, setShowHostForm] = useState(false);
  const [newHost, setNewHost] = useState(emptyHost);
  const [savingHost, setSavingHost] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmModal, setConfirmModal] = useState(null);

  useEffect(() => {
    dashboardApi.health().then(setHealth).catch(() => {});
    loadTokens();
    loadHosts();
  }, []);

  async function loadTokens() {
    try {
      const data = await tokenApi.getAll();
      setTokens(data || []);
    } catch (err) {
      console.error('Failed to load tokens:', err);
    }
  }

  async function loadHosts() {
    setHostsLoading(true);
    setHostsError(null);
    try {
      const data = await gitHostApi.getAll();
      setHosts(data || []);
    } catch (err) {
      setHostsError(err);
    } finally {
      setHostsLoading(false);
    }
  }

  async function handleAddHost(e) {
    e.preventDefault();
    if (!newHost.name.trim() || !newHost.base_url.trim()) return;
    setSavingHost(true);
    try {
      await gitHostApi.create({ kind: 'azuredevops', name: newHost.name.trim(), base_url: newHost.base_url.trim() });
      setNewHost(emptyHost);
      setShowHostForm(false);
      loadHosts();
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setSavingHost(false);
    }
  }

  function handleDeleteHost(id, name) {
    setConfirmModal({
      title: 'Delete Connection',
      message: `Delete connection "${name}"? Tokens of this connection are deleted too. Connections that still have repositories cannot be deleted.`,
      onConfirm: async () => {
        await gitHostApi.delete(id);
        loadHosts();
        loadTokens();
      },
    });
  }

  async function handleAddToken(e) {
    e.preventDefault();
    if (!newToken.label.trim() || !newToken.token.trim()) return;
    const azure = needsConnection(newToken.provider);
    if (azure && !newToken.git_host_id) {
      setTokenFormError('Select a connection for this Azure DevOps token.');
      return;
    }
    setTokenFormError('');
    setSaving(true);
    try {
      // git_host_id is only valid for providers that need a connection.
      const { git_host_id, ...rest } = newToken;
      await tokenApi.create(azure ? { ...rest, git_host_id } : rest);
      setNewToken(emptyToken);
      setShowAddForm(false);
      loadTokens();
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setSaving(false);
    }
  }

  function handleDeleteToken(id, label) {
    setConfirmModal({
      title: 'Delete Token',
      message: `Delete token "${label}"? Repositories using this token will need a new one.`,
      // A failed delete rejects, so ConfirmDialog alerts it and stays open.
      onConfirm: async () => {
        await tokenApi.delete(id);
        loadTokens();
      },
    });
  }

  return (
    <div>
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900">Settings</h2>
        <p className="text-sm text-gray-500">System configuration and access tokens.</p>
      </div>

      {/* Azure DevOps connections */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm mb-8">
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Azure DevOps connections</h3>
            <p className="text-xs text-gray-500 mt-0.5">An Azure DevOps organization or on-premises collection. Tokens and repositories are bound to one.</p>
          </div>
          {!showHostForm && (
            <button
              className="px-3 py-1.5 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5"
              onClick={() => setShowHostForm(true)}
            >
              <svg aria-hidden="true" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
              Add Connection
            </button>
          )}
        </div>

        {showHostForm && (
          <form onSubmit={handleAddHost} className="px-6 py-4 bg-blue-50/50 border-b border-gray-200">
            <div className="grid grid-cols-12 gap-3 items-start">
              <div className="col-span-3 space-y-1">
                <label htmlFor="host-name" className="text-xs font-medium text-gray-600">Connection name</label>
                <input
                  id="host-name"
                  className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="e.g. Contoso"
                  value={newHost.name}
                  onChange={e => setNewHost({ ...newHost, name: e.target.value })}
                  required
                  autoFocus
                />
              </div>
              <div className="col-span-7 space-y-1">
                <label htmlFor="host-url" className="text-xs font-medium text-gray-600">Base URL</label>
                <input
                  id="host-url"
                  className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono"
                  placeholder="https://dev.azure.com/contoso"
                  value={newHost.base_url}
                  onChange={e => setNewHost({ ...newHost, base_url: e.target.value })}
                  required
                />
                <p className="text-xs text-gray-400">
                  Examples: <span className="font-mono">https://dev.azure.com/contoso</span>, <span className="font-mono">https://tfs.company.local/tfs/DefaultCollection</span>
                </p>
              </div>
              <div className="col-span-2 flex gap-2 pt-5">
                <button
                  type="submit"
                  className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md disabled:opacity-50 flex items-center gap-1"
                  disabled={savingHost}
                >
                  {savingHost ? <span className="h-3 w-3 animate-spin rounded-full border-2 border-white border-t-transparent"></span> : null}
                  Save Connection
                </button>
                <button
                  type="button"
                  className="px-3 py-2 bg-white border border-gray-300 hover:bg-gray-50 text-gray-600 text-sm font-medium rounded-md"
                  onClick={() => { setShowHostForm(false); setNewHost(emptyHost); }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </form>
        )}

        {hostsLoading || hostsError ? (
          <div className="px-6 py-6"><ConnectionsStatus loading={hostsLoading} error={hostsError} onRetry={loadHosts} /></div>
        ) : hosts.length === 0 ? (
          <div className="px-6 py-8 text-center text-gray-400 text-sm">No Azure DevOps connections yet.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {hosts.map(host => (
              <div key={host.id} className="px-6 py-3.5 flex items-center justify-between hover:bg-gray-50 transition-colors">
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <ProviderIcon provider={host.kind} decorative />
                    <span className="font-medium text-gray-900 text-sm">{host.name}</span>
                  </div>
                  <span className="text-xs font-mono text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{host.base_url}</span>
                  <span className="text-xs text-gray-400">{host.kind}</span>
                </div>
                <button
                  className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                  onClick={() => handleDeleteHost(host.id, host.name)}
                  title="Delete Connection"
                  aria-label={`Delete connection ${host.name}`}
                >
                  <svg aria-hidden="true" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Access Tokens Section */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm mb-8">
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Access Tokens</h3>
            <p className="text-xs text-gray-500 mt-0.5">Manage GitHub, GitLab and Azure DevOps personal access tokens for repository imports.</p>
          </div>
          {!showAddForm && (
            <button
              className="px-3 py-1.5 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5"
              onClick={() => setShowAddForm(true)}
            >
              <svg aria-hidden="true" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
              Add Token
            </button>
          )}
        </div>

        {/* Add Token Form */}
        {showAddForm && (
          <form onSubmit={handleAddToken} className="px-6 py-4 bg-blue-50/50 border-b border-gray-200">
            <div className="grid grid-cols-12 gap-3 items-end">
              <div className="col-span-3 space-y-1">
                <label htmlFor="token-label" className="text-xs font-medium text-gray-600">Label</label>
                <input
                  id="token-label"
                  className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="e.g. Personal, Work"
                  value={newToken.label}
                  onChange={e => setNewToken({ ...newToken, label: e.target.value })}
                  required
                  autoFocus
                />
              </div>
              <div className="col-span-2 space-y-1">
                <label htmlFor="token-provider" className="text-xs font-medium text-gray-600">Provider</label>
                <select
                  id="token-provider"
                  className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  value={newToken.provider}
                  onChange={e => setNewToken({ ...newToken, provider: e.target.value, git_host_id: '' })}
                >
                  {PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
                </select>
              </div>
              {needsConnection(newToken.provider) && (
                <div className="col-span-2 space-y-1">
                  <label htmlFor="token-connection" className="text-xs font-medium text-gray-600">Connection</label>
                  {hostsLoading ? (
                    <ConnectionsStatus loading />
                  ) : hostsError ? (
                    <p className="text-xs text-red-700 pt-2">Connections could not be loaded. Retry in the section above.</p>
                  ) : hosts.length === 0 ? (
                    <p className="text-xs text-amber-700 pt-2">Add an Azure DevOps connection first (see the section above).</p>
                  ) : (
                    <select
                      id="token-connection"
                      className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none"
                      value={newToken.git_host_id}
                      onChange={e => { setNewToken({ ...newToken, git_host_id: e.target.value }); setTokenFormError(''); }}
                      aria-required="true"
                    >
                      <option value="">Select...</option>
                      {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
                    </select>
                  )}
                </div>
              )}
              <div className={`${needsConnection(newToken.provider) ? 'col-span-3' : 'col-span-5'} space-y-1`}>
                <label htmlFor="token-value" className="text-xs font-medium text-gray-600">Token</label>
                <input
                  id="token-value"
                  className="w-full h-9 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono"
                  type="password"
                  placeholder={TOKEN_PLACEHOLDERS[newToken.provider]}
                  value={newToken.token}
                  onChange={e => setNewToken({ ...newToken, token: e.target.value })}
                  required
                />
              </div>
              <div className="col-span-2 flex gap-2">
                <button
                  type="submit"
                  className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md disabled:opacity-50 flex items-center gap-1"
                  disabled={saving}
                >
                  {saving ? <span className="h-3 w-3 animate-spin rounded-full border-2 border-white border-t-transparent"></span> : null}
                  Save
                </button>
                <button
                  type="button"
                  className="px-3 py-2 bg-white border border-gray-300 hover:bg-gray-50 text-gray-600 text-sm font-medium rounded-md"
                  onClick={() => { setShowAddForm(false); setNewToken(emptyToken); }}
                >
                  Cancel
                </button>
              </div>
            </div>
            {tokenFormError && <p role="alert" className="mt-2 text-sm text-red-700">{tokenFormError}</p>}
          </form>
        )}

        {/* Token List */}
        {tokens.length === 0 ? (
          <div className="px-6 py-10 text-center text-gray-400 text-sm">
            <svg className="w-10 h-10 mx-auto mb-3 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
            No access tokens saved yet. Add one to get started with importing repositories.
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {tokens.map(token => (
              <div key={token.id} className="px-6 py-3.5 flex items-center justify-between hover:bg-gray-50 transition-colors">
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <ProviderIcon provider={token.provider} decorative />
                    <span className="font-medium text-gray-900 text-sm">{token.label}</span>
                  </div>
                  <span className="text-xs font-mono text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{token.masked_token}</span>
                  {token.git_host_id && (
                    <span className="text-xs text-blue-700 bg-blue-50 px-2 py-0.5 rounded">Connection: {hosts.find(h => h.id === token.git_host_id)?.name ?? 'unknown'}</span>
                  )}
                  <span className="text-xs text-gray-400">{new Date(token.created_at).toLocaleDateString()}</span>
                </div>
                <button
                  className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                  onClick={() => handleDeleteToken(token.id, token.label)}
                  title="Delete Token"
                  aria-label={`Delete token ${token.label}`}
                >
                  <svg aria-hidden="true" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* System Status Section */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm mb-8">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">System Status</h3>
        </div>
        <div className="px-6 py-4">
          <div className="flex items-center gap-3">
            <span className={`h-3 w-3 rounded-full ${health ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.4)]' : 'bg-red-500'}`}></span>
            <span className="font-medium text-gray-900 text-sm">{health ? 'All systems operational' : 'Unable to reach API'}</span>
          </div>
          {health && (
            <div className="mt-3 flex gap-6 text-xs text-gray-400 font-mono">
              <span>SERVICE: <span className="text-blue-600">{health.service}</span></span>
              <span>STATUS: <span className="text-green-600">{health.status}</span></span>
            </div>
          )}
        </div>
      </div>

      {/* Ecosystems */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm mb-8">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Supported Ecosystems</h3>
        </div>
        <div className="px-6 py-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { name: 'npm', files: 'package.json, package-lock.json, yarn.lock, pnpm-lock.yaml' },
              { name: 'PyPI', files: 'requirements*.txt, pyproject.toml, Pipfile(.lock), poetry.lock, uv.lock' },
              { name: 'NuGet', files: '*.csproj, packages.config, Directory.Packages.props, packages.lock.json' },
              { name: 'Go', files: 'go.mod' },
            ].map(eco => (
              <div key={eco.name} className="p-4 bg-gray-50 rounded-lg border border-gray-100 text-center">
                <div className="font-semibold text-gray-900 text-sm">{eco.name}</div>
                <div className="text-xs text-gray-400 mt-1 font-mono">{eco.files}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* About */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">About</h3>
        </div>
        <div className="px-6 py-4">
          <div className="flex items-center gap-4">
            <span className="font-bold text-gray-900">Orbit</span>
            <span className="px-2 py-0.5 bg-gray-100 rounded text-gray-500 text-xs font-medium">v0.1.0</span>
          </div>
          <p className="text-sm text-gray-500 mt-2">
            Open-source dependency management & security scanner. Vulnerability data powered by{' '}
            <a href="https://osv.dev" target="_blank" rel="noopener" className="text-blue-600 hover:text-blue-700 underline">osv.dev</a>.
          </p>
        </div>
      </div>

      {confirmModal && <ConfirmDialog {...confirmModal} onCancel={() => setConfirmModal(null)} />}
    </div>
  );
}
