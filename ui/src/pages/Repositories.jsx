import { useState, useEffect, useEffectEvent, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { repositoryApi, tokenApi, gitHostApi } from '../services/api';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import { useScanTracker } from '../hooks/useScanTracker';
import Spinner from '../components/Spinner';
import ErrorState from '../components/ErrorState';
import Pagination from '../components/Pagination';
import ConfirmDialog from '../components/ConfirmDialog';
import ProviderIcon from '../components/ProviderIcon';
import ConnectionsStatus from '../components/ConnectionsStatus';
import { PROVIDERS, TOKEN_PLACEHOLDERS, providerLabel, needsConnection } from '../providers';

const emptyForm = { name: '', url: '', provider: 'github', auth_token: '', default_branch: 'main', schedule: '0 */6 * * *', git_host_id: '' };
const FETCHERS = {
  github: repositoryApi.fetchGitHub,
  gitlab: repositoryApi.fetchGitLab,
  azuredevops: repositoryApi.fetchAzureDevOps,
};

// ImportMenuItems lists one import entry per provider, then manual add.
function ImportMenuItems({ onImport, onManual }) {
  const item = 'w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-3';
  return (
    <>
      {PROVIDERS.map(p => (
        <button key={p.id} className={item} onClick={() => onImport(p.id)}>
          <ProviderIcon provider={p.id} className="w-4 h-4" decorative />
          Import from {p.label}
        </button>
      ))}
      <div className="border-t border-gray-100 my-1"></div>
      <button className={item} onClick={onManual}>
        <svg aria-hidden="true" className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
        Add Manually
      </button>
    </>
  );
}

// A repository whose newest scan is still queued or running on the server.
const hasActiveScan = (repo) => repo.scan_status === 'pending' || repo.scan_status === 'running';

export default function Repositories() {
  const queryClient = useQueryClient();

  // Import dropdown
  const [showImportMenu, setShowImportMenu] = useState(false);
  const importMenuRef = useRef(null);

  // Manual add modal
  const [showManualModal, setShowManualModal] = useState(false);
  const [formData, setFormData] = useState(emptyForm);
  const [hosts, setHosts] = useState([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState(null);
  const [formError, setFormError] = useState('');

  // Import wizard (GitHub + GitLab)
  const [showGitHubModal, setShowGitHubModal] = useState(false);
  const [importProvider, setImportProvider] = useState('github');
  const [importStep, setImportStep] = useState(1);
  const [savedTokens, setSavedTokens] = useState([]);
  const [selectedTokenId, setSelectedTokenId] = useState('');
  const [fetchingRepos, setFetchingRepos] = useState(false);
  const [fetchError, setFetchError] = useState('');
  const [githubRepos, setGithubRepos] = useState([]);
  const [selectedRepos, setSelectedRepos] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [importing, setImporting] = useState(false);
  const [loadingTokens, setLoadingTokens] = useState(false);

  // Confirm modal
  const [confirmModal, setConfirmModal] = useState(null);

  // Filters & pagination (URL-based)
  const [searchParams, setSearchParams] = useSearchParams();
  const filterProvider = searchParams.get('provider') || 'all';
  const filterName = searchParams.get('q') || '';
  const filterStatus = searchParams.get('status') || '';
  const currentPage = parseInt(searchParams.get('page') || '1', 10);
  const perPage = 25;

  function setFilterProvider(v) {
    const p = new URLSearchParams(searchParams);
    if (v === 'all') p.delete('provider'); else p.set('provider', v);
    p.delete('page');
    setSearchParams(p, { replace: true });
  }
  function setFilterName(v) {
    const p = new URLSearchParams(searchParams);
    if (v === '') p.delete('q'); else p.set('q', v);
    p.delete('page');
    setSearchParams(p, { replace: true });
  }
  function setFilterStatus(v) {
    const p = new URLSearchParams(searchParams);
    if (v === '') p.delete('status'); else p.set('status', v);
    p.delete('page');
    setSearchParams(p, { replace: true });
  }
  function setCurrentPage(pg) {
    const p = new URLSearchParams(searchParams);
    const val = typeof pg === 'function' ? pg(currentPage) : pg;
    if (val <= 1) p.delete('page'); else p.set('page', String(val));
    setSearchParams(p, { replace: true });
  }

  const [searchInput, setSearchInput] = useState(filterName);
  const debouncedSearch = useDebouncedValue(searchInput, 300);
  // When the URL search changes from outside (e.g. a sidebar link drops q),
  // adopt it. Resetting searchInput also restarts the debounce, so a pending
  // keystroke can't write the old search back.
  const [seenFilterName, setSeenFilterName] = useState(filterName);
  if (filterName !== seenFilterName) {
    setSeenFilterName(filterName);
    if (filterName !== debouncedSearch) setSearchInput(filterName);
  }
  // Push the debounced search into the URL (resets to page 1).
  // Comparing before setting keeps this effect from looping.
  useEffect(() => {
    if (debouncedSearch !== filterName) setFilterName(debouncedSearch);
    // setFilterName only reads searchParams; adding it would re-run on every URL change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch]);

  function clearFilters() {
    const p = new URLSearchParams(searchParams);
    ['q', 'provider', 'status', 'page'].forEach(k => p.delete(k));
    setSearchParams(p, { replace: true });
    setSearchInput('');
  }

  const listParams = { page: currentPage, per_page: perPage, provider: filterProvider, q: filterName, status: filterStatus };
  const reposQuery = useQuery({
    queryKey: ['repositories', listParams],
    queryFn: ({ signal }) => repositoryApi.getAll(listParams, { signal }),
    placeholderData: keepPreviousData,
    // Scans outlive the page (and imports fire and forget), so poll while any row has one.
    refetchInterval: (query) => (query.state.data?.data?.some(hasActiveScan) ? 2000 : false),
  });
  const repoData = reposQuery.data ?? { data: [], total: 0, page: 1, per_page: perPage, total_pages: 1 };
  const repos = repoData.data || [];
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['repositories'] });
  // Rows kept on screen from the previous query while the next one loads.
  const showingPlaceholder = reposQuery.isPlaceholderData;

  // Deleting the last rows of the last page leaves the URL past the end; step
  // back once real data says so.
  const lastPage = Math.max(1, repoData.total_pages || 1);
  const pastLastPage = reposQuery.isSuccess && !showingPlaceholder && currentPage > lastPage;
  const goToLastPage = useEffectEvent(() => setCurrentPage(lastPage));
  useEffect(() => {
    if (pastLastPage) goToLastPage();
  }, [pastLastPage]);

  const tracker = useScanTracker({ onFinished: refresh });

  // Selection belongs to the query it was made in, so changing the page or a
  // filter drops it without an effect. Only rows on screen count, so ids that
  // disappeared after a refresh are never acted on; placeholder rows from the
  // previous query can't be selected at all, and nothing counts while a failed
  // load shows an error instead of the rows.
  const selectionKey = JSON.stringify(listParams);
  const [selection, setSelection] = useState({ key: selectionKey, ids: new Set() });
  const visibleIds = new Set(showingPlaceholder || reposQuery.isError ? [] : repos.map(r => r.id));
  const selectedFrom = (sel) => new Set(sel.key === selectionKey ? [...sel.ids].filter(id => visibleIds.has(id)) : []);
  const selectedIds = selectedFrom(selection);
  const setSelectedIds = (update) => setSelection((prev) => {
    const current = selectedFrom(prev);
    return { key: selectionKey, ids: typeof update === 'function' ? update(current) : update };
  });
  const [bulkScanning, setBulkScanning] = useState(false);

  // Close import dropdown on outside click
  useEffect(() => {
    function handleClick(e) {
      if (importMenuRef.current && !importMenuRef.current.contains(e.target)) {
        setShowImportMenu(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  // ---- Confirm Modal Helper ----
  function showConfirm(title, message, onConfirm, variant = 'danger') {
    setConfirmModal({ title, message, onConfirm, variant });
  }

  // ---- CRUD ----
  async function handleCreate(e) {
    e.preventDefault();
    try {
      const { git_host_id, ...rest } = formData;
      const azure = needsConnection(formData.provider);
      if (azure && !git_host_id) {
        setFormError('Select a connection for this Azure DevOps repository.');
        return;
      }
      setFormError('');
      // git_host_id is only valid for providers that need a connection.
      const created = await repositoryApi.create(azure ? { ...rest, git_host_id } : rest);
      setShowManualModal(false);
      setFormData(emptyForm);
      refresh();
      if (created?.id) tracker.start(created.id).catch(() => {});
    } catch (err) {
      alert('Error: ' + err.message);
    }
  }

  function handleDelete(id, name) {
    showConfirm(
      'Delete Repository',
      `Are you sure you want to delete "${name}"? All scan data will be permanently removed.`,
      async () => {
        await repositoryApi.delete(id);
        refresh();
        setSelectedIds(prev => { const s = new Set(prev); s.delete(id); return s; });
      }
    );
  }

  function handleDeleteSelected() {
    const ids = [...selectedIds];
    setConfirmModal({
      title: 'Delete Selected Repositories',
      message: `Delete ${ids.length} selected repositories? All of their scan data will be permanently removed.`,
      onConfirm: async () => {
        const results = await Promise.allSettled(ids.map((id) => repositoryApi.delete(id)));
        const failed = results.filter((r) => r.status === 'rejected');
        setSelectedIds(new Set());
        refresh();
        if (failed.length) alert(`Deleted ${ids.length - failed.length} of ${ids.length}. ${failed.length} failed: ${failed[0].reason.message}`);
      },
    });
  }

  // ---- Scanning ----
  async function handleScanSelected() {
    const ids = [...selectedIds];
    setBulkScanning(true);
    const results = await Promise.allSettled(ids.map((id) => tracker.start(id)));
    setBulkScanning(false);
    const failed = results.filter((r) => r.status === 'rejected');
    if (failed.length) alert(`Started ${ids.length - failed.length} of ${ids.length}. ${failed.length} failed: ${failed[0].reason.message}`);
  }

  // ---- Selection ----
  function toggleSelect(id) {
    setSelectedIds(prev => {
      const s = new Set(prev);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  }
  function toggleSelectAll() {
    if (selectedIds.size === repos.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(repos.map(r => r.id)));
    }
  }

  // ---- Import (GitHub / GitLab) ----
  async function loadHosts() {
    setHostsLoading(true);
    setHostsError(null);
    try { setHosts((await gitHostApi.getAll()) || []); } catch (err) { setHostsError(err); } finally { setHostsLoading(false); }
  }

  function openManual() {
    setFormError('');
    setShowImportMenu(false);
    setShowManualModal(true);
    loadHosts();
  }

  async function openImport(provider) {
    setImportProvider(provider);
    setShowImportMenu(false);
    setShowGitHubModal(true);
    setLoadingTokens(true);
    if (needsConnection(provider)) loadHosts();
    try {
      const data = await tokenApi.getAll();
      setSavedTokens(data || []);
      const filtered = (data || []).filter(t => t.provider === provider);
      if (filtered.length > 0) setSelectedTokenId(filtered[0].id);
    } catch { setSavedTokens([]); }
    finally { setLoadingTokens(false); }
  }

  async function handleFetchRepos() {
    if (!selectedTokenId) return;
    setFetchingRepos(true);
    setFetchError('');
    try {
      const fetched = await FETCHERS[importProvider](selectedTokenId);
      setGithubRepos(fetched || []);
      setSelectedRepos({});
      setImportStep(2);
    } catch (err) {
      setFetchError(err.message || 'Failed to fetch repositories.');
    } finally { setFetchingRepos(false); }
  }

  // Already-imported detection
  const importedUrls = new Set(repos.map(r => r.url?.replace(/\.git$/, '').toLowerCase()));
  function isImported(ghRepo) {
    return importedUrls.has(ghRepo.url?.replace(/\.git$/, '').toLowerCase());
  }

  function toggleRepo(fullName) {
    const ghRepo = githubRepos.find(r => r.full_name === fullName);
    if (ghRepo && isImported(ghRepo)) return;
    setSelectedRepos(prev => ({ ...prev, [fullName]: !prev[fullName] }));
  }

  function toggleAllRepos() {
    const newOnly = filteredGithubRepos.filter(r => !isImported(r));
    const allSelected = newOnly.length > 0 && newOnly.every(r => selectedRepos[r.full_name]);
    const updates = {};
    newOnly.forEach(r => { updates[r.full_name] = !allSelected; });
    setSelectedRepos(prev => ({ ...prev, ...updates }));
  }

  const filteredGithubRepos = githubRepos
    .filter(r =>
      r.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.description || '').toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      const aI = isImported(a), bI = isImported(b);
      if (aI !== bI) return aI ? 1 : -1;
      return a.full_name.localeCompare(b.full_name);
    });

  const importSelectedCount = Object.values(selectedRepos).filter(Boolean).length;
  const newRepoCount = filteredGithubRepos.filter(r => !isImported(r)).length;

  async function handleBulkImport() {
    const toImport = githubRepos
      .filter(r => selectedRepos[r.full_name])
      .map(r => ({ name: r.name, url: r.url, default_branch: r.default_branch || 'main' }));
    if (toImport.length === 0) return;
    setImporting(true);
    try {
      const result = await repositoryApi.bulkImport(selectedTokenId, toImport, importProvider);
      closeGitHubImport();
      // An import can create hundreds of repositories; polling a tracker for
      // each would flood the API, so their first scans are only queued and
      // the list shows their status from the server.
      (result?.created || []).forEach((r) => { if (r?.id) repositoryApi.triggerScan(r.id).catch(() => {}); });
      refresh();
      if (result?.skipped?.length) alert(`${result.skipped.length} already imported, skipped: ${result.skipped.join(', ')}`);
    } catch (err) {
      // Some repositories may have been created before the failure.
      refresh();
      alert('Import error: ' + err.message);
    }
    finally { setImporting(false); }
  }

  function closeGitHubImport() {
    setShowGitHubModal(false);
    setImportStep(1);
    setSelectedTokenId('');
    setGithubRepos([]);
    setSelectedRepos({});
    setSearchQuery('');
    setFetchError('');
    setSavedTokens([]);
    setImportProvider('github');
  }

  // The URL hint follows the provider, and for Azure DevOps the chosen connection.
  const chosenHost = hosts.find(h => h.id === formData.git_host_id);
  const urlPlaceholder = formData.provider === 'azuredevops'
    ? `${(chosenHost?.base_url || 'https://dev.azure.com/org').replace(/\/+$/, '')}/Project/_git/Repo`
    : formData.provider === 'gitlab' ? 'https://gitlab.com/group/repo' : 'https://github.com/org/repo';

  if (reposQuery.isPending) return <Spinner />;

  const hasFilters = filterName || filterProvider !== 'all' || filterStatus;
  // The onboarding empty state is only for a truly empty inventory; a failed
  // load or a filtered/paged view with no rows keeps the filter bar.
  const noRepositories = !reposQuery.isError && repos.length === 0 && !hasFilters && currentPage === 1;

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Repositories</h2>
          <p className="text-sm text-gray-500">Manage and scan your code repositories.</p>
        </div>
        {!noRepositories && (
          <div className="flex gap-2">
            {selectedIds.size > 0 && (
              <>
                <button
                  className="px-3 py-2 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
                  onClick={handleScanSelected}
                  disabled={bulkScanning || showingPlaceholder}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                  Scan selected ({selectedIds.size})
                </button>
                <button
                  className="px-3 py-2 bg-white border border-red-200 hover:bg-red-50 text-red-600 text-sm font-medium rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
                  onClick={handleDeleteSelected}
                  disabled={showingPlaceholder}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                  Delete selected ({selectedIds.size})
                </button>
              </>
            )}
            <div className="relative" ref={importMenuRef}>
              <button className="px-4 py-2 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2" onClick={() => setShowImportMenu(!showImportMenu)}>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
                Import
                <svg className="w-3 h-3 ml-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
              </button>
              {showImportMenu && (
                <div className="absolute right-0 mt-1 w-52 bg-white border border-gray-200 rounded-lg shadow-lg z-50 py-1">
                  <ImportMenuItems onImport={openImport} onManual={openManual} />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      {/* Empty state */}
      {reposQuery.isError ? (
        <ErrorState error={reposQuery.error} onRetry={() => reposQuery.refetch()} />
      ) : noRepositories ? (
        <div className="bg-white border border-gray-200 rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" /></svg>
          <h3 className="text-lg font-medium text-gray-900 mb-1">No repositories yet</h3>
          <p className="text-sm text-gray-500 mb-6">Import your repositories to get started.</p>
          <div className="relative inline-block">
            <button className="px-4 py-2 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2" onClick={() => setShowImportMenu(!showImportMenu)}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
              Import Repositories
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
            </button>
            {showImportMenu && (
              <div className="absolute left-1/2 -translate-x-1/2 mt-1 w-52 bg-white border border-gray-200 rounded-lg shadow-lg z-50 py-1">
                <ImportMenuItems onImport={openImport} onManual={openManual} />
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          {/* Filter bar */}
          <div className="px-4 py-3 border-b border-gray-200 bg-gray-50/50 flex items-center gap-3 flex-wrap">
            <div className="relative">
              <svg className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
              <input
                type="text"
                placeholder="Search repositories..."
                className="pl-9 pr-3 py-1.5 bg-white border border-gray-300 rounded-lg text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none w-64"
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
              />
            </div>
            <select
              className="px-3 py-1.5 bg-white border border-gray-300 rounded-lg text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none"
              value={filterProvider}
              onChange={e => setFilterProvider(e.target.value)}
            >
              <option value="all">All Providers</option>
              {PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <div className="flex gap-1">
              {[{ label: 'All', value: '' }, { label: 'Has Issues', value: 'issues' }, { label: 'Vulnerable', value: 'vulnerable' }, { label: 'Outdated', value: 'outdated' }].map(s => (
                <button
                  key={s.value}
                  className={`px-2.5 py-1 text-xs font-medium rounded-full transition-colors ${filterStatus === s.value ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                  onClick={() => setFilterStatus(s.value)}
                >{s.label}</button>
              ))}
            </div>
            <span className="ml-auto text-xs text-gray-400">{repoData.total} repositories</span>
          </div>
          {repos.length === 0 ? (
            <div className="p-12 text-center">
              <p className="text-sm text-gray-500 mb-4">No repositories match these filters.</p>
              <button
                className="px-3 py-2 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 text-sm font-medium rounded-lg transition-colors"
                onClick={clearFilters}
              >
                Clear filters
              </button>
            </div>
          ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 border-b border-gray-200 text-gray-500">
                <tr>
                  <th className="pl-4 pr-2 py-3 w-10">
                    <input
                      type="checkbox"
                      aria-label="Select all"
                      className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      checked={selectedIds.size === repos.length && repos.length > 0}
                      disabled={showingPlaceholder}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th className="px-4 py-3 font-medium">Name</th>
                  <th className="px-4 py-3 font-medium">Provider</th>
                  <th className="px-4 py-3 font-medium">Branch</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Last Scanned</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {repos.map(repo => {
                  const scanning = tracker.isScanning(repo.id) || hasActiveScan(repo);
                  return (
                  <tr key={repo.id} className={`hover:bg-gray-50 transition-colors ${selectedIds.has(repo.id) ? 'bg-blue-50/40' : ''}`}>
                    <td className="pl-4 pr-2 py-3">
                      <input
                        type="checkbox"
                        aria-label={`Select ${repo.name}`}
                        className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        checked={selectedIds.has(repo.id)}
                        disabled={showingPlaceholder}
                        onChange={() => toggleSelect(repo.id)}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <Link to={`/repositories/${repo.id}`} className="text-blue-600 hover:text-blue-800 font-medium truncate block max-w-xs">{repo.name}</Link>
                      <div className="text-gray-400 text-xs truncate max-w-xs">{repo.url}</div>
                    </td>
                    <td className="px-4 py-3 text-gray-600"><span className="inline-flex items-center gap-2"><ProviderIcon provider={repo.provider} className="w-4 h-4" decorative />{providerLabel(repo.provider)}</span></td>
                    <td className="px-4 py-3 text-gray-600">{repo.default_branch}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${repo.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                        {repo.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <div className="flex items-center gap-1.5">
                        <span className="text-gray-500">{repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleString() : <span className="text-gray-300">Never</span>}</span>
                        {repo.last_scanned_at && repo.vulnerable_deps > 0 && (
                          <span title={`${repo.vulnerable_deps} vulnerable package${repo.vulnerable_deps > 1 ? 's' : ''}`}>
                            <svg className="w-4 h-4 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.268 16c-.77 1.333.192 3 1.732 3z" /></svg>
                          </span>
                        )}
                        {repo.last_scanned_at && repo.vulnerable_deps === 0 && repo.outdated_deps > 0 && (
                          <span title={`${repo.outdated_deps} outdated package${repo.outdated_deps > 1 ? 's' : ''}`}>
                            <svg className="w-4 h-4 text-orange-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.268 16c-.77 1.333.192 3 1.732 3z" /></svg>
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex justify-end gap-1.5">
                        <button
                          className="px-2.5 py-1.5 bg-white border border-gray-200 hover:bg-gray-50 text-gray-600 rounded-md text-xs font-medium transition-colors disabled:opacity-50 flex items-center gap-1"
                          aria-label={`Scan ${repo.name}`}
                          onClick={() => tracker.start(repo.id).catch((e) => alert('Scan error: ' + e.message))}
                          disabled={scanning}
                        >
                          {scanning ? (
                            <span className="h-3 w-3 animate-spin rounded-full border-2 border-gray-400 border-t-transparent"></span>
                          ) : (
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                          )}
                          Scan
                        </button>
                        <button
                          className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                          onClick={() => handleDelete(repo.id, repo.name)}
                          title="Delete"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          )}
          <Pagination page={currentPage} totalPages={repoData.total_pages} total={repoData.total} label="repos" onChange={setCurrentPage} />
        </div>
      )}

      {/* ========== CONFIRM MODAL ========== */}
      {confirmModal && <ConfirmDialog {...confirmModal} onCancel={() => setConfirmModal(null)} />}

      {/* ========== IMPORT MODAL (GitHub / GitLab) ========== */}
      {showGitHubModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/50 p-4" onClick={closeGitHubImport}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl overflow-hidden max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center shrink-0">
              <div className="flex items-center gap-3">
                <ProviderIcon provider={importProvider} decorative />
                <h3 className="text-lg font-medium text-gray-900">{importStep === 1 ? 'Select Token' : 'Select Repositories'}</h3>
              </div>
              <button onClick={closeGitHubImport} className="text-gray-400 hover:text-gray-500"><svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
            </div>

            {importStep === 1 ? (
              <div className="p-6 space-y-4">
                {loadingTokens ? (
                  <div className="flex items-center justify-center py-8"><div className="h-6 w-6 animate-spin rounded-full border-3 border-blue-600 border-t-transparent"></div></div>
                ) : savedTokens.filter(t => t.provider === importProvider).length === 0 ? (
                  <div className="text-center py-8">
                    <svg className="w-10 h-10 mx-auto mb-3 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
                    <p className="text-gray-500 text-sm mb-4">No {providerLabel(importProvider)} access tokens found. Add one in Settings first.</p>
                    <Link to="/settings" className="inline-flex items-center gap-1.5 px-4 py-2 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg" onClick={closeGitHubImport}>Go to Settings</Link>
                  </div>
                ) : (
                  <>
                    <div className="space-y-1.5">
                      <label className="text-sm font-medium text-gray-700">Choose an access token</label>
                      <div className="space-y-2">
                        {savedTokens.filter(t => t.provider === importProvider).map(token => (
                          <label key={token.id} className={`flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${selectedTokenId === token.id ? 'border-blue-500 bg-blue-50/50' : 'border-gray-200 hover:border-gray-300'}`}>
                            <input type="radio" name="token" className="h-4 w-4 text-blue-600" checked={selectedTokenId === token.id} onChange={() => setSelectedTokenId(token.id)} />
                            <ProviderIcon provider={importProvider} className="w-4 h-4" decorative />
                            <div className="flex-1"><span className="font-medium text-gray-900 text-sm">{token.label}</span><span className="ml-2 text-xs font-mono text-gray-400">{token.masked_token}</span>{token.git_host_id && <span className="ml-2 text-xs text-blue-700 bg-blue-50 px-2 py-0.5 rounded">{hostsLoading ? 'Loading…' : hostsError ? 'connection unavailable' : (hosts.find(h => h.id === token.git_host_id)?.name ?? 'unknown connection')}</span>}</div>
                          </label>
                        ))}
                      </div>
                      <p className="text-xs text-gray-400 mt-2">Manage tokens in <Link to="/settings" onClick={closeGitHubImport} className="text-blue-600 hover:underline">Settings</Link></p>
                    </div>
                    {needsConnection(importProvider) && hostsError && <ConnectionsStatus error={hostsError} onRetry={loadHosts} />}
                    {fetchError && <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-sm text-red-700">{fetchError}</div>}
                    <div className="pt-2 flex justify-end gap-3">
                      <button className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50" onClick={closeGitHubImport}>Cancel</button>
                      <button className="px-4 py-2 text-sm font-medium text-white bg-gray-900 rounded-lg hover:bg-gray-800 disabled:opacity-50 flex items-center gap-2" onClick={handleFetchRepos} disabled={!selectedTokenId || fetchingRepos}>
                        {fetchingRepos && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent"></span>}
                        {fetchingRepos ? 'Fetching...' : 'Fetch Repositories'}
                      </button>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="flex flex-col overflow-hidden">
                <div className="px-6 py-3 border-b border-gray-200 flex items-center gap-3 shrink-0">
                  <div className="relative flex-1">
                    <svg className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                    <input className="w-full h-8 pl-9 pr-3 bg-gray-50 border border-gray-200 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder={`Search ${githubRepos.length} repositories (${newRepoCount} new)...`} value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
                  </div>
                  <button className="text-xs font-medium text-blue-600 hover:text-blue-800 whitespace-nowrap px-2 py-1" onClick={toggleAllRepos}>
                    {filteredGithubRepos.filter(r => !isImported(r)).every(r => selectedRepos[r.full_name]) && newRepoCount > 0 ? 'Deselect All' : 'Select All'}
                  </button>
                </div>
                <div className="overflow-y-auto flex-1" style={{ maxHeight: '400px' }}>
                  {filteredGithubRepos.length === 0 ? (
                    <div className="p-8 text-center text-gray-400 text-sm">No repositories match your search.</div>
                  ) : (
                    filteredGithubRepos.map(repo => {
                      const imported = isImported(repo);
                      return (
                        <label key={repo.full_name} className={`flex items-start gap-3 px-6 py-3 border-b border-gray-100 transition-colors ${imported ? 'opacity-50 cursor-default' : 'cursor-pointer hover:bg-gray-50'} ${selectedRepos[repo.full_name] ? 'bg-blue-50/50' : ''}`}>
                          <input type="checkbox" className="mt-1 h-4 w-4 rounded border-gray-300 text-blue-600 disabled:opacity-40" checked={imported || !!selectedRepos[repo.full_name]} onChange={() => toggleRepo(repo.full_name)} disabled={imported} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className={`font-medium text-sm truncate ${imported ? 'text-gray-400' : 'text-gray-900'}`}>{repo.full_name}</span>
                              {imported && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-100 text-blue-700">Imported</span>}
                              <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium ${repo.is_private ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>{repo.is_private ? 'Private' : 'Public'}</span>
                              {repo.language && <span className="text-[10px] text-gray-400">{repo.language}</span>}
                            </div>
                            {repo.description && <p className="text-xs text-gray-500 mt-0.5 truncate">{repo.description}</p>}
                          </div>
                        </label>
                      );
                    })
                  )}
                </div>
                <div className="px-6 py-3 border-t border-gray-200 flex items-center justify-between bg-gray-50 shrink-0">
                  <button className="text-sm text-gray-500 hover:text-gray-700 flex items-center gap-1" onClick={() => { setImportStep(1); setGithubRepos([]); setSelectedRepos({}); setSearchQuery(''); }}>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>Back
                  </button>
                  <button className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2" onClick={handleBulkImport} disabled={importSelectedCount === 0 || importing}>
                    {importing && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent"></span>}
                    {importing ? 'Importing...' : `Import Selected (${importSelectedCount})`}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========== MANUAL ADD MODAL ========== */}
      {showManualModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/50 p-4" onClick={() => setShowManualModal(false)}>
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
              <h3 className="text-lg font-medium text-gray-900">Add Repository Manually</h3>
              <button onClick={() => setShowManualModal(false)} className="text-gray-400 hover:text-gray-500"><svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg></button>
            </div>
            <form onSubmit={handleCreate} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor="repo-name" className="text-sm font-medium text-gray-700">Name</label>
                  <input id="repo-name" className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="my-project" value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} required />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="repo-provider" className="text-sm font-medium text-gray-700">Provider</label>
                  <select id="repo-provider" className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" value={formData.provider} onChange={e => setFormData({ ...formData, provider: e.target.value, git_host_id: '' })}>
                    {PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </select>
                </div>
              </div>
              {needsConnection(formData.provider) && (
                <div className="space-y-1.5">
                  <label htmlFor="repo-connection" className="text-sm font-medium text-gray-700">Connection</label>
                  {hostsLoading || hostsError ? (
                    <ConnectionsStatus loading={hostsLoading} error={hostsError} onRetry={loadHosts} />
                  ) : hosts.length === 0 ? (
                    <p className="text-xs text-amber-700">No Azure DevOps connection yet. <Link to="/settings" className="text-blue-600 hover:underline" onClick={() => setShowManualModal(false)}>Add one in Settings</Link>.</p>
                  ) : (
                    <select id="repo-connection" className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" value={formData.git_host_id} onChange={e => { setFormData({ ...formData, git_host_id: e.target.value }); setFormError(''); }} aria-required="true">
                      <option value="">Select...</option>
                      {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
                    </select>
                  )}
                </div>
              )}
              <div className="space-y-1.5">
                <label htmlFor="repo-url" className="text-sm font-medium text-gray-700">Repository URL</label>
                <input id="repo-url" className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder={urlPlaceholder} value={formData.url} onChange={e => setFormData({ ...formData, url: e.target.value })} required />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-gray-700">Default Branch</label>
                  <input className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="main" value={formData.default_branch} onChange={e => setFormData({ ...formData, default_branch: e.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-gray-700">Scan Schedule</label>
                  <input className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono" placeholder="0 */6 * * *" value={formData.schedule} onChange={e => setFormData({ ...formData, schedule: e.target.value })} />
                </div>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="repo-auth-token" className="text-sm font-medium text-gray-700">Auth Token <span className="text-gray-400 font-normal">(Optional)</span></label>
                <input id="repo-auth-token" className="w-full h-10 px-3 bg-white border border-gray-300 rounded-md text-sm focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none" type="password" placeholder={TOKEN_PLACEHOLDERS[formData.provider]} value={formData.auth_token} onChange={e => setFormData({ ...formData, auth_token: e.target.value })} />
              </div>
              {formError && <p role="alert" className="text-sm text-red-700">{formError}</p>}
              <div className="pt-4 flex justify-end gap-3">
                <button type="button" className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50" onClick={() => setShowManualModal(false)}>Cancel</button>
                <button type="submit" className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700">Save Repository</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
