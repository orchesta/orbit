import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { repositoryApi, scanApi } from '../services/api';
import { useScanTracker } from '../hooks/useScanTracker';
import Spinner from '../components/Spinner';
import ErrorState from '../components/ErrorState';

const isActive = (scan) => scan?.status === 'pending' || scan?.status === 'running';

// approximateVersionHint explains why a version is not exact. Go has no
// lockfile to add: go.mod lists minimum versions.
const approximateVersionHint = (ecosystem) =>
  ecosystem === 'Go'
    ? 'Version from go.mod (minimum version selection)'
    : 'Version taken from a manifest range; add a lockfile for exact results';

export default function RepoDetail() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState('dependencies');
  const [depFilter, setDepFilter] = useState('all');
  const queryClient = useQueryClient();

  const repoQuery = useQuery({ queryKey: ['repository', id], queryFn: () => repositoryApi.getById(id) });
  const scansQuery = useQuery({
    queryKey: ['repository', id, 'scans'],
    queryFn: () => scanApi.getHistory(id),
    // Follow a scan that is still running on the server (e.g. started before
    // this page was opened) until the newest scan is no longer active.
    refetchInterval: (query) => (isActive(query.state.data?.[0]) ? 2000 : false),
  });
  const scans = scansQuery.data || [];
  // Running or failed scans have incomplete data; show the last good one.
  const latestScan = scans.find((s) => s.status === 'completed') || null;
  const depsQuery = useQuery({
    queryKey: ['scan', latestScan?.id, 'dependencies'],
    queryFn: () => scanApi.getDependencies(latestScan.id),
    enabled: !!latestScan,
  });
  const vulnsQuery = useQuery({
    queryKey: ['scan', latestScan?.id, 'vulnerabilities'],
    queryFn: () => scanApi.getVulnerabilities(latestScan.id),
    enabled: !!latestScan,
  });
  const tracker = useScanTracker({
    onFinished: (repoId) => {
      queryClient.invalidateQueries({ queryKey: ['repository', repoId] });
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
    },
  });
  const deps = depsQuery.data || [];
  const visibleDeps = deps.filter((d) => depFilter === 'all' || (depFilter === 'direct' ? d.is_direct : !d.is_direct));
  const vulns = vulnsQuery.data || [];
  const repo = repoQuery.data;

  if (repoQuery.error?.status === 404 && !repo) {
    return (
      <div className="bg-white border border-gray-200 rounded-xl p-12 text-center shadow-sm">
        <p className="text-gray-500 text-lg mb-4">Repository not found.</p>
        <Link to="/repositories" className="text-blue-600 hover:text-blue-800 font-medium font-medium">&larr; Back to Repositories</Link>
      </div>
    );
  }

  // A failed background refetch keeps the data on screen; only a failed
  // first load replaces the page.
  const loadError = (!repo && repoQuery.error) || (!scansQuery.data && scansQuery.error);
  if (loadError) {
    return <ErrorState error={loadError} onRetry={() => { repoQuery.refetch(); scansQuery.refetch(); }} />;
  }

  if (!repo || !scansQuery.data) return <Spinner />;

  const scanning = tracker.isScanning(id) || isActive(scans[0]);
  const depsLoading = !!latestScan && depsQuery.isPending;
  const vulnsLoading = !!latestScan && vulnsQuery.isPending;
  const depsFailed = !!latestScan && depsQuery.isError && !depsQuery.data;
  const vulnsFailed = !!latestScan && vulnsQuery.isError && !vulnsQuery.data;
  const countLabel = (loading, failed, list) => (failed ? '—' : loading ? '…' : list.length);

  const newestScan = scans[0] || null;
  const newerThanShown = latestScan && newestScan && newestScan.id !== latestScan.id;
  const noScanMsg = (fallback) => (latestScan ? fallback : 'No completed scan yet');

  return (
    <div>
      <div className="mb-6">
        <Link to="/repositories" className="text-sm text-gray-500 hover:text-blue-600 mb-4 inline-block">&larr; Back to Repositories</Link>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
              {repo.name}
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${repo.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                {repo.is_active ? 'Active' : 'Inactive'}
              </span>
            </h2>
            <div className="flex items-center gap-3 mt-2 text-sm text-gray-500">
              <span className="capitalize">{repo.provider}</span>
              <span>&bull;</span>
              <span>{repo.url}</span>
            </div>
          </div>
          <button 
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2 min-w-[120px] shadow-sm disabled:opacity-50"
            onClick={() => tracker.start(id)
              // Show the queued scan in the history right away.
              .then(() => queryClient.invalidateQueries({ queryKey: ['repository', id, 'scans'] }))
              .catch((e) => alert('Scan error: ' + e.message))}
            disabled={scanning}
          >
           {scanning ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"></span>
                <span className="sr-only">Scanning…</span>
              </>
            ) : "Scan Now"}
          </button>
        </div>
      </div>

      {newestScan?.status === 'failed' && (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
          <span className="font-medium">Latest scan failed:</span> {newestScan.error || 'unknown error'}
        </div>
      )}
      {newerThanShown && (
        <p className="mb-2 text-xs text-gray-500">Last completed scan: {new Date(latestScan.started_at).toLocaleString()}</p>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard 
          label="Total Dependencies" 
          value={latestScan ? latestScan.total_deps : '—'} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />}
          color="text-blue-600"
        />
        <StatCard 
          label="Outdated" 
          value={latestScan ? latestScan.outdated_deps : '—'} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />}
          color="text-orange-600"
        />
        <StatCard 
          label="Vulnerable Packs" 
          value={latestScan ? latestScan.vulnerable_deps : '—'} 
          subtext={latestScan && latestScan.total_vulns > 0 ? `${latestScan.total_vulns} Total Issues` : ''}
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />}
          color="text-red-600"
        />
        <StatCard 
          label="Scan Duration" 
          value={latestScan ? `${(latestScan.duration / 1e9).toFixed(1)}s` : '—'} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />}
          color="text-gray-600"
        />
      </div>

      <div className="mb-6 border-b border-gray-200">
        <nav className="flex space-x-8">
          <TabButton active={activeTab === 'dependencies'} onClick={() => setActiveTab('dependencies')} label={`Dependencies (${countLabel(depsLoading, depsFailed, deps)})`} />
          <TabButton active={activeTab === 'vulnerabilities'} onClick={() => setActiveTab('vulnerabilities')} label={`Vulnerabilities (${countLabel(vulnsLoading, vulnsFailed, vulns)})`} />
          <TabButton active={activeTab === 'history'} onClick={() => setActiveTab('history')} label={`Scan History (${scans.length})`} />
        </nav>
      </div>

      <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden mb-12">
        {activeTab === 'dependencies' && (
          <div className="overflow-x-auto">
            {depsFailed ? (
              <ErrorState error={depsQuery.error} onRetry={() => depsQuery.refetch()} />
            ) : depsLoading ? (
              <Spinner />
            ) : deps.length === 0 ? (
              <EmptyState icon="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" message={noScanMsg('No dependencies found')} />
            ) : (
              <>
                <div className="flex items-center justify-end gap-2 px-6 py-3 border-b border-gray-200 text-sm text-gray-500">
                  <label htmlFor="dep-filter">Dependency type</label>
                  <select
                    id="dep-filter"
                    value={depFilter}
                    onChange={(e) => setDepFilter(e.target.value)}
                    className="rounded-lg border border-gray-200 bg-white px-2 py-1 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All</option>
                    <option value="direct">Direct</option>
                    <option value="transitive">Transitive</option>
                  </select>
                </div>
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-50 text-gray-500 border-b border-gray-200">
                    <tr>
                      <th className="px-6 py-3 font-medium">Package</th>
                      <th className="px-6 py-3 font-medium">Ecosystem</th>
                      <th className="px-6 py-3 font-medium">Current</th>
                      <th className="px-6 py-3 font-medium">Latest</th>
                      <th className="px-6 py-3 font-medium text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {visibleDeps.map(dep => (
                      <tr key={dep.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 font-medium text-gray-900">
                          {dep.name}
                          {dep.is_dev && (
                            <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">dev</span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-gray-500 capitalize">{dep.ecosystem}</td>
                        <td className="px-6 py-4 text-gray-500 font-mono text-xs">{dep.current_version || '-'}
                          {dep.is_resolved === false && (
                            <span
                              title={approximateVersionHint(dep.ecosystem)}
                              className="ml-1.5 inline-flex items-center px-1 rounded text-xs font-medium bg-gray-100 text-gray-500 cursor-help"
                            >
                              <span aria-hidden="true">≈</span>
                              <span className="sr-only">approximate version</span>
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-gray-500 font-mono text-xs">{dep.latest_version || '-'}</td>
                        <td className="px-6 py-4 text-center">
                          {dep.is_outdated ? (
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize 
                              ${dep.update_type === 'major' ? 'bg-red-100 text-red-800' : 
                                dep.update_type === 'minor' ? 'bg-yellow-100 text-yellow-800' : 
                                'bg-blue-100 text-blue-800'}`}>
                              {dep.update_type} Update
                            </span>
                          ) : (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                              Up to date
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {visibleDeps.length === 0 && (
                  <p className="p-8 text-center text-sm text-gray-400">No {depFilter} dependencies</p>
                )}
              </>
            )}
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="overflow-x-auto">
            {vulnsFailed ? (
              <ErrorState error={vulnsQuery.error} onRetry={() => vulnsQuery.refetch()} />
            ) : vulnsLoading ? (
              <Spinner />
            ) : vulns.length === 0 ? (
              <EmptyState icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040L3 5.618a11.986 11.986 0 001.274 13.92 11.987 11.987 0 0015.452 0c.935-1.12 1.587-2.43 1.944-3.834l-1.07-.356z" message={noScanMsg('No vulnerabilities detected')} />
            ) : (
              <table className="w-full text-left text-sm">
                <thead className="bg-gray-50 text-gray-500 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 font-medium">Vulnerability</th>
                    <th className="px-6 py-3 font-medium">Package</th>
                    <th className="px-6 py-3 font-medium text-center">Severity</th>
                    <th className="px-6 py-3 font-medium text-right">Fixed In</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {vulns.map(vuln => {
                    const dep = deps.find(d => d.id === vuln.dependency_id);
                    return (
                      <tr key={vuln.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4">
                          <div className="font-medium text-gray-900 mb-1">{vuln.summary || 'Summary unavailable'}</div>
                          <div className="flex items-center gap-2">
                             <a href={`https://osv.dev/vulnerability/${vuln.osv_id}`} target="_blank" rel="noopener" className="text-blue-600 hover:underline text-xs">
                               {vuln.osv_id}
                             </a>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="font-medium text-gray-900">{dep ? dep.name : 'Unknown'}</div>
                          <div className="text-xs text-gray-500 font-mono">{dep ? dep.current_version : ''}</div>
                        </td>
                        <td className="px-6 py-4 text-center">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
                            ${vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                              vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                              vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                              vuln.severity === 'low' ? 'bg-green-100 text-green-800' :
                              'bg-gray-100 text-gray-800'}`}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-gray-500 font-mono text-xs text-right">{vuln.fixed_version || '-'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
           </div>
        )}

        {activeTab === 'history' && (
          <div className="overflow-x-auto">
            {scans.length === 0 ? (
              <EmptyState icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" message="No scan history available" />
            ) : (
              <table className="w-full text-left text-sm">
                <thead className="bg-gray-50 text-gray-500 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 font-medium">Status</th>
                    <th className="px-6 py-3 font-medium text-center">Deps</th>
                    <th className="px-6 py-3 font-medium text-center">Outdated</th>
                    <th className="px-6 py-3 font-medium text-center">Vulnerable</th>
                    <th className="px-6 py-3 font-medium text-right">Started</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {scans.map(scan => (
                    <tr key={scan.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
                          ${scan.status === 'completed' ? 'bg-green-100 text-green-800' : 
                            scan.status === 'failed' ? 'bg-red-100 text-red-800' : 
                            'bg-blue-100 text-blue-800'}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-center text-gray-900">{scan.total_deps}</td>
                      <td className="px-6 py-4 text-center text-orange-600">{scan.outdated_deps}</td>
                      <td className="px-6 py-4 text-center text-red-600">{scan.vulnerable_deps}</td>
                      <td className="px-6 py-4 text-right text-gray-500 text-xs">{new Date(scan.started_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, icon, color, subtext }) {
  return (
    <div data-testid={`stat-${label.toLowerCase().replace(/\s+/g, '-')}`} className="bg-white p-5 rounded-xl border border-gray-200 shadow-sm flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-gray-500 mb-1">{label}</p>
        <div className="flex items-baseline gap-2">
           <h3 className="text-2xl font-bold text-gray-900 leading-none">{value}</h3>
           {subtext && <span className="text-xs font-medium text-red-600 bg-red-50 px-2 py-0.5 rounded-full">{subtext}</span>}
        </div>
      </div>
      <div className={`p-3 rounded-lg bg-gray-50 ${color}`}>
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          {icon}
        </svg>
      </div>
    </div>
  );
}

function TabButton({ active, onClick, label }) {
  return (
    <button 
      className={`py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap transition-colors
        ${active ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function EmptyState({ icon, message }) {
  return (
    <div className="p-12 text-center text-gray-400">
      <svg className="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icon} />
      </svg>
      <p className="font-medium text-gray-900">{message}</p>
    </div>
  )
}
