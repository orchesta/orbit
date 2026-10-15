import { useEffect, useEffectEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { vulnerabilityApi } from '../services/api';
import Spinner from '../components/Spinner';
import ErrorState from '../components/ErrorState';
import Pagination from '../components/Pagination';
import MaliciousBadge from '../components/MaliciousBadge';
import ExploitSignals from '../components/ExploitSignals';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

const EPSS_FLOORS = [
  { value: '', label: 'Any EPSS' },
  { value: '0.01', label: 'EPSS ≥ 1%' },
  { value: '0.1', label: 'EPSS ≥ 10%' },
  { value: '0.5', label: 'EPSS ≥ 50%' },
];

export default function Vulnerabilities() {
  // URL-based filter & pagination
  const [searchParams, setSearchParams] = useSearchParams();
  const filter = searchParams.get('severity') || 'all';
  const currentPage = parseInt(searchParams.get('page') || '1', 10);
  const kevOnly = searchParams.get('kev') === 'true';
  const minEpss = searchParams.get('min_epss') || '';
  const sort = searchParams.get('sort') === 'epss' ? 'epss' : 'severity';

  // setParam changes one filter and goes back to the first page.
  function setParam(key, value) {
    const p = new URLSearchParams(searchParams);
    if (value === '' || value == null) p.delete(key); else p.set(key, value);
    p.delete('page');
    setSearchParams(p, { replace: true });
  }
  function setFilter(v) {
    setParam('severity', v === 'all' ? '' : v);
  }
  function setCurrentPage(pg) {
    const p = new URLSearchParams(searchParams);
    const val = typeof pg === 'function' ? pg(currentPage) : pg;
    if (val <= 1) p.delete('page'); else p.set('page', String(val));
    setSearchParams(p, { replace: true });
  }

  const query = useQuery({
    queryKey: ['vulnerabilities', { page: currentPage, severity: filter, kev: kevOnly, minEpss, sort }],
    queryFn: () => vulnerabilityApi.list({
      page: currentPage, per_page: 25, severity: filter === 'all' ? undefined : filter,
      kev: kevOnly, min_epss: minEpss || undefined, sort,
    }),
    placeholderData: keepPreviousData,
  });

  // A stale link or shrinking results can leave the URL past the end; step
  // back once real data says so.
  const lastPage = Math.max(1, query.data?.total_pages || 1);
  const pastLastPage = query.isSuccess && !query.isPlaceholderData && currentPage > lastPage;
  const goToLastPage = useEffectEvent(() => setCurrentPage(lastPage));
  useEffect(() => {
    if (pastLastPage) goToLastPage();
  }, [pastLastPage]);

  if (query.isPending) return <Spinner />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;

  const { data: findings, total, total_pages: totalPages, counts, unverified_repositories: unverified } = query.data;
  const allCount = counts.critical + counts.high + counts.medium + counts.low + counts.unknown;
  // "Great job" only when nothing at all was found and every repository was checked.
  const allClear = allCount === 0 && unverified === 0;
  const exploitFilter = kevOnly || minEpss !== '';
  const emptyMessage = exploitFilter && allCount > 0
    ? 'No findings match the exploit filters.'
    : filter !== 'all' && allCount > 0
      ? `No ${capitalize(filter)} vulnerabilities in the latest scans.`
      : unverified > 0
        ? 'No vulnerabilities in checked repositories'
        : 'No vulnerabilities on this page';

  return (
    <div>
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 leading-tight">Vulnerabilities</h2>
        <p className="text-sm text-gray-500 mt-1">Security issues in the latest completed scan of each repository</p>
      </div>

      {unverified > 0 && (
        <div className="mb-6 rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-800" role="alert">
          {unverified} {unverified === 1 ? 'repository has' : 'repositories have'} no successful vulnerability check
        </div>
      )}

      {counts.malicious > 0 && (
        <div className="mb-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
          {counts.malicious === 1
            ? '1 finding is a known malicious package. Remove it and treat machines that installed it as compromised.'
            : `${counts.malicious} findings are known malicious packages. Remove them and treat machines that installed them as compromised.`}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
        {SEVERITIES.map(s => (
          <StatCard
            key={s}
            title={capitalize(s)}
            value={counts[s]}
            textColor={CARD_COLORS[s]}
            active={filter === s}
            onClick={() => setFilter(s)}
          />
        ))}
      </div>

      <div className="flex space-x-2 mb-6 overflow-x-auto pb-2">
        <FilterButton active={filter === 'all'} onClick={() => setFilter('all')} label={`All (${allCount})`} />
        {SEVERITIES.map(s => (
          <FilterButton
            key={s}
            active={filter === s}
            onClick={() => setFilter(s)}
            label={capitalize(s)}
          />
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <FilterButton
          active={kevOnly}
          onClick={() => setParam('kev', kevOnly ? '' : 'true')}
          label={`Known exploited (${counts.kev ?? 0})`}
        />
        <select
          aria-label="Minimum EPSS"
          value={minEpss}
          onChange={e => setParam('min_epss', e.target.value)}
          className="px-3 py-1.5 rounded-lg border border-gray-300 bg-white text-sm text-gray-700"
        >
          {EPSS_FLOORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select
          aria-label="Sort by"
          value={sort}
          onChange={e => setParam('sort', e.target.value === 'severity' ? '' : e.target.value)}
          className="px-3 py-1.5 rounded-lg border border-gray-300 bg-white text-sm text-gray-700"
        >
          <option value="severity">Sort: severity</option>
          <option value="epss">Sort: EPSS</option>
        </select>
      </div>

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        {findings.length === 0 ? (
          <div className="p-12 text-center text-gray-400">
            <svg className="w-12 h-12 mx-auto mb-3 text-green-500 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040L3 5.618a11.986 11.986 0 001.274 13.92 11.987 11.987 0 0015.452 0c.935-1.12 1.587-2.43 1.944-3.834l-1.07-.356z" />
            </svg>
            {allClear ? (
              <>
                <p className="font-medium text-gray-900 mb-1">No vulnerabilities found</p>
                <p className="text-sm">Great job keeping your dependencies up to date!</p>
              </>
            ) : (
              <p className="font-medium text-gray-900 mb-1">{emptyMessage}</p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 border-b border-gray-200 text-gray-500">
                <tr>
                  <th className="px-6 py-3 font-medium">Vulnerability</th>
                  <th className="px-6 py-3 font-medium">Package</th>
                  <th className="px-6 py-3 font-medium">Repository</th>
                  <th className="px-6 py-3 font-medium text-center">Severity</th>
                  <th className="px-6 py-3 font-medium">Exploit</th>
                  <th className="px-6 py-3 font-medium text-right">Fixed In</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {findings.map(vuln => (
                  <tr key={vuln.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="font-medium text-gray-900 mb-1">{vuln.summary || 'Summary unavailable'}</div>
                      <div className="flex items-center gap-2">
                         <a href={`https://osv.dev/vulnerability/${vuln.osv_id}`} target="_blank" rel="noopener" className="text-blue-600 hover:underline text-xs">
                           {vuln.osv_id}
                         </a>
                         {vuln.aliases?.length > 0 && (
                           <span className="text-gray-400 text-xs">({vuln.aliases[0]})</span>
                         )}
                         {vuln.malicious && <MaliciousBadge />}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-medium text-gray-900">{vuln.package_name}</div>
                      <div className="text-xs text-gray-500 font-mono">{vuln.current_version}</div>
                    </td>
                    <td className="px-6 py-4">
                      <Link to={`/repositories/${vuln.repository_id}`} className="text-gray-700 hover:text-blue-600 transition-colors">
                        {vuln.repository_name}
                      </Link>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
                        ${vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                          vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                          vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                          vuln.severity === 'low' ? 'bg-blue-100 text-blue-800' :
                          'bg-gray-100 text-gray-700'}`}>
                        {vuln.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <ExploitSignals vuln={vuln} />
                    </td>
                    <td className="px-6 py-4 text-gray-600 font-mono text-xs text-right">
                      {vuln.fixed_version || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={currentPage} totalPages={totalPages} total={total} label="vulnerabilities" onChange={setCurrentPage} />
      </div>
    </div>
  );
}

const CARD_COLORS = {
  critical: 'text-red-600',
  high: 'text-orange-600',
  medium: 'text-yellow-600',
  low: 'text-blue-600',
  unknown: 'text-gray-600',
};

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function StatCard({ title, value, textColor, onClick, active }) {
  return (
    <button
      type="button"
      aria-label={`${title}: ${value}`}
      onClick={onClick}
      className={`p-4 rounded-xl border cursor-pointer text-left transition-all ${active ? 'border-blue-500 shadow-sm ring-1 ring-blue-500' : 'border-gray-200 hover:border-gray-300 bg-white'}`}
    >
      <div className="text-sm font-medium text-gray-500 mb-1">{title}</div>
      <div className={`text-2xl font-bold ${textColor} ${active ? '' : 'opacity-90'}`}>{value}</div>
    </button>
  );
}

function FilterButton({ active, onClick, label }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap
        ${active ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
    >
      {label}
    </button>
  );
}
