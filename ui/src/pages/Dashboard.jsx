import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { repositoryApi, dashboardApi } from '../services/api';
import Spinner from '../components/Spinner';
import ErrorState from '../components/ErrorState';

export default function Dashboard() {
  const statsQuery = useQuery({ queryKey: ['dashboard', 'stats'], queryFn: dashboardApi.stats });
  const reposQuery = useQuery({
    queryKey: ['repositories', { per_page: 5, sort: 'recent' }],
    queryFn: () => repositoryApi.getAll({ per_page: 5, sort: 'recent' }),
  });

  if (statsQuery.isPending || reposQuery.isPending) return <Spinner />;
  const failed = statsQuery.error || reposQuery.error;
  if (failed) {
    return <ErrorState error={failed} onRetry={() => { statsQuery.refetch(); reposQuery.refetch(); }} />;
  }
  const stats = statsQuery.data;
  const repos = reposQuery.data?.data || [];

  return (
    <div>
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-gray-900 leading-tight">Dashboard</h2>
        <p className="text-sm text-gray-500 mt-1">Overview of your dependency health across {stats.total_repos} repositories</p>
      </div>

      {stats.unverified_repos > 0 && (
        <div className="mb-6 rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-800" role="alert">
          {stats.unverified_repos} {stats.unverified_repos === 1 ? 'repository has' : 'repositories have'} no successful vulnerability check yet — the totals below may be incomplete.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard 
          title="Managed Repos" 
          value={stats.total_repos} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />}
          color="text-blue-600"
        />
        <StatCard 
          title="Active Repos" 
          value={stats.active_repos} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040L3 5.618a11.986 11.986 0 001.274 13.92 11.987 11.987 0 0015.452 0c.935-1.12 1.587-2.43 1.944-3.834l-1.07-.356z" />}
          color="text-green-600"
        />
        <StatCard 
          title="Vulnerable Packs" 
          value={stats.vulnerable_deps} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.268 16c-.77 1.333.192 3 1.732 3z" />}
          color="text-red-600"
        />
        <StatCard 
          title="Total Vulnerabilities" 
          value={stats.total_vulns} 
          icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.268 16c-.77 1.333.192 3 1.732 3z" />}
          color="text-red-600"
        />
      </div>

      <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
        <div className="px-6 py-4 flex justify-between items-center border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Repositories</h3>
          <Link to="/repositories" className="text-sm font-medium text-blue-600 hover:text-blue-700">
            View all &rarr;
          </Link>
        </div>

        {repos.length === 0 ? (
          <div className="p-12 text-center text-gray-400">
            <svg className="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p className="font-medium text-gray-900 mb-1">No repositories added yet</p>
            <Link to="/repositories" className="text-sm text-blue-600 hover:text-blue-800">
              Add your first repository
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 text-gray-500 border-b border-gray-200">
                <tr>
                  <th className="px-6 py-3 font-medium">Name</th>
                  <th className="px-6 py-3 font-medium">Provider</th>
                  <th className="px-6 py-3 font-medium">Status</th>
                  <th className="px-6 py-3 font-medium">Last Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {repos.map(repo => (
                  <tr key={repo.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <Link to={`/repositories/${repo.id}`} className="font-medium text-blue-600 hover:text-blue-800 truncate block max-w-xs">
                        {repo.name}
                      </Link>
                      <div className="text-xs text-gray-500 truncate max-w-xs">{repo.url}</div>
                    </td>
                    <td className="px-6 py-4 text-gray-700 capitalize">
                      {repo.provider}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${repo.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                        {repo.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-gray-500 text-xs">
                      {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleString() : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, color, subtext }) {
  return (
    <div className="bg-white p-5 rounded-xl border border-gray-200 shadow-sm flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-gray-500 mb-1">{title}</p>
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
