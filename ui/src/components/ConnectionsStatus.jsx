// ConnectionsStatus is the inline loading / error state for the connections
// request, so a failed or pending load is never read as "no connections".
// It renders nothing once the request has succeeded.
export default function ConnectionsStatus({ loading, error, onRetry }) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 text-xs text-gray-500" role="status">
        <span className="h-3 w-3 animate-spin rounded-full border-2 border-blue-600 border-t-transparent"></span>
        Loading connections…
      </div>
    );
  }
  if (error) {
    return (
      <div className="flex items-center gap-3 bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-sm text-red-700" role="alert">
        <span className="flex-1">{error.message || 'Could not load connections.'}</span>
        <button type="button" className="px-2.5 py-1 bg-white border border-red-200 hover:bg-red-100 text-red-700 text-xs font-medium rounded-md" onClick={onRetry}>
          Retry
        </button>
      </div>
    );
  }
  return null;
}
