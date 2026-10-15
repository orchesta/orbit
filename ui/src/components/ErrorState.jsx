// ErrorState replaces a page's content when its data could not be loaded, so
// a failure is never mistaken for "nothing here".
export default function ErrorState({ error, onRetry, title = 'Could not load data' }) {
  return (
    <div className="bg-white border border-red-200 rounded-xl p-8 text-center shadow-sm" role="alert">
      <p className="font-medium text-red-700 mb-1">{title}</p>
      <p className="text-sm text-gray-500 mb-4">{error?.message || 'Unknown error'}</p>
      {onRetry && (
        <button className="px-4 py-2 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-lg" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
