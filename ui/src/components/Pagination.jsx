// Pagination renders the Prev/Next bar with a window of up to 7 page buttons.
export default function Pagination({ page, totalPages, total, label, onChange }) {
  if (totalPages <= 1) return null;
  return (
    <div className="px-4 py-3 border-t border-gray-200 flex items-center justify-between bg-gray-50/50">
      <span className="text-xs text-gray-500">Page {page} of {totalPages} ({total} {label})</span>
      <div className="flex gap-1">
        <button
          className="px-2.5 py-1 text-xs font-medium border border-gray-300 rounded-md bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={() => onChange(Math.max(1, page - 1))}
          disabled={page <= 1}
        >← Prev</button>
        {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
          let p;
          if (totalPages <= 7) { p = i + 1; }
          else if (page <= 4) { p = i + 1; }
          else if (page >= totalPages - 3) { p = totalPages - 6 + i; }
          else { p = page - 3 + i; }
          return (
            <button
              key={p}
              aria-label={`Page ${p}`}
              className={`px-2.5 py-1 text-xs font-medium border rounded-md transition-colors ${page === p ? 'bg-gray-900 text-white border-gray-900' : 'bg-white border-gray-300 hover:bg-gray-50 text-gray-700'}`}
              onClick={() => onChange(p)}
            >{p}</button>
          );
        })}
        <button
          className="px-2.5 py-1 text-xs font-medium border border-gray-300 rounded-md bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed"
          onClick={() => onChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
        >Next →</button>
      </div>
    </div>
  );
}
